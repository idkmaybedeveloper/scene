use std::collections::{BTreeMap, BTreeSet};

use aes::{
    Aes128, Block as AesBlock,
    cipher::{BlockEncrypt, KeyInit},
};
use anyhow::{Result, ensure};
use iced_x86::{Code, Instruction, MemoryOperand, Register};

use super::{
    Options, Output,
    cfg::{Destination, Exit, Function},
    emit::{Emitter, Label},
    flags_dead, mba,
    unwind::{self, CFA_SLOT, Cfa, FRAME_SIZE, Frames, Row, Rule},
};

struct State {
    input: [u8; 16],
    tag: [u8; 16],
    gate: Label,
}

pub fn transform(function: &Function<'_>, base: u64, options: Options) -> Result<Output> {
    let frames = unwind::analyze(function.insns, &function.tables)?;
    let mut out = Emitter::new();
    let dispatcher = out.label();
    let labels: Vec<_> = function.blocks.iter().map(|_| out.label()).collect();
    let key =
        std::array::from_fn(|i| (options.seed.rotate_left((i * 7) as u32) >> (i % 4 * 8)) as u8);
    let cipher = Aes128::new(&key.into());
    let states: Vec<_> = labels
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let mut input = AesBlock::from((index as u128).to_le_bytes());
            cipher.encrypt_block(&mut input);
            State { input: input.into(), tag: tag(input.into(), key), gate: out.label() }
        })
        .collect();
    ensure!(
        states.iter().map(|s| s.tag).collect::<BTreeSet<_>>().len() == states.len(),
        "dispatcher state collision"
    );
    let mut resumes = BTreeMap::new();
    let mut substitutions = 0;
    transition(
        &mut out,
        &states[0],
        key,
        dispatcher,
        &frames.rows[&function.insns[0].ip()],
        &frames,
    )?;
    let mut order: Vec<_> = (0..function.blocks.len()).collect();
    order.sort_unstable_by_key(|&i| states[i].tag);
    for index in order {
        let block = &function.blocks[index];
        out.unwind(frames.rows[&function.insns[block.body.start].ip()].clone());
        out.bind(labels[index]);
        for i in block.body.clone() {
            let insn = &function.insns[i];
            out.unwind(frames.rows[&insn.ip()].clone());
            out.record(insn.ip());
            let replacement = if options.mba {
                mba::substitute(insn, flags_dead(&function.insns[i..]))?
            } else {
                None
            };
            if let Some(replacement) = replacement {
                for insn in replacement {
                    out.push(insn);
                }
                substitutions += 1;
            } else {
                out.push(*insn);
            }
        }
        if let Some(address) = block.exit_address {
            out.unwind(frames.rows[&address].clone());
            out.record(address);
        }
        let row = match &block.exit {
            Exit::Call { site, .. } => &frames.rows[site],
            _ => {
                if let Some(address) = block.exit_address {
                    &frames.rows[&address]
                } else {
                    &frames.after[&function.insns[block.body.end - 1].ip()]
                }
            }
        };
        match &block.exit {
            Exit::Stop(insn) => out.push(*insn),
            Exit::Tail(address) => out.jump_to(*address)?,
            Exit::Jump(next) => {
                transition(&mut out, &states[*next], key, dispatcher, row, &frames)?
            }
            Exit::Call { site, next, resume } => {
                out.jump_to(*site)?;
                if let Some(next) = next {
                    let label = out.label();
                    out.unwind(row.clone());
                    out.bind(label);
                    resumes.insert(*resume, label);
                    transition(&mut out, &states[*next], key, dispatcher, row, &frames)?;
                }
            }
            Exit::Indirect { insn, targets } => {
                out.push(Instruction::with2(Code::Lea_r64_m, Register::RSP, stack(-128))?);
                out.unwind(row.shifted(128));
                out.push(Instruction::with(Code::Pushfq));
                out.unwind(row.shifted(136));
                out.push(Instruction::with1(Code::Push_r64, Register::R11)?);
                out.unwind(row.shifted(144));
                let edges: Vec<_> = targets.iter().map(|_| out.label()).collect();
                for (&(address, _), &edge) in targets.iter().zip(&edges) {
                    out.push(Instruction::with2(
                        Code::Lea_r64_m,
                        Register::R11,
                        MemoryOperand::with_base_displ(Register::RIP, address as i64),
                    )?);
                    let compare = if insn.op0_register() == Register::R11 {
                        Instruction::with2(Code::Cmp_rm64_r64, stack(0), Register::R11)?
                    } else {
                        Instruction::with2(Code::Cmp_rm64_r64, insn.op0_register(), Register::R11)?
                    };
                    out.push(compare);
                    out.branch(Instruction::with_branch(Code::Je_rel32_64, 0)?, edge);
                }
                restore_indirect(&mut out, row)?;
                out.push(*insn);
                for (&(_, next), &edge) in targets.iter().zip(&edges) {
                    out.unwind(row.shifted(144));
                    out.bind(edge);
                    restore_indirect(&mut out, row)?;
                    transition(&mut out, &states[next], key, dispatcher, row, &frames)?;
                }
            }
            Exit::Conditional { insn, taken, fallthrough } => {
                let edge = out.label();
                out.branch(*insn, edge);
                transition(&mut out, &states[*fallthrough], key, dispatcher, row, &frames)?;
                out.unwind(row.clone());
                out.bind(edge);
                match taken {
                    Destination::Block(next) => {
                        transition(&mut out, &states[*next], key, dispatcher, row, &frames)?
                    }
                    Destination::Address(address) => out.jump_to(*address)?,
                }
            }
        }
    }
    out.unwind(Row::dispatcher(&frames.saved));
    out.bind(dispatcher);
    for state in states.iter().rev() {
        out.vector(Register::XMM15, state.tag)?;
        out.push(Instruction::with2(Code::Pcmpeqb_xmm_xmmm128, Register::XMM15, Register::XMM14)?);
        out.push(Instruction::with2(Code::Pmovmskb_r32_xmm, Register::R11D, Register::XMM15)?);
        out.push(Instruction::with2(Code::Cmp_rm32_imm32, Register::R11D, 0xffffu32)?);
        out.branch(Instruction::with_branch(Code::Je_rel32_64, 0)?, state.gate);
    }
    out.push(Instruction::with(Code::Ud2));
    for (index, (state, &label)) in states.iter().zip(&labels).enumerate() {
        out.unwind(Row::dispatcher(&frames.saved));
        out.bind(state.gate);
        out.push(Instruction::with2(Code::Movdqu_xmm_xmmm128, Register::XMM14, stack(16))?);
        out.push(Instruction::with2(Code::Movdqu_xmm_xmmm128, Register::XMM15, stack(32))?);
        out.push(Instruction::with1(Code::Pop_r64, Register::R11)?);
        out.unwind(Row::dispatcher(&frames.saved).shifted(-8));
        out.push(Instruction::with(Code::Popfq));
        out.unwind(Row::dispatcher(&frames.saved).shifted(-16));
        out.push(Instruction::with2(Code::Lea_r64_m, Register::RSP, stack(FRAME_SIZE - 16))?);
        out.unwind(frames.rows[&function.insns[function.blocks[index].body.start].ip()].clone());
        out.jump(label)?;
    }
    let encoded = out.finish(base)?;
    let resumes = resumes
        .into_iter()
        .map(|(site, label)| Ok((site, encoded.address(label)?)))
        .collect::<Result<_>>()?;
    Ok(Output {
        code: encoded.code,
        blocks: function.blocks.len(),
        substitutions,
        entry_patch: function.entry_patch,
        resumes,
        moved: encoded.moved,
        unwind: encoded.unwind,
    })
}

fn restore_indirect(out: &mut Emitter, row: &Row) -> Result<()> {
    out.push(Instruction::with1(Code::Pop_r64, Register::R11)?);
    out.unwind(row.shifted(136));
    out.push(Instruction::with(Code::Popfq));
    out.unwind(row.shifted(128));
    out.push(Instruction::with2(Code::Lea_r64_m, Register::RSP, stack(128))?);
    out.unwind(row.clone());
    Ok(())
}

// transition.....
fn transition(
    out: &mut Emitter,
    state: &State,
    key: [u8; 16],
    dispatcher: Label,
    row: &Row,
    frames: &Frames,
) -> Result<()> {
    out.unwind(row.clone());
    out.push(Instruction::with2(Code::Lea_r64_m, Register::RSP, stack(-(FRAME_SIZE - 16)))?);
    out.unwind(row.shifted(FRAME_SIZE - 16));
    out.push(Instruction::with(Code::Pushfq));
    out.unwind(row.shifted(FRAME_SIZE - 8));
    out.push(Instruction::with1(Code::Push_r64, Register::R11)?);
    out.unwind(row.shifted(FRAME_SIZE));
    out.push(Instruction::with2(Code::Movdqu_xmmm128_xmm, stack(16), Register::XMM14)?);
    out.push(Instruction::with2(Code::Movdqu_xmmm128_xmm, stack(32), Register::XMM15)?);
    let Cfa::Register(register, offset) = row.cfa else { anyhow::bail!("invalid transition CFA") };
    let displacement = offset + if register == Register::RSP { FRAME_SIZE } else { 0 };
    out.push(Instruction::with2(
        Code::Lea_r64_m,
        Register::R11,
        MemoryOperand::with_base_displ(register, displacement),
    )?);
    out.push(Instruction::with2(Code::Mov_rm64_r64, stack(CFA_SLOT), Register::R11)?);
    for &register in &frames.saved {
        if let Some(Rule::Offset(offset)) = row.registers.get(&register) {
            out.push(Instruction::with2(Code::Mov_r64_rm64, Register::R11, stack(CFA_SLOT))?);
            out.push(Instruction::with2(
                Code::Mov_r64_rm64,
                Register::R11,
                MemoryOperand::with_base_displ(Register::R11, *offset),
            )?);
            out.push(Instruction::with2(
                Code::Mov_rm64_r64,
                stack(unwind::slot(register)),
                Register::R11,
            )?);
        } else {
            out.push(Instruction::with2(
                Code::Mov_rm64_r64,
                stack(unwind::slot(register)),
                register,
            )?);
        }
    }
    out.unwind(Row::dispatcher(&frames.saved));
    out.vector(Register::XMM14, state.input)?;
    out.vector(Register::XMM15, key)?;
    out.push(Instruction::with2(Code::Pxor_xmm_xmmm128, Register::XMM14, Register::XMM15)?);
    out.push(Instruction::with3(
        Code::Pshufd_xmm_xmmm128_imm8,
        Register::XMM15,
        Register::XMM14,
        0xb1u32,
    )?);
    out.push(Instruction::with2(Code::Pmuludq_xmm_xmmm128, Register::XMM14, Register::XMM15)?);
    out.push(Instruction::with3(
        Code::Pshufd_xmm_xmmm128_imm8,
        Register::XMM14,
        Register::XMM14,
        0x4eu32,
    )?);
    out.jump(dispatcher)
}

fn stack(displacement: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ(Register::RSP, displacement)
}

fn tag(input: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    let words: [u32; 4] = std::array::from_fn(|i| {
        u32::from_le_bytes(std::array::from_fn(|j| input[i * 4 + j] ^ key[i * 4 + j]))
    });
    let mut tag = [0; 16];
    tag[..8].copy_from_slice(&(words[2] as u64 * words[3] as u64).to_le_bytes());
    tag[8..].copy_from_slice(&(words[0] as u64 * words[1] as u64).to_le_bytes());
    tag
}
