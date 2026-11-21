use anyhow::{Result, bail, ensure};
use bad64::{Instruction, Op, Operand};
use dynasmrt::{
    DynamicLabel, DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation, dynasm,
};

use super::{
    bytecode::{Kind, Record},
    context::{FRAME_SIZE, SP_OFFSET, STATE_SIZE},
    mutation::Mutation,
    operands,
};

enum Writeback {
    None,
    Before,
    After,
}

pub fn lift(decoded: &Instruction) -> Result<Option<Vec<Record>>> {
    let op = decoded.op();
    let kind = match op {
        Op::LDR | Op::LDUR => Kind::Load,
        Op::STR | Op::STUR => Kind::Store,
        Op::LDP => Kind::LoadPair,
        Op::STP => Kind::StorePair,
        _ => return Ok(None),
    };
    let pair = matches!(op, Op::LDP | Op::STP);
    let load = matches!(op, Op::LDR | Op::LDUR | Op::LDP);
    let (dst, second, address) = match decoded.operands() {
        [dst, address] if !pair => (dst, None, address),
        [dst, second, address] if pair => (dst, Some(second), address),
        _ => bail!("vm: unsupported memory operands {decoded}"),
    };
    if matches!(address, Operand::Label(_)) {
        return Ok(None);
    }
    let dst = operands::register(dst)?;
    let second = second.map(operands::register).transpose()?;
    ensure!(second.as_ref().is_none_or(|r| r.wide == dst.wide), "vm: mixed memory widths");
    let (base, offset, writeback) = match *address {
        Operand::MemReg(reg) => (reg, 0, Writeback::None),
        Operand::MemOffset { reg, offset, mul_vl: false, arrspec: None } => {
            (reg, scene_disasm::arm64::immediate(offset), Writeback::None)
        }
        Operand::MemPreIdx { reg, imm } => {
            (reg, scene_disasm::arm64::immediate(imm), Writeback::Before)
        }
        Operand::MemPostIdxImm { reg, imm } => {
            (reg, scene_disasm::arm64::immediate(imm), Writeback::After)
        }
        _ => bail!("vm: unsupported addressing mode {address}"),
    };
    let base = operands::general_register(base)?;
    ensure!(base.wide, "vm: unsupported address register width");
    let mut memory = Record::new(kind, dst.wide);
    memory.dst = dst.index;
    memory.lhs = base.index;
    memory.rhs = second.map_or(31, |r| r.index);
    memory.aux = u32::from(memory.rhs);
    ensure!(
        matches!(writeback, Writeback::None)
            || (memory.lhs != memory.dst && (!pair || memory.lhs != memory.rhs)),
        "vm: overlapping memory writeback"
    );
    ensure!(!pair || !load || memory.dst != memory.rhs, "vm: overlapping pair destinations");
    let mut adjust = Record::new(Kind::Add, true);
    adjust.dst = memory.lhs;
    adjust.lhs = memory.lhs;
    adjust.rhs = 255;
    adjust.immediate = offset;
    match writeback {
        Writeback::None => {
            memory.immediate = offset;
            Ok(Some(vec![memory]))
        }
        Writeback::Before => Ok(Some(vec![adjust, memory])),
        Writeback::After => Ok(Some(vec![memory, adjust])),
    }
}

#[allow(clippy::useless_conversion)]
pub fn emit(
    asm: &mut VecAssembler<Aarch64Relocation>,
    kind: Kind,
    wide: bool,
    mutation: &Mutation,
    store: DynamicLabel,
    dispatch: DynamicLabel,
) {
    let r = &mutation.registers;
    dynasm!(asm; .arch aarch64; add X(r.opcode), X(r.lhs), X(r.immediate));
    match kind {
        Kind::Load | Kind::LoadPair => {
            if wide {
                dynasm!(asm; .arch aarch64; ldr X(r.lhs), [X(r.opcode)]);
            } else {
                dynasm!(asm; .arch aarch64; ldr W(r.lhs), [X(r.opcode)]);
            }
            if kind == Kind::LoadPair {
                if wide {
                    dynasm!(asm; .arch aarch64; ldr X(r.rhs), [X(r.opcode), #8]);
                } else {
                    dynasm!(asm; .arch aarch64; ldr W(r.rhs), [X(r.opcode), #4]);
                }
                dynasm!(asm; .arch aarch64; str X(r.rhs), [sp, X(r.aux), LSL #3]);
            }
            dynasm!(asm; .arch aarch64; b =>store);
        }
        _ => {
            dynasm!(asm; .arch aarch64; ldr X(r.scratch), [sp, X(r.dst), LSL #3]);
            if wide {
                dynasm!(asm; .arch aarch64; str X(r.scratch), [X(r.opcode)]);
            } else {
                dynasm!(asm; .arch aarch64; str W(r.scratch), [X(r.opcode)]);
            }
            if kind == Kind::StorePair {
                if wide {
                    dynasm!(asm; .arch aarch64; str X(r.rhs), [X(r.opcode), #8]);
                } else {
                    dynasm!(asm; .arch aarch64; str W(r.rhs), [X(r.opcode), #4]);
                }
            }
            dynasm!(asm; .arch aarch64; b =>dispatch);
        }
    }
}

#[allow(clippy::useless_conversion)]
pub fn move_stack(
    asm: &mut VecAssembler<Aarch64Relocation>,
    mutation: &Mutation,
    dispatch: DynamicLabel,
) {
    /* Native memory operations must see the original SP and its red zone.
     * Move only the private VM state, choosing the memmove direction for overlap.
     * This helper stays outside MBA/CFF because their temporary stack saves can
     * overwrite the destination while the private frame is being relocated.
     */
    let r = &mutation.registers;
    let backward = asm.new_dynamic_label();
    let forward_loop = asm.new_dynamic_label();
    let backward_loop = asm.new_dynamic_label();
    let finish = asm.new_dynamic_label();
    dynasm!(asm; .arch aarch64
        ; sub XSP(r.scratch), XSP(r.lhs), FRAME_SIZE
        ; mov XSP(r.opcode), sp
        ; cmp X(r.scratch), X(r.opcode)
        ; b.eq =>finish
        ; mov W(r.aux), STATE_SIZE / 16
        ; b.hi =>backward
        ; =>forward_loop
        ; ldr q0, [X(r.opcode)], #16
        ; str q0, [X(r.scratch)], #16
        ; subs W(r.aux), WSP(r.aux), #1
        ; b.ne =>forward_loop
        ; b =>finish
        ; =>backward
        ; add XSP(r.opcode), XSP(r.opcode), STATE_SIZE
        ; add XSP(r.scratch), XSP(r.scratch), STATE_SIZE
        ; =>backward_loop
        ; ldr q0, [X(r.opcode), #-16]!
        ; str q0, [X(r.scratch), #-16]!
        ; subs W(r.aux), WSP(r.aux), #1
        ; b.ne =>backward_loop
        ; =>finish
        ; sub XSP(r.scratch), XSP(r.lhs), FRAME_SIZE
        ; mov sp, XSP(r.scratch)
        ; str X(r.lhs), [sp, SP_OFFSET]
        ; b =>dispatch
    );
}
