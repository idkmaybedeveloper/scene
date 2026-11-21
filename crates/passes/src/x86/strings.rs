use anyhow::Result;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

use super::{GeneratedCode, emit::Emitter, unwind::Row};
use crate::strings::EncryptedString;

const SAVED: &[Register] = &[
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
];
const VECTORS: &[Register] = &[Register::XMM0, Register::XMM1, Register::XMM2];
const SYS_MPROTECT: u32 = 0x0200_004a;

pub struct Storage {
    pub state: u64,
    pub mapped_size: u64,
    pub source: u64,
    pub length: usize,
}

pub fn decoder(
    value: &EncryptedString,
    source: u64,
    output: u64,
    base: u64,
) -> Result<GeneratedCode> {
    let mut out = Emitter::new();
    out.unwind(Row::leaf());
    let block = out.label();
    let byte = out.label();
    let done = out.label();
    out.push(Instruction::with2(Code::Lea_r64_m, Register::RSP, memory(Register::RSP, -16))?);
    out.unwind(Row::leaf().shifted(16));
    out.push(Instruction::with2(
        Code::Lea_r64_m,
        Register::RAX,
        memory(Register::RIP, source as i64),
    )?);
    out.push(Instruction::with2(
        Code::Lea_r64_m,
        Register::RDI,
        memory(Register::RIP, output as i64),
    )?);
    out.push(Instruction::with2(
        Code::Mov_r64_imm64,
        Register::RCX,
        value.ciphertext.len() as u64,
    )?);
    out.vector(Register::XMM0, value.nonce[..16].try_into()?)?;
    out.vector(Register::XMM1, value.nonce[16..].try_into()?)?;
    out.push(Instruction::with2(Code::Pxor_xmm_xmmm128, Register::XMM0, Register::XMM1)?);
    out.push(Instruction::with2(
        Code::Movdqu_xmmm128_xmm,
        memory(Register::RSP, 0),
        Register::XMM0,
    )?);
    out.push(Instruction::with2(Code::Mov_r64_rm64, Register::R8, memory(Register::RSP, 0))?);
    out.push(Instruction::with2(Code::Mov_r64_rm64, Register::R9, memory(Register::RSP, 8))?);
    out.push(Instruction::with1(Code::Bswap_r64, Register::R8)?);
    out.push(Instruction::with1(Code::Bswap_r64, Register::R9)?);
    out.bind(block);
    for (register, offset) in [(Register::R8, 0), (Register::R9, 8)] {
        out.push(Instruction::with2(Code::Mov_r64_rm64, Register::R10, register)?);
        out.push(Instruction::with1(Code::Bswap_r64, Register::R10)?);
        out.push(Instruction::with2(
            Code::Mov_rm64_r64,
            memory(Register::RSP, offset),
            Register::R10,
        )?);
    }
    out.push(Instruction::with2(Code::Add_rm64_imm8, Register::R9, 1i32)?);
    out.push(Instruction::with2(Code::Adc_rm64_imm8, Register::R8, 0i32)?);
    out.push(Instruction::with2(
        Code::Movdqu_xmm_xmmm128,
        Register::XMM0,
        memory(Register::RSP, 0),
    )?);
    for (round, key) in value.keys.as_chunks::<32>().0.iter().enumerate() {
        out.vector(Register::XMM1, key[..16].try_into()?)?;
        out.vector(Register::XMM2, key[16..].try_into()?)?;
        out.push(Instruction::with2(Code::Pxor_xmm_xmmm128, Register::XMM1, Register::XMM2)?);
        let operation = match round {
            0 => Code::Pxor_xmm_xmmm128,
            10 => Code::Aesenclast_xmm_xmmm128,
            _ => Code::Aesenc_xmm_xmmm128,
        };
        out.push(Instruction::with2(operation, Register::XMM0, Register::XMM1)?);
    }
    out.push(Instruction::with2(
        Code::Movdqu_xmmm128_xmm,
        memory(Register::RSP, 0),
        Register::XMM0,
    )?);
    out.push(Instruction::with2(Code::Xor_rm32_r32, Register::R10D, Register::R10D)?);
    out.bind(byte);
    out.push(Instruction::with2(Code::Movzx_r32_rm8, Register::EDX, memory(Register::RAX, 0))?);
    out.push(Instruction::with2(
        Code::Xor_r8_rm8,
        Register::DL,
        MemoryOperand::with_base_index_scale(Register::RSP, Register::R10, 1),
    )?);
    out.push(Instruction::with2(Code::Mov_rm8_r8, memory(Register::RDI, 0), Register::DL)?);
    out.push(Instruction::with1(Code::Inc_rm64, Register::RAX)?);
    out.push(Instruction::with1(Code::Inc_rm64, Register::RDI)?);
    out.push(Instruction::with1(Code::Dec_rm64, Register::RCX)?);
    out.branch(Instruction::with_branch(Code::Je_rel32_64, 0)?, done);
    out.push(Instruction::with1(Code::Inc_rm32, Register::R10D)?);
    out.push(Instruction::with2(Code::Cmp_rm32_imm8, Register::R10D, 16i32)?);
    out.branch(Instruction::with_branch(Code::Jb_rel32_64, 0)?, byte);
    out.jump(block)?;
    out.bind(done);
    out.push(Instruction::with2(Code::Lea_r64_m, Register::RSP, memory(Register::RSP, 16))?);
    out.unwind(Row::leaf());
    out.push(Instruction::with(Code::Retnq));
    out.finish(base)
}

pub fn initializer(base: u64, storage: Storage, decoders: &[u64]) -> Result<GeneratedCode> {
    let state = storage.state;
    let mut out = Emitter::new();
    out.unwind(Row::leaf());
    let retry = out.label();
    let wait = out.label();
    let done = out.label();
    let failed = out.label();
    out.push(Instruction::with2(Code::Mov_r32_imm32, Register::EAX, SYS_MPROTECT)?);
    out.push(Instruction::with2(
        Code::Lea_r64_m,
        Register::RDI,
        memory(Register::RIP, state as i64),
    )?);
    out.push(Instruction::with2(Code::Mov_r64_imm64, Register::RSI, storage.mapped_size)?);
    out.push(Instruction::with2(Code::Mov_r32_imm32, Register::EDX, 3u32)?);
    out.push(Instruction::with(Code::Syscall));
    out.branch(Instruction::with_branch(Code::Jb_rel32_64, 0)?, failed);
    out.bind(retry);
    out.push(Instruction::with2(Code::Xor_rm32_r32, Register::EAX, Register::EAX)?);
    out.push(Instruction::with2(Code::Mov_r32_imm32, Register::EDX, 1u32)?);
    let mut acquire = Instruction::with2(
        Code::Cmpxchg_rm32_r32,
        memory(Register::RIP, state as i64),
        Register::EDX,
    )?;
    acquire.set_has_lock_prefix(true);
    out.push(acquire);
    out.branch(Instruction::with_branch(Code::Jne_rel32_64, 0)?, wait);
    out.push(Instruction::with2(
        Code::Lea_r64_m,
        Register::RSI,
        memory(Register::RIP, storage.source as i64),
    )?);
    out.push(Instruction::with2(
        Code::Lea_r64_m,
        Register::RDI,
        memory(Register::RIP, state as i64 + 16),
    )?);
    out.push(Instruction::with2(Code::Mov_r64_imm64, Register::RCX, storage.length as u64)?);
    out.push(Instruction::with(Code::Cld));
    out.push(Instruction::with_rep_movsb(64)?);
    for &decoder in decoders {
        out.push(Instruction::with_branch(Code::Call_rel32_64, decoder)?);
    }
    out.push(Instruction::with2(Code::Mov_rm32_imm32, memory(Register::RIP, state as i64), 2u32)?);
    out.jump(done)?;
    out.bind(wait);
    out.push(Instruction::with2(Code::Cmp_EAX_imm32, Register::EAX, 2u32)?);
    out.branch(Instruction::with_branch(Code::Je_rel32_64, 0)?, done);
    out.push(Instruction::with(Code::Pause));
    out.jump(retry)?;
    out.bind(done);
    out.push(Instruction::with(Code::Retnq));
    out.bind(failed);
    out.push(Instruction::with(Code::Ud2));
    out.finish(base)
}

pub fn reference(
    base: u64,
    state: u64,
    initialize: u64,
    original: &Instruction,
    target: u64,
    row: &Row,
    after: &Row,
) -> Result<GeneratedCode> {
    let mut out = Emitter::new();
    out.unwind(row.clone());
    let ready = out.label();
    out.push(Instruction::with2(Code::Lea_r64_m, Register::RSP, memory(Register::RSP, -128))?);
    out.unwind(row.shifted(128));
    out.push(Instruction::with(Code::Pushfq));
    let mut delta = 136;
    out.unwind(row.shifted(delta));
    for &register in SAVED {
        out.push(Instruction::with1(Code::Push_r64, register)?);
        delta += 8;
        out.unwind(row.shifted(delta));
    }
    out.push(Instruction::with2(Code::Lea_r64_m, Register::RSP, memory(Register::RSP, -48))?);
    delta += 48;
    out.unwind(row.shifted(delta));
    for (index, &register) in VECTORS.iter().enumerate() {
        out.push(Instruction::with2(
            Code::Movdqu_xmmm128_xmm,
            memory(Register::RSP, index as i64 * 16),
            register,
        )?);
    }
    out.push(Instruction::with2(Code::Cmp_rm32_imm8, memory(Register::RIP, state as i64), 2i32)?);
    out.branch(Instruction::with_branch(Code::Je_rel32_64, 0)?, ready);
    out.push(Instruction::with_branch(Code::Call_rel32_64, initialize)?);
    out.bind(ready);
    for (index, &register) in VECTORS.iter().enumerate() {
        out.push(Instruction::with2(
            Code::Movdqu_xmm_xmmm128,
            register,
            memory(Register::RSP, index as i64 * 16),
        )?);
    }
    out.push(Instruction::with2(Code::Lea_r64_m, Register::RSP, memory(Register::RSP, 48))?);
    delta -= 48;
    out.unwind(row.shifted(delta));
    for &register in SAVED.iter().rev() {
        out.push(Instruction::with1(Code::Pop_r64, register)?);
        delta -= 8;
        out.unwind(row.shifted(delta));
    }
    out.push(Instruction::with(Code::Popfq));
    out.unwind(row.shifted(128));
    out.push(Instruction::with2(Code::Lea_r64_m, Register::RSP, memory(Register::RSP, 128))?);
    out.unwind(row.clone());
    let mut reference = *original;
    reference.set_memory_displacement64(target);
    out.push(reference);
    out.unwind(after.clone());
    out.jump_to(original.next_ip())?;
    out.finish(base)
}

fn memory(base: Register, displacement: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ(base, displacement)
}
