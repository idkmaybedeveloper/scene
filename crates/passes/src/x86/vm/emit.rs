use super::super::emit::{Emitter, Label};
use anyhow::Result;
use iced_x86::{Code, Instruction, MemoryOperand, Register};

pub const GPRS: [Register; 16] = [
    Register::RAX,
    Register::RCX,
    Register::RDX,
    Register::RBX,
    Register::RSP,
    Register::RBP,
    Register::RSI,
    Register::RDI,
    Register::R8,
    Register::R9,
    Register::R10,
    Register::R11,
    Register::R12,
    Register::R13,
    Register::R14,
    Register::R15,
];
pub fn memory(base: Register, offset: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ(base, offset)
}
pub fn indexed(base: Register, index: Register, scale: u32, offset: i64) -> MemoryOperand {
    MemoryOperand::new(base, index, scale, offset, 1, false, Register::None)
}
pub fn sized(reg: Register, width: usize) -> Register {
    let first = match width {
        1 => Register::AL,
        2 => Register::AX,
        4 => Register::EAX,
        _ => Register::RAX,
    };
    if width == 1 && reg.number() >= 4 {
        Register::try_from(Register::SPL as usize + reg.number() - 4).unwrap()
    } else {
        Register::try_from(first as usize + reg.number()).unwrap()
    }
}
pub fn constant(out: &mut Emitter, reg: Register, value: u64) -> Result<()> {
    out.push(Instruction::with2(Code::Mov_r64_imm64, reg, value)?);
    Ok(())
}
pub fn load(out: &mut Emitter, reg: Register, base: Register, offset: i64) -> Result<()> {
    out.push(Instruction::with2(Code::Mov_r64_rm64, reg, memory(base, offset))?);
    Ok(())
}
pub fn store(out: &mut Emitter, base: Register, offset: i64, reg: Register) -> Result<()> {
    out.push(Instruction::with2(Code::Mov_rm64_r64, memory(base, offset), reg)?);
    Ok(())
}
pub fn lea(out: &mut Emitter, reg: Register, label: Label) -> Result<()> {
    out.reference(Instruction::with2(Code::Lea_r64_m, reg, memory(Register::RIP, 0))?, label);
    Ok(())
}
pub fn branch(out: &mut Emitter, code: Code, label: Label) -> Result<()> {
    out.branch(Instruction::with_branch(code, 0)?, label);
    Ok(())
}
pub fn compare(out: &mut Emitter, reg: Register, value: i32) -> Result<()> {
    out.push(Instruction::with2(Code::Cmp_rm64_imm32, reg, value)?);
    Ok(())
}

pub fn read(out: &mut Emitter, dst: Register, address: MemoryOperand, width: usize) -> Result<()> {
    let (code, reg) = match width {
        1 => (Code::Movzx_r64_rm8, dst),
        2 => (Code::Movzx_r64_rm16, dst),
        4 => (Code::Mov_r32_rm32, sized(dst, 4)),
        _ => (Code::Mov_r64_rm64, dst),
    };
    out.push(Instruction::with2(code, reg, address)?);
    Ok(())
}
pub fn write(out: &mut Emitter, address: MemoryOperand, reg: Register, width: usize) -> Result<()> {
    let code = match width {
        1 => Code::Mov_rm8_r8,
        2 => Code::Mov_rm16_r16,
        4 => Code::Mov_rm32_r32,
        _ => Code::Mov_rm64_r64,
    };
    out.push(Instruction::with2(code, address, sized(reg, width))?);
    Ok(())
}
