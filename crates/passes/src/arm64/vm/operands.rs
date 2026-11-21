use anyhow::{Result, bail, ensure};
use bad64::{Operand, Reg, Shift};

use scene_disasm::arm64::{immediate, register_index};

pub struct Register {
    pub index: u8,
    pub wide: bool,
}

pub fn register(operand: &Operand) -> Result<Register> {
    match *operand {
        Operand::Reg { reg, arrspec: None } => general_register(reg),
        _ => bail!("vm: expected general register, got {operand}"),
    }
}

pub fn general_register(reg: Reg) -> Result<Register> {
    ensure!(reg.size() == 4 || reg.size() == 8, "vm: unsupported register {reg}");
    let index =
        register_index(reg).ok_or_else(|| anyhow::anyhow!("vm: unsupported register {reg}"))?;
    Ok(Register { index, wide: reg.size() == 8 })
}

pub fn integer(operand: &Operand) -> Result<u64> {
    match *operand {
        Operand::Imm32 { imm, shift } | Operand::Imm64 { imm, shift } => {
            let value = immediate(imm);
            match shift {
                None => Ok(value),
                Some(Shift::LSL(amount)) if amount < 64 => Ok(value.wrapping_shl(amount)),
                _ => bail!("vm: unsupported immediate shift {operand}"),
            }
        }
        _ => bail!("vm: expected integer, got {operand}"),
    }
}

pub fn shift(shift: Shift) -> Result<u32> {
    let (kind, amount) = match shift {
        Shift::LSL(amount) => (0, amount),
        Shift::LSR(amount) => (1, amount),
        Shift::ASR(amount) => (2, amount),
        Shift::ROR(amount) => (3, amount),
        _ => bail!("vm: unsupported register extension {shift}"),
    };
    ensure!(amount < 64, "vm: invalid shift amount");
    Ok(kind | amount << 2)
}
