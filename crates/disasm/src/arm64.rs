use std::{fmt, ops::Range};

use anyhow::{Result, ensure};
use bad64::{Condition, Imm, Instruction, Op, Operand, Reg};
#[derive(Clone, Debug)]
pub struct Insn {
    pub address: u64,
    pub word: u32,
    pub target: Option<u64>,
    pub data: bool,
}

impl Insn {
    pub fn decode(&self) -> Option<bad64::Instruction> {
        bad64::decode(self.word, self.address).ok()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcRel {
    Imm26,
    Imm19,
    Imm14,
    Adr,
    Adrp,
}

//TODO: FEAT_CMPBR compare-and-branch (CB<cc>) has its own imm9 form
pub fn pc_rel(word: u32) -> Option<PcRel> {
    let decoded = bad64::decode(word, 0).ok()?;
    match decoded.op() {
        Op::B | Op::BL => Some(PcRel::Imm26),
        Op::CBZ | Op::CBNZ => Some(PcRel::Imm19),
        Op::TBZ | Op::TBNZ => Some(PcRel::Imm14),
        Op::ADR => Some(PcRel::Adr),
        Op::ADRP => Some(PcRel::Adrp),
        Op::LDR | Op::LDRSW | Op::PRFM if label(&decoded).is_some() => Some(PcRel::Imm19),
        op if branch_condition(op).is_some() => Some(PcRel::Imm19),
        _ => None,
    }
}

pub fn target(word: u32, pc: u64) -> Option<u64> {
    label(&bad64::decode(word, pc).ok()?)
}

pub fn label(instruction: &Instruction) -> Option<u64> {
    instruction.operands().iter().find_map(|operand| match operand {
        Operand::Label(value) => Some(immediate(*value)),
        _ => None,
    })
}

pub fn immediate(value: Imm) -> u64 {
    match value {
        Imm::Signed(value) => value as u64,
        Imm::Unsigned(value) => value,
    }
}

pub fn register_index(register: Reg) -> Option<u8> {
    match register {
        Reg::SP | Reg::WSP => Some(32),
        Reg::XZR | Reg::WZR => Some(31),
        Reg::X29 => Some(29),
        Reg::X30 => Some(30),
        register => {
            register.name().strip_prefix(['x', 'w'])?.parse::<u8>().ok().filter(|&index| index < 31)
        }
    }
}

pub fn branch_condition(op: Op) -> Option<Condition> {
    Some(match op {
        Op::B_EQ => Condition::EQ,
        Op::B_NE => Condition::NE,
        Op::B_CS => Condition::CS,
        Op::B_CC => Condition::CC,
        Op::B_MI => Condition::MI,
        Op::B_PL => Condition::PL,
        Op::B_VS => Condition::VS,
        Op::B_VC => Condition::VC,
        Op::B_HI => Condition::HI,
        Op::B_LS => Condition::LS,
        Op::B_GE => Condition::GE,
        Op::B_LT => Condition::LT,
        Op::B_GT => Condition::GT,
        Op::B_LE => Condition::LE,
        Op::B_AL => Condition::AL,
        Op::B_NV => Condition::NV,
        _ => return None,
    })
}

pub fn is_conditional_branch(op: Op) -> bool {
    matches!(op, Op::CBZ | Op::CBNZ | Op::TBZ | Op::TBNZ) || branch_condition(op).is_some()
}

pub fn decode(code: &[u8], base: u64, is_data: impl Fn(Range<u64>) -> bool) -> Result<Vec<Insn>> {
    ensure!(
        code.len().is_multiple_of(4),
        "arm64 code size {:#x} is not a multiple of 4",
        code.len()
    );
    Ok(code
        .as_chunks::<4>()
        .0
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let address = base + 4 * i as u64;
            let word = u32::from_le_bytes(*chunk);
            let data = is_data(address..address + 4);
            let target = if data { None } else { target(word, address) };
            Insn { address, word, target, data }
        })
        .collect())
}

pub(crate) fn fmt_listing(insns: &[Insn], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for insn in insns {
        match insn.decode().filter(|_| !insn.data) {
            Some(decoded) => writeln!(f, "{:016x}  {:08x}  {decoded}", insn.address, insn.word)?,
            None => writeln!(f, "{:016x}  {:08x}  .word", insn.address, insn.word)?,
        }
    }
    Ok(())
}
