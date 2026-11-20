use std::{fmt, ops::Range};

use anyhow::{Result, ensure};
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

// ref: Arm ARM, C4.1 "A64 instruction set encoding", sections
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
    match word {
        w if w & 0x7C00_0000 == 0x1400_0000 => Some(PcRel::Imm26),
        w if w & 0xFF00_0000 == 0x5400_0000 => Some(PcRel::Imm19),
        w if w & 0x7E00_0000 == 0x3400_0000 => Some(PcRel::Imm19),
        w if w & 0x3B00_0000 == 0x1800_0000 => Some(PcRel::Imm19),
        w if w & 0x7E00_0000 == 0x3600_0000 => Some(PcRel::Imm14),
        w if w & 0x9F00_0000 == 0x1000_0000 => Some(PcRel::Adr),
        w if w & 0x9F00_0000 == 0x9000_0000 => Some(PcRel::Adrp),
        _ => None,
    }
}

pub fn target(word: u32, pc: u64) -> Option<u64> {
    let adr_imm = || (((word >> 5) & 0x7_FFFF) << 2 | (word >> 29) & 3) as u64;
    Some(match pc_rel(word)? {
        PcRel::Imm26 => pc.wrapping_add_signed(sext(word as u64 & 0x3FF_FFFF, 26) << 2),
        PcRel::Imm19 => pc.wrapping_add_signed(sext((word >> 5) as u64 & 0x7_FFFF, 19) << 2),
        PcRel::Imm14 => pc.wrapping_add_signed(sext((word >> 5) as u64 & 0x3FFF, 14) << 2),
        PcRel::Adr => pc.wrapping_add_signed(sext(adr_imm(), 21)),
        PcRel::Adrp => (pc & !0xFFF).wrapping_add_signed(sext(adr_imm(), 21) << 12),
    })
}

fn sext(value: u64, bits: u32) -> i64 {
    ((value << (64 - bits)) as i64) >> (64 - bits)
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
