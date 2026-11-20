pub mod arm64;
pub mod x86;

use std::{fmt, ops::Range};

use anyhow::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86,
    X64,
    Arm64,
}

// a decoded chunk of code
#[derive(Clone, Debug)]
pub enum Listing {
    X86 { bitness: u32, insns: Vec<x86::Insn> },
    Arm64(Vec<arm64::Insn>),
}

pub fn disassemble(arch: Arch, code: &[u8], base: u64, data: &[Range<u64>]) -> Result<Listing> {
    let is_data =
        |range: Range<u64>| data.iter().any(|d| d.start < range.end && range.start < d.end);
    Ok(match arch {
        Arch::X86 => Listing::X86 { bitness: 32, insns: x86::decode(32, code, base, data) },
        Arch::X64 => Listing::X86 { bitness: 64, insns: x86::decode(64, code, base, data) },
        Arch::Arm64 => Listing::Arm64(arm64::decode(code, base, is_data)?),
    })
}

impl Listing {
    pub fn len(&self) -> usize {
        match self {
            Listing::X86 { insns, .. } => insns.len(),
            Listing::Arm64(insns) => insns.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Display for Listing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Listing::X86 { insns, .. } => x86::fmt_listing(insns, f),
            Listing::Arm64(insns) => arm64::fmt_listing(insns, f),
        }
    }
}
