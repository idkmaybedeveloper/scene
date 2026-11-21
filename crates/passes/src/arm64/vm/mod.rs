// stolen from https://github.com/dmaivel/covirt
mod bytecode;
mod context;
mod lift;
mod runtime;

use std::ops::Range;

use anyhow::Result;
use scene_disasm::arm64::Insn;

pub struct Output {
    pub code: Vec<u8>,
    pub bytecode: Range<usize>,
    pub instructions: usize,
    pub entry_patch: u64,
    pub sources: Vec<u64>,
    pub listing: Vec<DumpRow>,
}

pub struct DumpRow {
    pub offset: usize,
    pub source: u64,
    pub source_text: String,
    pub opcode: u8,
    pub operation: String,
}

impl std::fmt::Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "| offset | source             | lifted from                          | op | vm instruction"
        )?;
        writeln!(
            f,
            "|--------|--------------------|--------------------------------------|----|--------------------"
        )?;
        for row in &self.listing {
            writeln!(
                f,
                "| {:06x} | {:#018x} | {:<36} | {:02x} | {}",
                row.offset, row.source, row.source_text, row.opcode, row.operation
            )?;
        }
        Ok(())
    }
}

pub fn transform(insns: &[Insn], base: u64, seed: u32) -> Result<Output> {
    let program = lift::lift(insns)?;
    runtime::emit(&program, base, seed)
}

pub fn validate(insns: &[Insn]) -> Result<()> {
    lift::lift(insns).map(|_| ())
}
