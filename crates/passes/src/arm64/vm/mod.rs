// stolen from https://github.com/dmaivel/covirt
mod bytecode;
mod cipher;
mod context;
mod harden;
mod lift;
mod memory;
mod mutation;
mod operands;
mod runtime;

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use anyhow::Result;
pub use cipher::Binding;
use scene_disasm::arm64::Insn;

pub struct Options {
    pub seed: u32,
    pub strength: u32,
    pub anchors: Vec<u64>,
    pub mutation_seed: Option<u64>,
    pub addresses: BTreeMap<u64, u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            seed: 0x7363_656e,
            strength: 2,
            anchors: Vec::new(),
            mutation_seed: None,
            addresses: BTreeMap::new(),
        }
    }
}

pub struct Output {
    pub code: Vec<u8>,
    pub bytecode: Range<usize>,
    pub instructions: usize,
    pub entry_patch: u64,
    pub sources: Vec<u64>,
    pub listing: Vec<DumpRow>,
    pub binding: Binding,
    pub runtime_size: usize,
    pub raw_runtime_size: usize,
    pub substitutions: usize,
    pub handlers: usize,
    pub mutation_seed: u64,
    pub kept: BTreeSet<u64>,
    pub resumes: BTreeMap<u64, u64>,
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
    transform_with_options(insns, base, Options { seed, ..Options::default() })
}

pub fn transform_with_options(insns: &[Insn], base: u64, options: Options) -> Result<Output> {
    let mut program = lift::lift(insns)?;
    for (record, source) in program.records.iter_mut().zip(&program.sources) {
        if let Some(&target) = options.addresses.get(&source.address) {
            record.opcode =
                bytecode::Opcode { kind: bytecode::Kind::Address, wide: true, flags: false };
            record.immediate = target;
        }
    }
    runtime::emit(&program, base, options)
}

pub fn validate(insns: &[Insn]) -> Result<()> {
    lift::lift(insns).map(|_| ())
}
