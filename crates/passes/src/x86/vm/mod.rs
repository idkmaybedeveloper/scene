mod context;
mod emit;
mod lift;
mod runtime;

use std::{collections::BTreeMap, ops::Range};

use super::unwind::Row;
pub use crate::vm::Binding;
use anyhow::Result;
use iced_x86::Instruction;

pub struct Options {
    pub seed: u32,
    pub mutation_seed: Option<u64>,
    pub anchors: Vec<u64>,
    pub addresses: BTreeMap<u64, u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            seed: 0x7363656e,
            mutation_seed: None,
            anchors: Vec::new(),
            addresses: BTreeMap::new(),
        }
    }
}

pub struct Output {
    pub code: Vec<u8>,
    pub bytecode: Range<usize>,
    pub entry_patch: u64,
    pub sources: Vec<u64>,
    pub binding: Binding,
    pub instructions: usize,
    pub handlers: usize,
    pub unwind: Vec<(u64, Row)>,
    pub moved: BTreeMap<u64, u64>,
}

pub fn validate(insns: &[Instruction]) -> Result<()> {
    lift::lift(insns).map(|_| ())
}

pub fn transform(insns: &[Instruction], base: u64, options: Options) -> Result<Output> {
    runtime::emit(&lift::lift(insns)?, base, options)
}
