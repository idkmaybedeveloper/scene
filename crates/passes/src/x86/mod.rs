mod cff;
mod cfg;
mod emit;
mod mba;
pub mod strings;
pub mod unwind;
pub use emit::Encoded as GeneratedCode;

use std::collections::BTreeMap;

use anyhow::Result;
use iced_x86::{FlowControl, Instruction, Mnemonic};

#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// mba nesting depth: 0 disables substitution, higher re-substitutes generated ops
    pub mba: u32,
    /// cff intensity: 0 disables flattening, higher splits blocks finer and adds decoys
    pub cff: u32,
    pub seed: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self { mba: 1, cff: 1, seed: 0x7363_656e }
    }
}

pub struct Output {
    pub code: Vec<u8>,
    pub blocks: usize,
    pub substitutions: usize,
    pub entry_patch: u64,
    pub resumes: BTreeMap<u64, u64>,
    pub moved: BTreeMap<u64, u64>,
    pub unwind: Vec<(u64, unwind::Row)>,
}

pub fn transform(insns: &[Instruction], base: u64, options: Options) -> Result<Output> {
    transform_with_tables(insns, base, options, &BTreeMap::new())
}

pub fn transform_with_tables(
    insns: &[Instruction],
    base: u64,
    options: Options,
    tables: &BTreeMap<u64, Vec<u64>>,
) -> Result<Output> {
    cff::transform(&cfg::Function::parse(insns, tables, options.cff)?, base, options)
}

pub fn substitute(insns: &[Instruction], base: u64, depth: u32) -> Result<Option<Vec<u8>>> {
    let Some(insn) = insns.first() else { return Ok(None) };
    if depth == 0 || insn.len() < 5 {
        return Ok(None);
    }
    let flags_dead = matches!(insn.mnemonic(), Mnemonic::Add | Mnemonic::Sub) && flags_dead(insns);
    let Some(replacement) = mba::substitute(insn, flags_dead, depth)? else {
        return Ok(None);
    };
    let mut bytes = scene_asm::x86::relocate(64, &replacement, base)?;
    bytes.extend(scene_asm::x86::jump(base + bytes.len() as u64, insn.next_ip())?);
    Ok(Some(bytes))
}

fn flags_dead(insns: &[Instruction]) -> bool {
    let mut pending = insns[0].rflags_modified();
    for insn in &insns[1..] {
        if insn.rflags_read() & pending != 0 {
            return false;
        }
        pending &= !insn.rflags_modified();
        if pending == 0 {
            return true;
        }
        if insn.flow_control() != FlowControl::Next {
            return false;
        }
    }
    false
}
