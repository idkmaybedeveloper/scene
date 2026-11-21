mod cff;
mod cfg;
mod emit;
mod mba;
mod relocate;
pub mod strings;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use scene_disasm::arm64::Insn;

use cfg::Function;
use emit::Emitter;

#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// mba nesting depth: 0 disables substitution, higher nests the identities deeper
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

#[derive(Clone, Debug)]
pub struct Output {
    pub insns: Vec<Insn>,
    pub blocks: usize,
    pub substitutions: usize,
    pub flattened: bool,
    pub block_addresses: BTreeMap<u64, u64>,
    pub resumes: BTreeMap<u64, u64>,
    pub entry_patch: u64,
    pub moved: BTreeMap<u64, u64>,
    pub kept: BTreeSet<u64>,
}

pub fn reachable_len(insns: &[Insn]) -> Result<usize> {
    cfg::reachable_len(insns)
}

pub fn mba_sites(insns: &[Insn]) -> Result<Vec<usize>> {
    cfg::mba_sites(insns)
}

pub fn substitute(insn: &Insn, base: u64, depth: u32) -> Result<Option<Vec<Insn>>> {
    let mut emitter = Emitter::new(base)?;
    if depth == 0 || !mba::emit(insn.word, &mut emitter, depth) {
        return Ok(None);
    }
    emitter.jump_to(insn.address + 4);
    Ok(Some(emitter.finish()?))
}

pub fn transform(insns: &[Insn], base: u64, options: Options) -> Result<Output> {
    let len = cfg::reachable_len(insns)?;
    let function = Function::parse(&insns[..len], options.cff)?;
    let mut emitter = Emitter::new(base)?;
    let labels: Vec<_> = function.blocks.iter().map(|_| emitter.label()).collect();
    if options.cff > 0 {
        cff::emit(&function, &labels, &mut emitter, options)?;
    } else {
        for (index, block) in function.blocks.iter().enumerate() {
            emitter.bind(labels[index]);
            emit_body(&mut emitter, &insns[block.body.clone()], options.mba)?;
            if let Some(address) = block.exit_address {
                emitter.record(address);
            }
            block.exit.emit(&mut emitter, &labels);
        }
    }
    let block_addresses = function
        .blocks
        .iter()
        .zip(&labels)
        .map(|(block, &label)| Ok((block.address, emitter.address(label)?)))
        .collect::<Result<_>>()?;
    let substitutions = emitter.substitutions;
    let resumes = emitter.resumes.clone();
    relocate::remaining(&mut emitter, insns)?;
    let moved = emitter.moved.clone();
    let kept = insns
        .iter()
        .filter(|i| i.decode().is_some_and(|d| cfg::is_call(d.op()) || d.op() == bad64::Op::BTI))
        .map(|i| i.address)
        .collect();
    Ok(Output {
        insns: emitter.finish()?,
        blocks: function.blocks.len(),
        substitutions,
        flattened: options.cff > 0,
        block_addresses,
        resumes,
        entry_patch: function.entry_patch,
        moved,
        kept,
    })
}

fn emit_body(emitter: &mut Emitter, insns: &[Insn], depth: u32) -> Result<()> {
    for insn in insns {
        emitter.record(insn.address);
        if depth > 0 && mba::emit(insn.word, emitter, depth) {
            emitter.substitutions += 1;
        } else {
            emitter.original(insn)?;
        }
    }
    Ok(())
}
