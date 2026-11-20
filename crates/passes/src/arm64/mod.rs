mod cff;
mod cfg;
mod emit;
mod mba;

use std::collections::BTreeMap;

use anyhow::Result;
use scene_disasm::arm64::Insn;

use cfg::Function;
use emit::Emitter;

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub mba: bool,
    pub cff: bool,
    pub seed: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self { mba: true, cff: true, seed: 0x7363_656e }
    }
}

#[derive(Clone, Debug)]
pub struct Output {
    pub insns: Vec<Insn>,
    pub blocks: usize,
    pub substitutions: usize,
    pub flattened: bool,
    pub block_addresses: BTreeMap<u64, u64>,
}

pub fn reachable_len(insns: &[Insn]) -> Result<usize> {
    cfg::reachable_len(insns)
}

pub fn transform(insns: &[Insn], base: u64, options: Options) -> Result<Output> {
    let function = Function::parse(insns)?;
    let mut emitter = Emitter::new(base)?;
    let labels: Vec<_> = function.blocks.iter().map(|_| emitter.label()).collect();
    if options.cff {
        cff::emit(&function, &labels, &mut emitter, options)?;
    } else {
        for (index, block) in function.blocks.iter().enumerate() {
            emitter.bind(labels[index]);
            emit_body(&mut emitter, &insns[block.body.clone()], options.mba)?;
            block.exit.emit(&mut emitter, &labels)?;
        }
    }
    let block_addresses = function
        .blocks
        .iter()
        .zip(&labels)
        .map(|(block, &label)| Ok((block.address, emitter.address(label)?)))
        .collect::<Result<_>>()?;
    let substitutions = emitter.substitutions;
    Ok(Output {
        insns: emitter.finish()?,
        blocks: function.blocks.len(),
        substitutions,
        flattened: options.cff,
        block_addresses,
    })
}

fn emit_body(emitter: &mut Emitter, insns: &[Insn], substitute: bool) -> Result<()> {
    for insn in insns {
        if substitute && mba::emit(insn.word, emitter) {
            emitter.substitutions += 1;
        } else {
            emitter.original(insn)?;
        }
    }
    Ok(())
}
