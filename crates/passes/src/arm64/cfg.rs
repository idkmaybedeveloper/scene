use std::{collections::BTreeSet, ops::Range};

use anyhow::{Result, anyhow, bail, ensure};
use scene_disasm::arm64::{Insn, target};

use super::emit::{Emitter, Label};

pub struct Function<'a> {
    pub insns: &'a [Insn],
    pub blocks: Vec<Block>,
}

pub struct Block {
    pub address: u64,
    pub body: Range<usize>,
    pub exit: Exit,
}

pub enum Exit {
    Return,
    Jump(usize),
    Conditional { word: u32, taken: usize, fallthrough: usize },
}

impl Exit {
    pub fn emit(&self, out: &mut Emitter, labels: &[Label]) -> Result<()> {
        match *self {
            Self::Return => out.ret(),
            Self::Jump(next) => out.jump(labels[next]),
            Self::Conditional { word, taken, fallthrough } => {
                out.branch(word, labels[taken]);
                out.jump(labels[fallthrough]);
            }
        }
        Ok(())
    }
}

enum Control {
    Return,
    Jump(u64),
    Conditional(u64),
    None,
}

fn control(insn: &Insn) -> Result<Control> {
    let word = insn.word;
    ensure!(word & 0x3F00_0000 != 0x0800_0000, "exclusive/ordered accesses are unsupported");
    if word == 0xD65F_03C0 {
        return Ok(Control::Return);
    }
    if word & 0xFC00_0000 == 0x1400_0000 {
        return Ok(Control::Jump(target(word, insn.address).unwrap()));
    }
    if word & 0xFF00_0010 == 0x5400_0000
        || word & 0x7E00_0000 == 0x3400_0000
        || word & 0x7E00_0000 == 0x3600_0000
    {
        return Ok(Control::Conditional(target(word, insn.address).unwrap()));
    }
    if word & 0x1C00_0000 == 0x1400_0000
        && ![0xD503_201F, 0xD53B_4200 | (word & 31), 0xD51B_4200 | (word & 31)].contains(&word)
    {
        bail!("{:#x}: unsupported control/system instruction {word:08x}", insn.address);
    }
    ensure!(word & 0x1E00_0000 != 0x0400_0000, "sve instructions are unsupported x(");
    Ok(Control::None)
}

pub fn reachable_len(insns: &[Insn]) -> Result<usize> {
    ensure!(!insns.is_empty(), "empty function");
    let start = insns[0].address;
    let mut pending = vec![0];
    let mut visited = BTreeSet::new();
    while let Some(index) = pending.pop() {
        ensure!(index < insns.len(), "function falls past its end");
        if !visited.insert(index) {
            continue;
        }
        let insn = &insns[index];
        ensure!(insn.address == start + index as u64 * 4, "noncontiguous function");
        ensure!(!insn.data && insn.decode().is_some(), "data or invalid instruction");
        let destination = |address: u64| -> Result<usize> {
            let offset =
                address.checked_sub(start).ok_or_else(|| anyhow!("branch leaves function"))?;
            ensure!(
                offset.is_multiple_of(4) && offset / 4 < insns.len() as u64,
                "branch leaves function"
            );
            Ok((offset / 4) as usize)
        };
        match control(insn)? {
            Control::Return => {}
            Control::Jump(dst) => pending.push(destination(dst)?),
            Control::Conditional(dst) => {
                pending.push(destination(dst)?);
                pending.push(index + 1);
            }
            Control::None => pending.push(index + 1),
        }
    }
    Ok(visited.last().copied().unwrap() + 1)
}

impl<'a> Function<'a> {
    pub fn parse(insns: &'a [Insn]) -> Result<Self> {
        ensure!(!insns.is_empty(), "empty function");
        let start = insns[0].address;
        ensure!(start.is_multiple_of(4), "unaligned function");
        let end = start
            .checked_add(insns.len() as u64 * 4)
            .ok_or_else(|| anyhow!("function address overflow"))?;
        let mut leaders = BTreeSet::from([0]);
        for (i, insn) in insns.iter().enumerate() {
            ensure!(insn.address == start + i as u64 * 4, "noncontiguous function");
            ensure!(
                !insn.data && insn.decode().is_some(),
                "{:#x}: data or invalid instruction",
                insn.address
            );
            match control(insn)? {
                Control::Jump(dst) | Control::Conditional(dst) => {
                    ensure!(
                        (start..end).contains(&dst) && dst.is_multiple_of(4),
                        "{:#x}: branch leaves function ({dst:#x})",
                        insn.address
                    );
                    leaders.insert(((dst - start) / 4) as usize);
                    if i + 1 < insns.len() {
                        leaders.insert(i + 1);
                    }
                }
                Control::Return => {
                    if i + 1 < insns.len() {
                        leaders.insert(i + 1);
                    }
                }
                Control::None => {
                    if let Some(dst) = target(insn.word, insn.address) {
                        ensure!(
                            !(start..end).contains(&dst),
                            "{:#x}: pc-relative ref to function interior",
                            insn.address
                        );
                    }
                }
            }
        }
        let leaders: Vec<_> = leaders.into_iter().collect();
        let block_at = |address| leaders.binary_search(&((address - start) as usize / 4)).unwrap();
        let mut blocks = Vec::new();
        for (index, &first) in leaders.iter().enumerate() {
            let limit = leaders.get(index + 1).copied().unwrap_or(insns.len());
            let last = &insns[limit - 1];
            let mut body = first..limit - 1;
            let exit = match control(last)? {
                Control::Return => Exit::Return,
                Control::Jump(dst) => Exit::Jump(block_at(dst)),
                Control::Conditional(dst) => {
                    ensure!(limit < insns.len(), "conditional falls past function end");
                    Exit::Conditional {
                        word: last.word,
                        taken: block_at(dst),
                        fallthrough: index + 1,
                    }
                }
                Control::None => {
                    ensure!(limit < insns.len(), "function falls past its end");
                    body.end = limit;
                    Exit::Jump(index + 1)
                }
            };
            blocks.push(Block { address: insns[first].address, body, exit });
        }
        Ok(Self { insns, blocks })
    }
}
