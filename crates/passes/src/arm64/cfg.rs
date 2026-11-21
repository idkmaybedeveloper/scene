use std::{collections::BTreeSet, ops::Range};

use anyhow::{Result, anyhow, bail, ensure};
use bad64::Op;
use scene_disasm::arm64::{Insn, target};

use super::emit::{Emitter, Label};

pub struct Function<'a> {
    pub insns: &'a [Insn],
    pub blocks: Vec<Block>,
    pub entry_patch: u64,
}

pub struct Block {
    pub address: u64,
    pub body: Range<usize>,
    pub exit: Exit,
    pub exit_address: Option<u64>,
}

pub enum Exit {
    Raw(u32),
    Tail(u64),
    Jump(usize),
    Call { site: u64, next: usize, bridge: bool },
    Conditional { word: u32, taken: Destination, fallthrough: usize },
}

#[derive(Clone, Copy)]
pub enum Destination {
    Block(usize),
    Address(u64),
}

impl Exit {
    pub fn emit(&self, out: &mut Emitter, labels: &[Label]) {
        match *self {
            Self::Raw(word) => out.raw(word),
            Self::Tail(address) => out.jump_to(address),
            Self::Jump(next) => out.jump(labels[next]),
            Self::Call { site, next, bridge } => {
                out.jump_to(site);
                if bridge {
                    out.resume(site + 4);
                    out.jump(labels[next]);
                }
            }
            Self::Conditional { word, taken, fallthrough } => {
                match taken {
                    Destination::Block(next) => out.branch(word, labels[next]),
                    Destination::Address(address) => {
                        let edge = out.label();
                        out.branch(word, edge);
                        out.jump(labels[fallthrough]);
                        out.bind(edge);
                        out.jump_to(address);
                        return;
                    }
                }
                out.jump(labels[fallthrough]);
            }
        }
    }
}

enum Control {
    Stop(u32),
    Call,
    Jump(u64),
    Conditional(u64),
    None,
}

pub(super) fn is_call(op: Op) -> bool {
    matches!(op, Op::BL | Op::BLR | Op::BLRAA | Op::BLRAAZ | Op::BLRAB | Op::BLRABZ)
}

fn control(insn: &Insn) -> Result<Control> {
    let word = insn.word;
    ensure!(word & 0x3F00_0000 != 0x0800_0000, "exclusive/ordered accesses are unsupported");
    let decoded = insn.decode().ok_or_else(|| anyhow!("invalid instruction"))?;
    match decoded.op() {
        Op::RET
        | Op::RETAA
        | Op::RETAB
        | Op::BR
        | Op::BRAA
        | Op::BRAAZ
        | Op::BRAB
        | Op::BRABZ
        | Op::BRK
        | Op::HLT => return Ok(Control::Stop(word)),
        op if is_call(op) => return Ok(Control::Call),
        Op::BTI
        | Op::PACIASP
        | Op::PACIBSP
        | Op::AUTIASP
        | Op::AUTIBSP
        | Op::PACIA1716
        | Op::PACIB1716
        | Op::AUTIA1716
        | Op::AUTIB1716
        | Op::PACIAZ
        | Op::PACIBZ
        | Op::AUTIAZ
        | Op::AUTIBZ
        | Op::XPACLRI => return Ok(Control::None),
        _ => {}
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
    if word & 0xFFFF_F0FF == 0xD503_30BF || word & 0xFFFF_F0FF == 0xD503_309F || word == 0xD503_3FDF
    {
        return Ok(Control::None);
    }
    if word & 0x1C00_0000 == 0x1400_0000
        && ![0xD503_201F, 0xD53B_4200 | (word & 31), 0xD51B_4200 | (word & 31)].contains(&word)
    {
        bail!("{:#x}: unsupported control/system instruction {word:08x}", insn.address);
    }
    ensure!(word & 0x1E00_0000 != 0x0400_0000, "sve instructions are unsupported x(");
    Ok(Control::None)
}

fn reachable(insns: &[Insn], allow_unknown: bool) -> Result<BTreeSet<usize>> {
    ensure!(!insns.is_empty(), "empty function");
    let start = insns[0].address;
    let mut pending = vec![0];
    let mut visited = BTreeSet::new();
    while let Some(index) = pending.pop() {
        if allow_unknown && index >= insns.len() {
            continue;
        }
        ensure!(index < insns.len(), "function falls past its end");
        if !visited.insert(index) {
            continue;
        }
        let insn = &insns[index];
        ensure!(insn.address == start + index as u64 * 4, "noncontiguous function");
        if insn.data || insn.decode().is_none() {
            ensure!(allow_unknown, "data or invalid instruction");
            continue;
        }
        let flow = match control(insn) {
            Ok(flow) => flow,
            Err(_) if allow_unknown => {
                if insn.word & 0xFFFF_F01F == 0xD503_201F {
                    pending.push(index + 1);
                }
                continue;
            }
            Err(error) => return Err(error),
        };
        match flow {
            Control::Stop(_) => {}
            Control::Call if index + 1 == insns.len() => {}
            Control::Call | Control::None => pending.push(index + 1),
            Control::Jump(dst) | Control::Conditional(dst) => {
                if let Some(offset) = dst.checked_sub(start)
                    && offset.is_multiple_of(4)
                    && offset / 4 < insns.len() as u64
                {
                    pending.push((offset / 4) as usize);
                }
                if matches!(flow, Control::Conditional(_)) {
                    pending.push(index + 1);
                }
            }
        }
    }
    Ok(visited)
}

pub fn mba_sites(insns: &[Insn]) -> Result<Vec<usize>> {
    ensure!(
        !insns.iter().any(|i| !i.data && i.word & 0x3F00_0000 == 0x0800_0000),
        "exclusive/ordered accesses are unsupported"
    );
    Ok(reachable(insns, true)?
        .into_iter()
        .filter(|&i| !insns[i].data && insns[i].decode().is_some())
        .collect())
}

pub fn reachable_len(insns: &[Insn]) -> Result<usize> {
    Ok(reachable(insns, false)?.last().copied().unwrap() + 1)
}

impl<'a> Function<'a> {
    pub fn parse(insns: &'a [Insn], cff: u32) -> Result<Self> {
        ensure!(!insns.is_empty(), "empty function");
        let start = insns[0].address;
        ensure!(start.is_multiple_of(4), "unaligned function");
        let end = start
            .checked_add(insns.len() as u64 * 4)
            .ok_or_else(|| anyhow!("function address overflow"))?;
        let entry_patch =
            start + if insns[0].decode().is_some_and(|i| i.op() == Op::BTI) { 4 } else { 0 };
        ensure!(entry_patch < end, "missing entry instruction");
        let mut leaders = BTreeSet::from([0]);
        let internal = |dst| (start..end).contains(&dst);
        for (i, insn) in insns.iter().enumerate() {
            ensure!(insn.address == start + i as u64 * 4, "noncontiguous function");
            ensure!(
                !insn.data && insn.decode().is_some(),
                "{:#x}: data or invalid instruction",
                insn.address
            );
            match control(insn)? {
                Control::Jump(dst) | Control::Conditional(dst) => {
                    if internal(dst) {
                        ensure!(dst.is_multiple_of(4), "unaligned branch target");
                        leaders.insert(((dst - start) / 4) as usize);
                    }
                    if i + 1 < insns.len() {
                        leaders.insert(i + 1);
                    }
                }
                Control::Call => {
                    ensure!(insn.address != entry_patch, "call overlaps entry trampoline");
                    if i + 1 == insns.len() {
                        continue;
                    }
                    leaders.insert(i + 1);
                }
                Control::Stop(_) => {
                    if i + 1 < insns.len() {
                        leaders.insert(i + 1);
                    }
                }
                Control::None => {
                    if let Some(dst) = target(insn.word, insn.address) {
                        ensure!(
                            !internal(dst),
                            "{:#x}: pc-relative ref to function interior",
                            insn.address
                        );
                    }
                }
            }
        }
        split_blocks(&mut leaders, insns.len(), cff);
        let leaders: Vec<_> = leaders.into_iter().collect();
        let block_at = |address| leaders.binary_search(&((address - start) as usize / 4)).unwrap();
        let destination = |address| {
            if internal(address) {
                Destination::Block(block_at(address))
            } else {
                Destination::Address(address)
            }
        };
        let mut blocks = Vec::new();
        for (index, &first) in leaders.iter().enumerate() {
            let limit = leaders.get(index + 1).copied().unwrap_or(insns.len());
            let last = &insns[limit - 1];
            let mut body = first..limit - 1;
            let exit = match control(last)? {
                Control::Stop(word) => Exit::Raw(word),
                Control::Jump(dst) => match destination(dst) {
                    Destination::Block(next) => Exit::Jump(next),
                    Destination::Address(address) => Exit::Tail(address),
                },
                Control::Call if limit == insns.len() => Exit::Tail(last.address),
                Control::Call => Exit::Call {
                    site: last.address,
                    next: index + 1,
                    bridge: !insns[limit].decode().is_some_and(|i| is_call(i.op())),
                },
                Control::Conditional(dst) => {
                    ensure!(limit < insns.len(), "conditional falls past function end");
                    Exit::Conditional {
                        word: last.word,
                        taken: destination(dst),
                        fallthrough: index + 1,
                    }
                }
                Control::None => {
                    ensure!(limit < insns.len(), "function falls past its end");
                    body.end = limit;
                    Exit::Jump(index + 1)
                }
            };
            let exit_address = (body.end != limit).then_some(last.address);
            blocks.push(Block { address: insns[first].address, body, exit, exit_address });
        }
        Ok(Self { insns, blocks, entry_patch })
    }
}

/// subdivides straight-line runs into smaller basic blocks so the flattener produces more
/// dispatcher states. inserted leaders only ever land on interior instructions of a natural
/// block, whose predecessor is a fall-through, so each new block gets an unconditional
/// `Exit::Jump` to the next. higher `cff` means a smaller step and thus more states.
fn split_blocks(leaders: &mut BTreeSet<usize>, len: usize, cff: u32) {
    let step = match cff {
        0 | 1 => return,
        2 => 4,
        3 => 2,
        _ => 1,
    };
    let mut bounds: Vec<usize> = leaders.iter().copied().collect();
    bounds.push(len);
    for pair in bounds.windows(2) {
        let mut cut = pair[0] + step;
        while cut < pair[1] {
            leaders.insert(cut);
            cut += step;
        }
    }
}
