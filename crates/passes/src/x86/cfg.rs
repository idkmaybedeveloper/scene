use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use anyhow::{Result, bail, ensure};
use iced_x86::{FlowControl, Instruction, Mnemonic};

pub struct Function<'a> {
    pub insns: &'a [Instruction],
    pub blocks: Vec<Block>,
    pub entry_patch: u64,
    pub tables: BTreeMap<u64, Vec<u64>>,
}

pub struct Block {
    pub body: Range<usize>,
    pub exit: Exit,
    pub exit_address: Option<u64>,
}

pub enum Exit {
    Stop(Instruction),
    Tail(u64),
    Jump(usize),
    Call { site: u64, next: Option<usize>, resume: u64 },
    Indirect { insn: Instruction, targets: Vec<(u64, usize)> },
    Conditional { insn: Instruction, taken: Destination, fallthrough: usize },
}

pub enum Destination {
    Block(usize),
    Address(u64),
}

impl<'a> Function<'a> {
    pub fn parse(insns: &'a [Instruction], tables: &BTreeMap<u64, Vec<u64>>) -> Result<Self> {
        ensure!(!insns.is_empty(), "empty function");
        let start = insns[0].ip();
        let end = insns.last().unwrap().next_ip();
        let indices: BTreeMap<_, _> = insns.iter().enumerate().map(|(i, s)| (s.ip(), i)).collect();
        ensure!(insns.windows(2).all(|p| p[0].next_ip() == p[1].ip()), "noncontiguous function");
        let internal = |address| (start..end).contains(&address);
        let target = |address| -> Result<Option<usize>> {
            if !internal(address) {
                return Ok(None);
            }
            Ok(Some(
                *indices
                    .get(&address)
                    .ok_or_else(|| anyhow::anyhow!("branch into instruction interior"))?,
            ))
        };
        let mut pending = vec![0];
        let mut reachable = BTreeSet::new();
        let mut leaders = BTreeSet::from([0]);
        while let Some(i) = pending.pop() {
            ensure!(i < insns.len(), "function falls past its end");
            if !reachable.insert(i) {
                continue;
            }
            let insn = &insns[i];
            if insn.is_ip_rel_memory_operand() {
                let address = insn.ip_rel_memory_address();
                ensure!(
                    address == start || !internal(address),
                    "pc-relative reference to function interior"
                );
            }
            match insn.flow_control() {
                FlowControl::Next if i + 1 < insns.len() => pending.push(i + 1),
                FlowControl::Next => {}
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                    ensure!(
                        insn.flow_control() == FlowControl::ConditionalBranch
                            || insn.is_jmp_short_or_near(),
                        "unsupported far branch"
                    );
                    if let Some(next) = target(insn.near_branch_target())? {
                        pending.push(next);
                        leaders.insert(next);
                    }
                    if insn.flow_control() == FlowControl::ConditionalBranch {
                        pending.push(i + 1);
                        leaders.insert(i + 1);
                    }
                }
                FlowControl::Call | FlowControl::IndirectCall => {
                    ensure!(
                        insn.is_call_near() || insn.is_call_near_indirect(),
                        "unsupported call instruction"
                    );
                    ensure!(
                        !insn.is_call_near()
                            || insn.near_branch_target() == start
                            || !internal(insn.near_branch_target()),
                        "call to function interior"
                    );
                    if i + 1 < insns.len() {
                        pending.push(i + 1);
                        leaders.insert(i + 1);
                    }
                }
                FlowControl::Return | FlowControl::Exception => {}
                FlowControl::IndirectBranch => {
                    let destinations = tables
                        .get(&insn.ip())
                        .ok_or_else(|| anyhow::anyhow!("unresolved indirect branch"))?;
                    for &address in destinations {
                        let next = target(address)?
                            .ok_or_else(|| anyhow::anyhow!("jump table leaves function"))?;
                        leaders.insert(next);
                        pending.push(next);
                    }
                }
                _ => bail!("unsupported control/system instruction"),
            }
        }
        let mut previous = None;
        for &i in &reachable {
            if previous.is_none_or(|p| p + 1 != i) {
                leaders.insert(i);
            }
            previous = Some(i);
        }
        if leaders.len() == 1 && reachable.len() > 3 {
            leaders.insert(*reachable.iter().nth(reachable.len() / 2).unwrap());
        }
        let leaders: Vec<_> = leaders.into_iter().filter(|i| reachable.contains(i)).collect();
        ensure!(leaders.len() <= 128, "too many blocks for x86 dispatcher");
        let block_at = |address| -> usize { leaders.binary_search(&indices[&address]).unwrap() };
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
            let last_index = *reachable.range(first..limit).next_back().unwrap();
            let last = insns[last_index];
            let mut body = first..last_index;
            let next = || -> Result<usize> {
                ensure!(
                    index + 1 < leaders.len() && leaders[index + 1] == last_index + 1,
                    "missing fallthrough block"
                );
                Ok(index + 1)
            };
            let exit = match last.flow_control() {
                FlowControl::Return | FlowControl::Exception => Exit::Stop(last),
                FlowControl::UnconditionalBranch => match destination(last.near_branch_target()) {
                    Destination::Block(index) => Exit::Jump(index),
                    Destination::Address(address) => Exit::Tail(address),
                },
                FlowControl::ConditionalBranch => Exit::Conditional {
                    insn: last,
                    taken: destination(last.near_branch_target()),
                    fallthrough: next()?,
                },
                FlowControl::Call | FlowControl::IndirectCall => Exit::Call {
                    site: last.ip(),
                    next: if last_index + 1 == insns.len() { None } else { Some(next()?) },
                    resume: last.next_ip(),
                },
                FlowControl::IndirectBranch => Exit::Indirect {
                    insn: last,
                    targets: tables[&last.ip()]
                        .iter()
                        .map(|&address| (address, block_at(address)))
                        .collect(),
                },
                FlowControl::Next => {
                    body.end += 1;
                    if last_index + 1 == insns.len() {
                        Exit::Tail(last.next_ip())
                    } else {
                        Exit::Jump(next()?)
                    }
                }
                _ => unreachable!(),
            };
            let exit_address =
                (body.end == last_index && !matches!(exit, Exit::Call { .. })).then_some(last.ip());
            blocks.push(Block { body, exit, exit_address });
        }
        let entry_patch =
            if insns[0].mnemonic() == Mnemonic::Endbr64 { insns[0].next_ip() } else { start };
        Ok(Self { insns, blocks, entry_patch, tables: tables.clone() })
    }
}
