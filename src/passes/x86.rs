use std::{collections::BTreeSet, ops::Range};

use anyhow::{Context, Result, ensure};
use iced_x86::{FlowControl, Instruction, OpKind};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind};
use scene_disasm::{Listing, x86::Insn};
use scene_passes::x86::{Options, Output};

use super::report::Report;
use crate::macho::{self, functions, layout::CodeLayout};

pub fn run(file: &object::File, data: &[u8], dump: bool) -> Result<Vec<u8>> {
    let section = file.section_by_name("__text").context("missing __text section")?;
    let (offset, size) = section.file_range().context("__text has no file data")?;
    let base = section.address();
    let layout = CodeLayout::new(file, data, 0)?;
    let dice = macho::data_in_code(file)?;
    let mut targets = BTreeSet::new();
    let mut insns = Vec::new();
    let mut starts = functions::starts(file)?;
    starts.retain(|a| (base..base + size).contains(a));
    ensure!(!starts.is_empty(), "missing LC_FUNCTION_STARTS entries for __text");
    starts.sort_unstable();
    starts.dedup();
    targets.extend(starts.iter().copied());
    targets.extend(file.symbols().map(|s| s.address()));
    starts.push(base + size);
    for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Some((offset, size)) = section.file_range() else { continue };
        let address = section.address();
        let ranges: Vec<_> = dice
            .iter()
            .filter(|r| r.start < offset + size && offset < r.end)
            .map(|r| {
                address + r.start.max(offset) - offset..address + r.end.min(offset + size) - offset
            })
            .collect();
        let bytes = section.data()?;
        let decoded = if section.name()? == "__text" {
            let mut decoded = Vec::new();
            for pair in starts.windows(2) {
                let first = (pair[0] - address) as usize;
                let end = (pair[1] - address) as usize;
                decoded.extend(scene_disasm::x86::decode(64, &bytes[first..end], pair[0], &ranges));
            }
            decoded
        } else {
            scene_disasm::x86::decode(64, bytes, address, &ranges)
        };
        for insn in &decoded {
            if let Insn::Decoded(insn) = insn {
                for kind in insn.op_kinds() {
                    if kind == OpKind::NearBranch64 {
                        targets.insert(insn.near_branch_target());
                    }
                }
                if insn.is_ip_rel_memory_operand() {
                    targets.insert(insn.ip_rel_memory_address());
                }
            }
        }
        if section.name()? == "__text" {
            insns = decoded;
        }
    }
    let mut out = data.to_vec();
    let mut code = Vec::new();
    let mut entries = Vec::new();
    let mut report = Report::default();
    if dump {
        print!("; __text @ {base:#x}\n{}", Listing::X86 { bitness: 64, insns: insns.clone() });
    }
    for pair in starts.windows(2) {
        let range = pair[0]..pair[1];
        let first = insns.partition_point(|i| i.address() < range.start);
        let end = insns.partition_point(|i| i.address() < range.end);
        let candidate = &insns[first..end];
        let Some(decoded) = decode_function(candidate, &range) else {
            report.skip("data or invalid function boundary");
            continue;
        };
        let destination = layout.base + code.len() as u64;
        let converted = (|| -> Result<_> {
            let options = Options {
                seed: Options::default().seed ^ range.start as u32,
                ..Options::default()
            };
            let output = scene_passes::x86::transform(&decoded, destination, options)?;
            ensure!(layout.fits(code.len() + output.code.len()), "executable padding exhausted");
            let bridges = bridges(&decoded, &output, destination, &targets)?;
            Ok((output, bridges))
        })();
        match converted {
            Ok((output, bridges)) => {
                for bridge in bridges {
                    let at = (offset + bridge.address - base) as usize;
                    out[at..at + bridge.size].fill(0x90);
                    out[at..at + bridge.bytes.len()].copy_from_slice(&bridge.bytes);
                }
                if dump {
                    eprintln!(
                        "{:#x} -> {destination:#x}: {} blocks, {} mba, {} bytes",
                        range.start,
                        output.blocks,
                        output.substitutions,
                        output.code.len()
                    );
                }
                report.cff += 1;
                report.substitutions += output.substitutions;
                entries.push(destination);
                entries.extend(output.resumes.values().copied());
                code.extend(output.code);
                continue;
            }
            Err(error) => {
                report.cff_skip(&error);
                if dump {
                    eprintln!("{:#x}: cff skipped: {error:#}", range.start);
                }
            }
        }
        let previous = report.substitutions;
        for (index, insn) in decoded.iter().enumerate() {
            if targets.range(insn.ip() + 1..insn.next_ip()).next().is_some() {
                continue;
            }
            let destination = layout.base + code.len() as u64;
            let converted = (|| -> Result<_> {
                let Some(bytes) = scene_passes::x86::substitute(&decoded[index..], destination)?
                else {
                    return Ok(None);
                };
                ensure!(layout.fits(code.len() + bytes.len()), "executable padding exhausted");
                let bridge = scene_asm::x86::jump(insn.ip(), destination)?;
                Ok(Some((bytes, bridge)))
            })();
            match converted {
                Ok(Some((bytes, bridge))) => {
                    let at = (offset + insn.ip() - base) as usize;
                    out[at..at + insn.len()].fill(0x90);
                    out[at..at + bridge.len()].copy_from_slice(&bridge);
                    if dump {
                        eprintln!("{:#x} -> {destination:#x}: {insn}", insn.ip());
                        print!(
                            "; mba @ {destination:#x}\n{}",
                            Listing::X86 {
                                bitness: 64,
                                insns: scene_disasm::x86::decode(64, &bytes, destination, &[]),
                            }
                        );
                    }
                    entries.push(destination);
                    code.extend(bytes);
                    report.substitutions += 1;
                }
                Ok(None) => {}
                Err(error) => {
                    if dump {
                        eprintln!("{:#x}: skipped: {error:#}", insn.ip());
                    }
                }
            }
        }
        if report.substitutions != previous {
            report.mba_only += 1;
        } else {
            report.skip("no eligible arithmetic");
        }
    }
    report.print(code.len());
    ensure!(!entries.is_empty(), "no eligible x86_64 instructions to transform");
    layout.finish(&out, code, &entries)
}

struct Bridge {
    address: u64,
    size: usize,
    bytes: Vec<u8>,
}

fn bridges(
    insns: &[Instruction],
    output: &Output,
    destination: u64,
    targets: &BTreeSet<u64>,
) -> Result<Vec<Bridge>> {
    let mut sites = output.resumes.clone();
    sites.insert(output.entry_patch, destination);
    let mut bridges = Vec::new();
    let mut previous_end = 0;
    for (address, target) in sites {
        ensure!(address >= previous_end, "overlapping x86 trampolines");
        let index = insns
            .binary_search_by_key(&address, |s| s.ip())
            .map_err(|_| anyhow::anyhow!("trampoline is not on an instruction boundary"))?;
        let mut end = address;
        for insn in &insns[index..] {
            ensure!(
                !matches!(insn.flow_control(), FlowControl::Call | FlowControl::IndirectCall),
                "call overlaps x86 trampoline"
            );
            end = insn.next_ip();
            if end - address >= 5 {
                break;
            }
        }
        ensure!(end - address >= 5, "insufficient space for x86 trampoline");
        ensure!(
            targets.range(address + 1..end).next().is_none(),
            "reference into x86 trampoline interior"
        );
        bridges.push(Bridge {
            address,
            size: (end - address) as usize,
            bytes: scene_asm::x86::jump(address, target)?,
        });
        previous_end = end;
    }
    for (&address, &target) in &output.moved {
        let insn = &insns[insns.binary_search_by_key(&address, |s| s.ip()).unwrap()];
        if insn.len() < 5
            || bridges
                .iter()
                .any(|b| b.address < insn.next_ip() && address < b.address + b.size as u64)
            || targets.range(address + 1..insn.next_ip()).next().is_some()
        {
            continue;
        }
        bridges.push(Bridge {
            address,
            size: insn.len(),
            bytes: scene_asm::x86::jump(address, target)?,
        });
    }
    Ok(bridges)
}

fn decode_function(insns: &[Insn], range: &Range<u64>) -> Option<Vec<Instruction>> {
    let mut cursor = range.start;
    let mut decoded = Vec::new();
    for insn in insns {
        if insn.address() != cursor {
            return None;
        }
        cursor += insn.len() as u64;
        match insn {
            Insn::Decoded(insn) => decoded.push(*insn),
            Insn::Raw { .. } => break,
        }
    }
    (cursor <= range.end && !decoded.is_empty()).then_some(decoded)
}
