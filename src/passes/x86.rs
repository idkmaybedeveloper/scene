use std::{collections::BTreeSet, ops::Range};

use anyhow::{Context, Result, ensure};
use iced_x86::{Instruction, OpKind};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind};
use scene_disasm::{Listing, x86::Insn};

use crate::macho::{self, functions, layout::CodeLayout};

pub fn run(file: &object::File, data: &[u8], dump: bool) -> Result<Vec<u8>> {
    let section = file.section_by_name("__text").context("missing __text section")?;
    let (offset, size) = section.file_range().context("__text has no file data")?;
    let base = section.address();
    let dice = macho::data_in_code(file)?;
    let mut targets = BTreeSet::new();
    let mut insns = Vec::new();
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
        let decoded = scene_disasm::x86::decode(64, section.data()?, address, &ranges);
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
    let mut starts = functions::starts(file)?;
    starts.retain(|a| (base..base + size).contains(a));
    ensure!(!starts.is_empty(), "missing LC_FUNCTION_STARTS entries for __text");
    targets.extend(starts.iter().copied());
    targets.extend(file.symbols().map(|s| s.address()));
    starts.sort_unstable();
    starts.dedup();
    starts.push(base + size);
    let layout = CodeLayout::new(file, data, 0)?;
    let mut out = data.to_vec();
    let mut code = Vec::new();
    let mut entries = Vec::new();
    let mut substitutions = 0;
    let mut transformed = 0;
    let mut rejected = 0;
    if dump {
        print!("; __text @ {base:#x}\n{}", Listing::X86 { bitness: 64, insns: insns.clone() });
    }
    for pair in starts.windows(2) {
        let range = pair[0]..pair[1];
        let first = insns.partition_point(|i| i.address() < range.start);
        let end = insns.partition_point(|i| i.address() < range.end);
        let candidate = &insns[first..end];
        let Some(decoded) = decode_function(candidate, &range) else {
            rejected += 1;
            continue;
        };
        let previous = substitutions;
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
                    substitutions += 1;
                }
                Ok(None) => {}
                Err(error) => {
                    rejected += 1;
                    if dump {
                        eprintln!("{:#x}: skipped: {error:#}", insn.ip());
                    }
                }
            }
        }
        transformed += usize::from(substitutions != previous);
    }
    eprintln!(
        "x86_64 mba: {substitutions} substitutions in {transformed} functions; \
         {rejected} rejected candidates; generated: {} bytes",
        code.len()
    );
    ensure!(!entries.is_empty(), "no eligible x86_64 instructions to transform");
    layout.finish(&out, code, &entries)
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
