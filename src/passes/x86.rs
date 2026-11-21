use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use anyhow::{Context, Result, ensure};
use iced_x86::{FlowControl, Instruction, OpKind};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SectionKind};
use scene_disasm::{Listing, x86::Insn};
use scene_passes::x86::unwind as frames;
use scene_passes::x86::{Options, Output};

use super::report::Report;
use super::vm::Pending;
use super::x86_vm;
use crate::config::Passes;
use crate::macho::{
    self, functions,
    layout::CodeLayout,
    strings::x86::{Rewrite as StringRewrite, Strings},
    unwind::Unwind,
};

pub fn run(
    file: &object::File,
    data: &[u8],
    dump: bool,
    passes: &Passes,
    banner: &[Vec<u8>],
    banner_into: Option<&str>,
) -> Result<Vec<u8>> {
    ensure!(
        !file.segments().any(|s| s.name().ok().flatten() == Some("__SCENE")),
        "binary already contains scene"
    );
    let section = file.section_by_name("__text").context("missing __text section")?;
    let (offset, size) = section.file_range().context("__text has no file data")?;
    let base = section.address();
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
    targets.extend(macho::exceptions::landing_pads(file)?);
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
    let mut source_rows = BTreeMap::new();
    let mut source_after = BTreeMap::new();
    let mut tables = BTreeMap::new();
    for pair in starts.windows(2) {
        let first = insns.partition_point(|i| i.address() < pair[0]);
        let end = insns.partition_point(|i| i.address() < pair[1]);
        if let Some(decoded) = decode_function(&insns[first..end], &(pair[0]..pair[1]))
            && let Ok(known) = macho::jump_tables::collect(file, &decoded)
        {
            if let Ok(frames) = frames::analyze(&decoded, &known) {
                source_rows.extend(frames.rows);
                source_after.extend(frames.after);
            }
            targets.extend(known.values().flatten().copied());
            tables.extend(known);
        }
    }
    let strings = Strings::collect(file, &insns, &targets, &source_rows, passes.strings)?;
    let mut unwind = Unwind::new(file)?;
    let layout = CodeLayout::with_metadata(
        file,
        data,
        strings.storage_size(),
        unwind.header_size(),
        unwind.code_limit(),
    )?;
    if layout.in_text_padding() {
        // code and eh_frame share the __text padding; reserve the strings budget up front
        unwind.reserve(strings.unwind_budget(), strings.code_budget())?;
        unwind.share_code(layout.base);
    } else {
        // generated code lives in __SCENE; put the eh_frame there too, free of the padding limit
        unwind.segment();
    }
    let mut moved = BTreeMap::new();
    let mut out = data.to_vec();
    let mut code = Vec::new();
    let mut entries = Vec::new();
    let mut report = Report::default();
    let hook = match banner_into {
        Some(name) => file.symbols().find(|s| s.name().ok() == Some(name)).map(|s| s.address()),
        None => file
            .entry()
            .checked_sub(offset)
            .map(|d| base + d)
            .filter(|a| (base..base + size).contains(a)),
    };
    let mut main_hook: Option<(u64, u64)> = None;
    let vm_functions = x86_vm::select(file, &insns, &starts, &passes.vm, passes.seed, &mut report)?;
    let vm_addresses = strings.vm_addresses(&layout);
    let mut virtualized = BTreeSet::new();
    let mut vm_entries = BTreeMap::new();
    let mut bindings = Vec::new();
    let mut protected = Vec::new();
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
        if vm_functions.contains(&range.start) {
            let destination = layout.base + code.len() as u64;
            let converted = (|| -> Result<_> {
                let seed = passes.seed ^ range.start as u32;
                let output = scene_passes::x86::vm::transform(
                    &decoded,
                    destination,
                    scene_passes::x86::vm::Options {
                        seed,
                        anchors: x86_vm::anchors(&insns, seed),
                        addresses: vm_addresses
                            .range(range.clone())
                            .map(|(&a, &b)| (a, b))
                            .collect(),
                        // exact pushfq-window unwind is affordable once eh_frame lives in __SCENE
                        precise: !layout.in_text_padding(),
                        ..Default::default()
                    },
                )?;
                ensure!(
                    layout.fits(code.len() + output.code.len()),
                    "executable padding exhausted"
                );
                unwind.add(destination, output.code.len(), &output.unwind)?;
                Ok(output)
            })();
            match converted {
                Ok(output) => {
                    // obliterate the original reachable instructions; the entry gets its jump
                    // to the vm code installed later (through strings, or directly when there
                    // are no encrypted strings)
                    let lengths: BTreeMap<_, _> =
                        decoded.iter().map(|i| (i.ip(), i.len())).collect();
                    for &source in &output.sources {
                        if let Some(&len) = lengths.get(&source) {
                            let at = (offset + source - base) as usize;
                            out[at..at + len].fill(0xcc);
                        }
                    }
                    virtualized.extend(output.sources.iter().copied());
                    vm_entries.insert(output.entry_patch, destination);
                    if dump {
                        log::info!(
                            "{:#x} -> {destination:#x}: vm, {} instructions, {} bytecode bytes, {} bytes",
                            range.start,
                            output.instructions,
                            output.bytecode.len(),
                            output.code.len()
                        );
                    }
                    protected.push(
                        destination + output.bytecode.start as u64
                            ..destination + output.bytecode.end as u64,
                    );
                    entries.push(destination);
                    report.vm += 1;
                    report.vm_instructions += output.instructions;
                    report.vm_bytecode += output.bytecode.len();
                    report.vm_handlers += output.handlers;
                    bindings.push(Pending {
                        range: code.len()..code.len() + output.code.len(),
                        binding: output.binding,
                    });
                    code.extend(output.code);
                    continue;
                }
                Err(error) => {
                    report.vm_skip(&error);
                    log::warn!("{:#x}: vm skipped: {error:#}", range.start);
                }
            }
        }
        if !passes.cff.on() && !passes.mba.on() {
            report.untouched += 1;
            continue;
        }
        if passes.cff.on() {
            let destination = layout.base + code.len() as u64;
            let converted = (|| -> Result<_> {
                let options = Options {
                    mba: passes.mba.get(),
                    cff: passes.cff.get(),
                    seed: passes.seed ^ range.start as u32,
                };
                let output = scene_passes::x86::transform_with_tables(
                    &decoded,
                    destination,
                    options,
                    &tables,
                )?;
                ensure!(
                    layout.fits(code.len() + output.code.len()),
                    "executable padding exhausted"
                );
                let bridges = bridges(&decoded, &output, destination, &targets)?;
                unwind.add(destination, output.code.len(), &output.unwind)?;
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
                        log::info!(
                            "{:#x} -> {destination:#x}: {} blocks, {} mba, {} bytes",
                            range.start,
                            output.blocks,
                            output.substitutions,
                            output.code.len()
                        );
                    }
                    report.cff += 1;
                    report.substitutions += output.substitutions;
                    if Some(range.start) == hook {
                        main_hook = Some((output.entry_patch, destination));
                    }
                    entries.push(destination);
                    entries.extend(output.resumes.values().copied());
                    moved.extend(output.moved);
                    code.extend(output.code);
                    continue;
                }
                Err(error) => {
                    report.cff_skip(&error);
                    if dump {
                        log::info!("{:#x}: cff skipped: {error:#}", range.start);
                    }
                }
            }
        }
        if !passes.mba.on() {
            report.skip("no eligible arithmetic");
            continue;
        }
        let previous = report.substitutions;
        for (index, insn) in decoded.iter().enumerate() {
            if targets.range(insn.ip() + 1..insn.next_ip()).next().is_some() {
                continue;
            }
            let destination = layout.base + code.len() as u64;
            let converted = (|| -> Result<_> {
                let Some(bytes) = scene_passes::x86::substitute(
                    &decoded[index..],
                    destination,
                    passes.mba.get(),
                )?
                else {
                    return Ok(None);
                };
                ensure!(layout.fits(code.len() + bytes.len()), "executable padding exhausted");
                let bridge = scene_asm::x86::jump(insn.ip(), destination)?;
                let row = source_rows.get(&insn.ip()).context("missing source unwind row")?;
                unwind.add(destination, bytes.len(), &[(destination, row.clone())])?;
                Ok(Some((bytes, bridge)))
            })();
            match converted {
                Ok(Some((bytes, bridge))) => {
                    let at = (offset + insn.ip() - base) as usize;
                    out[at..at + insn.len()].fill(0x90);
                    out[at..at + bridge.len()].copy_from_slice(&bridge);
                    if dump {
                        log::info!("{:#x} -> {destination:#x}: {insn}", insn.ip());
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
                        log::info!("{:#x}: skipped: {error:#}", insn.ip());
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
    unwind.release();
    let strings_encrypt = strings.storage_size() != 0;
    strings.apply(StringRewrite {
        file,
        out: &mut out,
        code: &mut code,
        layout: &layout,
        moved: &moved,
        entries: &mut entries,
        unwind: &mut unwind,
        rows: &source_rows,
        after: &source_after,
        virtualized: &virtualized,
        vm_entries: &vm_entries,
    })?;
    // strings.apply installs the guarded vm entry jumps only when it actually encrypts
    // something; with nothing to encrypt it bails early, so patch those entries directly here
    if !strings_encrypt {
        for (&entry, &destination) in &vm_entries {
            let jump = scene_asm::x86::jump(entry, destination)?;
            let at = (offset + entry - base) as usize;
            out[at..at + jump.len()].copy_from_slice(&jump);
        }
    }
    if !banner.is_empty() {
        let destination = layout.base + code.len() as u64;
        let main = main_hook.map(|(_, dest)| dest);
        let embedded = scene_passes::x86::banner::emit(destination, banner, main)?;
        ensure!(layout.fits(code.len() + embedded.code.len()), "banner exceeds executable space");
        protected.push(destination..destination + embedded.code.len() as u64);
        code.extend(embedded.code);
        entries.extend_from_slice(&embedded.entries);
        match main_hook {
            Some((entry_patch, _)) => {
                let at = (offset + entry_patch - base) as usize;
                let shim = scene_asm::x86::jump(entry_patch, destination)?;
                out[at..at + shim.len()].copy_from_slice(&shim);
                log::info!("banner: {} lines woven into main at {destination:#x}", banner.len());
            }
            None => log::info!("banner: {} lines embedded at {destination:#x}", banner.len()),
        }
    }
    super::vm::seal(&mut code, bindings, &out, offset, base)?;
    report.print(code.len());
    ensure!(!entries.is_empty(), "no eligible x86_64 instructions to transform");
    // in __SCENE mode the eh_frame trails the code at an 8-aligned address; hand that address to
    // finish so the pc-relative fdes are relocated to it, and to finish_with_unwind to place it
    let eh_frame = unwind.is_segmented().then(|| (layout.base + code.len() as u64 + 7) & !7);
    let unwind = unwind.finish(eh_frame);
    layout.finish_with_unwind(&out, code, &entries, Some(unwind), &protected)
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
