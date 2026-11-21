use std::ops::Range;

use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSection};
use scene_disasm::{Listing, arm64::Insn};
use scene_passes::arm64::{Options, mba_sites, substitute, transform};

use crate::config::Passes;
use crate::macho::{
    self, functions,
    layout::CodeLayout,
    strings::{Rewrite as StringRewrite, Strings},
};

mod report;
mod vm;
pub mod x86;
use report::Report;

pub fn run(
    file: &object::File,
    data: &[u8],
    dump: bool,
    passes: &Passes,
    banner: &[Vec<u8>],
    banner_into: Option<&str>,
) -> Result<Vec<u8>> {
    let section = file.section_by_name("__text").context("missing __text section")?;
    let (offset, size) = section.file_range().context("__text has no file data")?;
    let base = section.address();
    let functions = functions::in_text(file, base, size)?;
    let dice = macho::data_in_code(file)?;
    let insns = decode(section.data()?, base, offset, &dice)?;
    let mut report = Report::default();
    let vm_functions =
        vm::select(file, &insns, &functions, &dice, &passes.vm, passes.seed, &mut report)?;
    let strings = Strings::collect(file, &insns, &functions, passes.strings)?;
    let layout = CodeLayout::new(file, data, strings.storage_size())?;
    let vm_addresses = strings.vm_addresses(&layout);
    let mut virtualized = std::collections::BTreeSet::new();
    let mut moved = std::collections::BTreeMap::new();
    if dump {
        print!("; __text @ {base:#x}\n{}", Listing::Arm64(insns.clone()));
    }
    let mut out = data.to_vec();
    let mut code = Vec::new();
    let mut entries = Vec::new();
    let mut protected = Vec::new();
    let mut bindings = Vec::new();
    let hook = banner_hook(file, &functions, base, offset, size, banner_into);
    let mut main_hook: Option<(u64, u64)> = None;
    for (index, function) in functions.iter().enumerate() {
        let candidate = &insns[function.range.clone()];
        if vm_functions.contains(&index) {
            let destination = layout.base + code.len() as u64;
            let converted = (|| -> Result<_> {
                let start = candidate[0].address;
                let seed = passes.seed ^ start as u32;
                let output = scene_passes::arm64::vm::transform_with_options(
                    candidate,
                    destination,
                    scene_passes::arm64::vm::Options {
                        seed,
                        anchors: vm::anchors(&insns, seed),
                        addresses: vm_addresses
                            .range(start..start + candidate.len() as u64 * 4)
                            .map(|(&a, &b)| (a, b))
                            .collect(),
                        ..Default::default()
                    },
                )?;
                ensure!(
                    layout.fits(code.len() + output.code.len()),
                    "executable padding exhausted"
                );
                let jump =
                    scene_asm::arm64::retarget(0x1400_0000, output.entry_patch, destination)?;
                Ok((output, jump))
            })();
            match converted {
                Ok((output, jump)) => {
                    let patches = output
                        .sources
                        .iter()
                        .copied()
                        .filter(|address| !output.kept.contains(address))
                        .filter(|&address| {
                            address != candidate[0].address || address == output.entry_patch
                        })
                        .map(|address| {
                            (
                                address,
                                if address == output.entry_patch { jump } else { 0xd420_0000 },
                            )
                        })
                        .collect();
                    apply(&mut out, offset, base, patches);
                    for (&site, &resume) in &output.resumes {
                        apply(
                            &mut out,
                            offset,
                            base,
                            vec![(site, scene_asm::arm64::retarget(0x1400_0000, site, resume)?)],
                        );
                    }
                    virtualized.extend(output.sources.iter().copied());
                    entries.extend(output.resumes.values().copied());
                    if Some(candidate[0].address) == hook {
                        main_hook = Some((output.entry_patch, destination));
                    }
                    if dump {
                        log::info!(
                            "{}: vm at {destination:#x}, {} instructions, {} bytecode bytes, {} total bytes, mutant {:#x}",
                            function.name,
                            output.instructions,
                            output.bytecode.len(),
                            output.code.len(),
                            output.mutation_seed
                        );
                        print!("; vm {} @ {destination:#x}\n{output}", function.name);
                    }
                    protected.push(
                        destination + output.bytecode.start as u64
                            ..destination + output.bytecode.end as u64,
                    );
                    entries.push(destination);
                    report.vm_runtime += output.runtime_size;
                    report.vm_raw_runtime += output.raw_runtime_size;
                    report.vm_handlers += output.handlers;
                    report.vm_substitutions += output.substitutions;
                    report.vm_instructions += output.instructions;
                    report.vm_bytecode += output.bytecode.len();
                    bindings.push(vm::Pending {
                        range: code.len()..code.len() + output.code.len(),
                        binding: output.binding,
                    });
                    code.extend(output.code);
                    report.vm += 1;
                    continue;
                }
                Err(error) => {
                    report.vm_skip(&error);
                    log::warn!("{}: vm skipped: {error:#}", function.name);
                }
            }
        }
        if !passes.cff.on() && !passes.mba.on() {
            report.untouched += 1;
            continue;
        }
        let destination = layout.base + code.len() as u64;
        let converted = (|| -> Result<_> {
            let len = candidate.len();
            let start = candidate[0].address;
            let options = Options {
                mba: passes.mba.get(),
                cff: passes.cff.get(),
                seed: passes.seed ^ start as u32,
            };
            let output = transform(candidate, destination, options)?;
            ensure!(
                layout.fits(code.len() + output.insns.len() * 4),
                "executable padding exhausted"
            );
            let mut bridges = Vec::with_capacity(output.moved.len() + output.resumes.len() + 1);
            for (&address, &moved) in &output.moved {
                if !output.kept.contains(&address) {
                    bridges
                        .push((address, scene_asm::arm64::retarget(0x1400_0000, address, moved)?));
                }
            }
            for (&address, &resume) in &output.resumes {
                bridges.push((address, scene_asm::arm64::retarget(0x1400_0000, address, resume)?));
            }
            bridges.push((
                output.entry_patch,
                scene_asm::arm64::retarget(0x1400_0000, output.entry_patch, destination)?,
            ));
            Ok((len, output, bridges))
        })();
        let (len, output, bridges) = match converted {
            Ok(converted) => converted,
            Err(error) => {
                report.cff_skip(&error);
                if !passes.mba.on() {
                    if dump {
                        log::info!("{}: skipped: {error:#}", function.name);
                    }
                    continue;
                }
                match substitute_function(candidate, &layout, code.len(), passes.mba.get()) {
                    Ok(patches) if !patches.entries.is_empty() => {
                        let count = patches.entries.len();
                        apply(&mut out, offset, base, patches.words);
                        code.extend_from_slice(&patches.code);
                        entries.extend_from_slice(&patches.entries);
                        report.substitutions += count;
                        report.mba_only += 1;
                        if dump {
                            log::info!("{}: {count} mba, cff skipped: {error:#}", function.name);
                        }
                    }
                    Ok(_) => {
                        report.skip("no eligible arithmetic");
                        if dump {
                            log::info!(
                                "{}: skipped: {error:#}; no eligible arithmetic",
                                function.name
                            );
                        }
                    }
                    Err(reason) => {
                        report.skip(reason.root_cause().to_string());
                        if dump {
                            log::info!("{}: skipped: {reason:#}", function.name);
                        }
                    }
                }
                continue;
            }
        };
        apply(&mut out, offset, base, bridges);
        moved.extend(&output.moved);
        if Some(candidate[0].address) == hook {
            main_hook = Some((output.entry_patch, destination));
        }
        let code_size = output.insns.len() * 4;
        if dump {
            log::info!(
                "{}: {:#x} -> {destination:#x}, {} -> {code_size} bytes, {} blocks, {} mba",
                function.name,
                candidate[0].address,
                len * 4,
                output.blocks,
                output.substitutions
            );
        }
        report.substitutions += output.substitutions;
        let listing = Listing::Arm64(output.insns);
        if dump {
            print!("; {} @ {destination:#x}\n{listing}", function.name);
        }
        code.extend_from_slice(&scene_asm::assemble(&listing, destination, code_size)?);
        entries.push(destination);
        report.cff += 1;
    }
    strings.apply(StringRewrite {
        file,
        out: &mut out,
        code: &mut code,
        layout: &layout,
        moved: &moved,
        insns: &insns,
        functions: &functions,
        entries: &mut entries,
        virtualized: &virtualized,
    })?;
    if !banner.is_empty() {
        let destination = layout.base + code.len() as u64;
        let main = main_hook.map(|(entry, destination)| {
            let at = (offset + entry - base) as usize;
            let word = u32::from_le_bytes(out[at..at + 4].try_into().unwrap());
            scene_disasm::arm64::target(word, entry).unwrap_or(destination)
        });
        let emitted = scene_passes::arm64::banner::emit(destination, banner, main)?;
        ensure!(layout.fits(code.len() + emitted.code.len()), "banner exceeds executable space");
        protected.push(destination..destination + emitted.code.len() as u64);
        code.extend_from_slice(&emitted.code);
        entries.extend_from_slice(&emitted.entries);
        match main_hook {
            Some((entry_patch, _)) => {
                let shim = scene_asm::arm64::retarget(0x1400_0000, entry_patch, destination)?;
                apply(&mut out, offset, base, vec![(entry_patch, shim)]);
                log::info!("banner: {} lines woven into main at {destination:#x}", banner.len());
            }
            None => log::info!("banner: {} lines embedded at {destination:#x}", banner.len()),
        }
    }
    vm::seal(&mut code, bindings, &out, offset, base)?;
    report.print(code.len());
    ensure!(!entries.is_empty(), "no eligible instructions to transform");
    layout.finish(&out, code, &entries, &protected)
}

/// address of the function the banner should be woven into: the named symbol when given,
/// otherwise the binary's entry point (if it lands in __text). none disables weaving
fn banner_hook(
    file: &object::File,
    functions: &[functions::Function],
    base: u64,
    offset: u64,
    size: u64,
    into: Option<&str>,
) -> Option<u64> {
    match into {
        Some(name) => {
            functions.iter().find(|f| f.name == name).map(|f| base + f.range.start as u64 * 4)
        }
        None => {
            // LC_MAIN's entryoff is a file offset; map it back to a __text virtual address
            let entry = base + file.entry().checked_sub(offset)?;
            (base..base + size).contains(&entry).then_some(entry)
        }
    }
}

fn apply(out: &mut [u8], offset: u64, base: u64, words: Vec<(u64, u32)>) {
    for (address, word) in words {
        let at = (offset + address - base) as usize;
        out[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
}

struct Patches {
    words: Vec<(u64, u32)>,
    entries: Vec<u64>,
    code: Vec<u8>,
}

fn substitute_function(
    insns: &[Insn],
    layout: &CodeLayout,
    used: usize,
    depth: u32,
) -> Result<Patches> {
    let mut patches = Patches { words: Vec::new(), entries: Vec::new(), code: Vec::new() };
    for index in mba_sites(insns)? {
        let insn = &insns[index];
        let destination = layout.base + (used + patches.code.len()) as u64;
        let Some(replacement) = substitute(insn, destination, depth)? else { continue };
        let size = replacement.len() * 4;
        ensure!(layout.fits(used + patches.code.len() + size), "executable padding exhausted");
        let jump = scene_asm::arm64::retarget(0x1400_0000, insn.address, destination)?;
        patches.code.extend_from_slice(&scene_asm::assemble(
            &Listing::Arm64(replacement),
            destination,
            size,
        )?);
        patches.words.push((insn.address, jump));
        patches.entries.push(destination);
    }
    Ok(patches)
}

fn decode(bytes: &[u8], base: u64, offset: u64, data: &[Range<u64>]) -> Result<Vec<Insn>> {
    scene_disasm::arm64::decode(bytes, base, |range| {
        let file_range = offset + range.start - base..offset + range.end - base;
        data.iter().any(|data| data.start < file_range.end && file_range.start < data.end)
    })
}
