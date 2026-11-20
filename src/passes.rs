use std::ops::Range;

use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSection};
use scene_disasm::{Listing, arm64::Insn};
use scene_passes::arm64::{Options, mba_sites, substitute, transform};

use crate::macho::{self, functions, layout::CodeLayout};

mod report;
use report::Report;

pub fn run(file: &object::File, data: &[u8], dump: bool) -> Result<Vec<u8>> {
    let layout = CodeLayout::new(file, data)?;
    let section = file.section_by_name("__text").context("missing __text section")?;
    let (offset, size) = section.file_range().context("__text has no file data")?;
    let base = section.address();
    let functions = functions::in_text(file, base, size)?;
    let dice = macho::data_in_code(file)?;
    let insns = decode(section.data()?, base, offset, &dice)?;
    if dump {
        print!("; __text @ {base:#x}\n{}", Listing::Arm64(insns.clone()));
    }
    let mut out = data.to_vec();
    let mut code = Vec::new();
    let mut entries = Vec::new();
    let mut report = Report::default();
    for function in functions {
        let candidate = &insns[function.range.clone()];
        let destination = layout.base + code.len() as u64;
        let converted = (|| -> Result<_> {
            let len = candidate.len();
            let start = candidate[0].address;
            let options =
                Options { seed: Options::default().seed ^ start as u32, ..Options::default() };
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
                match substitute_function(candidate, &layout, code.len()) {
                    Ok(patches) if !patches.entries.is_empty() => {
                        let count = patches.entries.len();
                        apply(&mut out, offset, base, patches.words);
                        code.extend_from_slice(&patches.code);
                        entries.extend_from_slice(&patches.entries);
                        report.substitutions += count;
                        report.mba_only += 1;
                        if dump {
                            eprintln!("{}: {count} mba, cff skipped: {error:#}", function.name);
                        }
                    }
                    Ok(_) => {
                        report.skip("no eligible arithmetic");
                        if dump {
                            eprintln!(
                                "{}: skipped: {error:#}; no eligible arithmetic",
                                function.name
                            );
                        }
                    }
                    Err(reason) => {
                        report.skip(reason.root_cause().to_string());
                        if dump {
                            eprintln!("{}: skipped: {reason:#}", function.name);
                        }
                    }
                }
                continue;
            }
        };
        apply(&mut out, offset, base, bridges);
        let code_size = output.insns.len() * 4;
        if dump {
            eprintln!(
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
    report.print(code.len());
    ensure!(!entries.is_empty(), "no eligible instructions to transform");
    layout.finish(&out, code, &entries)
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

fn substitute_function(insns: &[Insn], layout: &CodeLayout, used: usize) -> Result<Patches> {
    let mut patches = Patches { words: Vec::new(), entries: Vec::new(), code: Vec::new() };
    for index in mba_sites(insns)? {
        let insn = &insns[index];
        let destination = layout.base + (used + patches.code.len()) as u64;
        let Some(replacement) = substitute(insn, destination)? else { continue };
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
