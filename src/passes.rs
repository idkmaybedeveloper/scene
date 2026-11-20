use std::ops::Range;

use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSection, SectionKind};
use scene_disasm::{Listing, arm64::Insn};
use scene_passes::arm64::{Options, reachable_len, transform};

use crate::macho::{self, functions, layout::CodeLayout};

pub fn run(file: &object::File, data: &[u8], dump: bool) -> Result<Vec<u8>> {
    let layout = CodeLayout::new(file, data)?;
    let section = file.section_by_name("__text").context("missing __text section")?;
    let (offset, size) = section.file_range().context("__text has no file data")?;
    let base = section.address();
    let functions = functions::in_text(file, base, size)?;
    let dice = macho::data_in_code(file)?;
    let insns = decode(section.data()?, base, offset, &dice)?;
    let mut references = Vec::new();
    for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Some((offset, _)) = section.file_range() else { continue };
        for insn in decode(section.data()?, section.address(), offset, &dice)? {
            if let Some(target) = insn.target {
                references.push((insn.address, target));
            }
        }
    }
    if dump {
        print!("; __text @ {base:#x}\n{}", Listing::Arm64(insns.clone()));
    }
    let mut out = data.to_vec();
    let mut code = Vec::new();
    let mut entries = Vec::new();
    let mut substitutions = 0;
    let mut skipped = 0;
    for function in functions {
        let candidate = &insns[function.range.clone()];
        let destination = layout.base + code.len() as u64;
        let converted = (|| -> Result<_> {
            let len = reachable_len(candidate)?;
            let candidate = &candidate[..len];
            let start = candidate[0].address;
            let end = start + len as u64 * 4;
            ensure!(
                !references.iter().any(|&(source, target)| target > start
                    && target < end
                    && !(start..end).contains(&source)),
                "reference to function interior"
            );
            let options =
                Options { seed: Options::default().seed ^ start as u32, ..Options::default() };
            let output = transform(candidate, destination, options)?;
            ensure!(
                layout.fits(code.len() + output.insns.len() * 4),
                "executable padding exhausted"
            );
            let jump = scene_asm::arm64::retarget(0x1400_0000, start, destination)?;
            Ok((len, output, jump))
        })();
        let (len, output, jump) = match converted {
            Ok(converted) => converted,
            Err(error) => {
                eprintln!("{}: skipped: {error:#}", function.name);
                skipped += 1;
                continue;
            }
        };
        let byte_start = offset as usize + function.range.start * 4;
        let byte_end = byte_start + len * 4;
        for word in out[byte_start..byte_end].as_chunks_mut::<4>().0 {
            *word = 0xD420_0000u32.to_le_bytes();
        }
        out[byte_start..byte_start + 4].copy_from_slice(&jump.to_le_bytes());
        let code_size = output.insns.len() * 4;
        eprintln!(
            "{}: {:#x} -> {destination:#x}, {} -> {code_size} bytes, {} blocks, {} mba",
            function.name,
            candidate[0].address,
            len * 4,
            output.blocks,
            output.substitutions
        );
        substitutions += output.substitutions;
        let listing = Listing::Arm64(output.insns);
        if dump {
            print!("; {} @ {destination:#x}\n{listing}", function.name);
        }
        code.extend_from_slice(&scene_asm::assemble(&listing, destination, code_size)?);
        entries.push(destination);
    }
    ensure!(!entries.is_empty(), "no supported arm64 leaf functions to transform");
    eprintln!(
        "{} functions transformed, {skipped} skipped, {substitutions} mba, {} code bytes",
        entries.len(),
        code.len()
    );
    layout.finish(&out, code, &entries)
}

fn decode(bytes: &[u8], base: u64, offset: u64, data: &[Range<u64>]) -> Result<Vec<Insn>> {
    scene_disasm::arm64::decode(bytes, base, |range| {
        let file_range = offset + range.start - base..offset + range.end - base;
        data.iter().any(|data| data.start < file_range.end && file_range.start < data.end)
    })
}
