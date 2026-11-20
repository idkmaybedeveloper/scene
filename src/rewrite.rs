use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};
use object::{Architecture, Object, ObjectSection, SectionKind};
use scene_disasm::Arch;

use crate::{macho, passes};

pub fn rewrite(file: &object::File, data: &[u8], dump: bool) -> Result<Vec<u8>> {
    let arch = match file.architecture() {
        Architecture::X86_64 => Arch::X64,
        Architecture::I386 => Arch::X86,
        Architecture::Aarch64 => Arch::Arm64,
        other => bail!("unsupported architecture {other:?}"),
    };

    let dice = macho::data_in_code(file)?;
    let mut out = data.to_vec();
    for section in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Some((offset, size)) = section.file_range() else { continue };
        let range = offset as usize..(offset + size) as usize;
        let base = section.address();
        let name = section.name().unwrap_or("?");

        let file_to_vaddr = |r: &Range<u64>| base + r.start - offset..base + r.end - offset;
        let data_ranges: Vec<_> = dice
            .iter()
            .filter(|r| r.start < offset + size && offset < r.end)
            .map(file_to_vaddr)
            .collect();

        let mut listing = scene_disasm::disassemble(arch, &data[range.clone()], base, &data_ranges)
            .with_context(|| format!("disassembling {name}"))?;
        if dump {
            print!("; {name} @ {base:#x}\n{listing}");
        }
        passes::run(&mut listing)?;
        let code = scene_asm::assemble(&listing, base, range.len())
            .with_context(|| format!("assembling {name}"))?;
        ensure!(code.len() == range.len());

        let changed = code.iter().zip(&data[range.clone()]).filter(|(a, b)| a != b).count();
        eprintln!(
            "{name:<16} {base:#014x} {:>8} insns {:>8} bytes, {changed} changed",
            listing.len(),
            range.len()
        );
        out[range].copy_from_slice(&code);
    }
    Ok(out)
}
