use std::collections::BTreeSet;
use std::ops::Range;

use anyhow::{Result, anyhow};
use object::{
    build::macho::{Builder, LoadCommand, SectionId},
    macho,
};

pub fn apply(
    builder: &mut Builder<'_>,
    starts: &mut Vec<u64>,
    entries: &[u64],
    code_end: u64,
    protected: &[Range<u64>],
) -> Result<()> {
    compact_header(builder);
    let debug: Vec<_> = builder
        .sections
        .iter()
        .filter(|s| is_debug_section(s.segname(), s.sectname(), s.flags))
        .map(|s| s.id())
        .collect();
    let mut removed = 0;
    for symbol in &mut builder.symbols {
        if !symbol.delete
            && (symbol.n_type.is_stab() || symbol.section.is_some_and(|s| debug.contains(&s)))
        {
            symbol.delete = true;
            removed += 1;
        }
    }
    for section in &mut builder.sections {
        if debug.contains(&section.id()) {
            section.delete = true;
        }
    }
    for segment in &mut builder.segments {
        segment.sections.retain(|s| !debug.contains(s));
        if segment.segname() == b"__DWARF" && segment.sections.is_empty() {
            /* object 0.41 uses original segment IDs as indices into the compact
             * output table, so deleting a segment makes later IDs invalid.
             * Keep an empty descriptor to preserve those IDs while dropping
             * all debug payload and its mapping from the rebuilt image.
             */
            segment.segname = [0; 16];
            segment.segname[..12].copy_from_slice(b"__SCENE_META");
            segment.vmsize = 0;
            segment.maxprot = macho::VM_PROT_READ;
            segment.initprot = macho::VM_PROT_READ;
        }
    }
    builder
        .commands
        .retain(|c| !matches!(c, LoadCommand::Other { cmd, .. } if *cmd == macho::LC_SYMSEG));
    let executable: Vec<_> = builder
        .sections
        .iter()
        .filter(|s| {
            !s.delete && s.flags & macho::S_ATTR_SOME_INSTRUCTIONS != macho::SectionFlags(0)
        })
        .map(|s| (s.id(), s.addr..s.addr + s.data.size() as u64))
        .collect();
    let mut renamed = 0;
    for symbol in &mut builder.symbols {
        if !symbol.delete
            && !symbol.is_extdef()
            && !symbol.n_type.is_stab()
            && symbol.n_type.typ() == macho::N_SECT
        {
            symbol.name = name()?.into();
            renamed += 1;
        }
    }

    // ref: https://www.romainthomas.fr/publication/22-pst-the-poor-mans-obfuscator/whitepaper.pdf
    let mut entries = entries.to_vec();
    entries.sort_unstable();
    entries.dedup();
    let step = entries.len().div_ceil(2048).max(1);
    entries.push(code_end);
    let mut occupied: BTreeSet<_> = starts.iter().copied().collect();
    let mut decoys = 0;
    for pair in entries.windows(2).step_by(step) {
        if pair[1] - pair[0] < 32 {
            continue;
        }
        let mut choices = [0; 2];
        random(&mut choices)?;
        for choice in choices {
            let address = pair[0] + 4 * (1 + choice as u64 % 5);
            if protected.iter().any(|range| range.contains(&address)) {
                continue;
            }
            if !occupied.insert(address) {
                continue;
            }
            starts.push(address);
            if let Some(&(section, _)) = executable.iter().find(|(_, r)| r.contains(&address)) {
                add_symbol(builder, section, address)?;
            }
            decoys += 1;
        }
    }
    log::info!(
        "metadata: {removed} debug symbols and {} debug sections removed; {renamed} local names replaced, {decoys} decoy function entries",
        debug.len()
    );
    Ok(())
}

pub fn header_savings(data: &[u8]) -> Result<(usize, usize)> {
    let builder = Builder::read(data)?;
    let saved = builder
        .commands
        .iter()
        .map(|command| match command {
            LoadCommand::Other { cmd, data } if *cmd == macho::LC_SOURCE_VERSION => data.len() + 8,
            LoadCommand::LinkeditData { cmd, data }
                if *cmd == macho::LC_DATA_IN_CODE && data.is_empty() =>
            {
                16
            }
            LoadCommand::BuildVersion(version) => version.tools.len() * 8,
            _ => 0,
        })
        .sum();
    let signature = builder.commands.iter().any(|command| matches!(command, LoadCommand::LinkeditData { cmd, .. } if *cmd == macho::LC_CODE_SIGNATURE));
    Ok((saved, if signature { 0 } else { 16 }))
}

fn compact_header(builder: &mut Builder<'_>) {
    builder.commands.retain(|command| !matches!(command,
        LoadCommand::Other { cmd, .. } if *cmd == macho::LC_SOURCE_VERSION)
        && !matches!(command, LoadCommand::LinkeditData { cmd, data } if *cmd == macho::LC_DATA_IN_CODE && data.is_empty()));
    for command in &mut builder.commands {
        if let LoadCommand::BuildVersion(version) = command {
            version.tools.clear();
        }
    }
}

pub fn is_debug_section(segment: &[u8], name: &[u8], flags: macho::SectionFlags) -> bool {
    segment == b"__DWARF"
        || flags & macho::S_ATTR_DEBUG != macho::SectionFlags(0)
        || name.starts_with(b"__debug_")
        || name.starts_with(b"__zdebug_")
}

fn add_symbol(builder: &mut Builder<'_>, section: SectionId, address: u64) -> Result<()> {
    let symbol = builder.symbols.add();
    symbol.name = name()?.into();
    symbol.section = Some(section);
    symbol.n_type = macho::N_SECT.into();
    symbol.n_value = address;
    Ok(())
}

fn name() -> Result<Vec<u8>> {
    let mut bytes = vec![0; 128];
    random(&mut bytes)?;
    for byte in &mut bytes {
        *byte = b"li"[*byte as usize & 1];
    }
    Ok(bytes)
}

fn random(bytes: &mut [u8]) -> Result<()> {
    getrandom::getrandom(bytes).map_err(|e| anyhow!("generating metadata: {e}"))
}
