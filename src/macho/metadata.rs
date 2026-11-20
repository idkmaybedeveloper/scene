use std::collections::BTreeSet;

use anyhow::{Result, anyhow};
use object::{
    build::macho::{Builder, SectionId},
    macho,
};

pub fn apply(
    builder: &mut Builder<'_>,
    starts: &mut Vec<u64>,
    entries: &[u64],
    code_end: u64,
) -> Result<()> {
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
            && executable.iter().any(|(id, _)| symbol.section == Some(*id))
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
    eprintln!("metadata: {renamed} names changed, {decoys} decoy function entries");
    Ok(())
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
    let mut bytes = vec![0; 32];
    random(&mut bytes)?;
    for byte in &mut bytes {
        *byte = b"Il1i"[*byte as usize & 3];
    }
    Ok(bytes)
}

fn random(bytes: &mut [u8]) -> Result<()> {
    getrandom::getrandom(bytes).map_err(|e| anyhow!("generating metadata: {e}"))
}
