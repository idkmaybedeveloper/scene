use std::{collections::BTreeMap, ops::Range};

use anyhow::{Result, ensure};
use object::{Object, ObjectSegment, ObjectSymbol, macho, read::macho::LoadCommandVariant};

pub struct Function {
    pub name: String,
    pub range: Range<usize>,
}

pub fn starts(file: &object::File) -> Result<Vec<u64>> {
    let object::File::MachO64(image) = file else { return Ok(Vec::new()) };
    let endian = image.endian();
    let text = file.segments().find(|s| s.name().ok().flatten() == Some("__TEXT"));
    let Some(text) = text else { return Ok(Vec::new()) };
    let mut commands = image.macho_load_commands()?;
    while let Some(command) = commands.next()? {
        let LoadCommandVariant::LinkeditData(data) = command.variant()? else { continue };
        if data.cmd.get(endian) == macho::LC_FUNCTION_STARTS {
            return Ok(data
                .function_starts(endian, image.data(), text.address())?
                .collect::<object::read::Result<_>>()?);
        }
    }
    Ok(Vec::new())
}

pub fn in_text(file: &object::File, base: u64, size: u64) -> Result<Vec<Function>> {
    let mut starts: Vec<_> =
        starts(file)?.into_iter().filter(|a| (base..base + size).contains(a)).collect();
    ensure!(!starts.is_empty(), "missing LC_FUNCTION_STARTS entries for __text");
    starts.sort_unstable();
    starts.dedup();
    starts.push(base + size);
    let names: BTreeMap<_, _> =
        file.symbols().filter_map(|s| Some((s.address(), s.name().ok()?.to_owned()))).collect();
    starts
        .windows(2)
        .map(|pair| {
            let [start, end] = [pair[0], pair[1]];
            ensure!(
                start.is_multiple_of(4) && end.is_multiple_of(4),
                "unaligned function boundary"
            );
            let name = names.get(&start).cloned().unwrap_or_else(|| format!("{start:#x}"));
            Ok(Function { name, range: ((start - base) / 4) as usize..((end - base) / 4) as usize })
        })
        .collect()
}
