use std::{collections::BTreeMap, ops::Range};

use anyhow::{Context, Result, ensure};
use object::{
    Object, ObjectSection, ObjectSegment, ObjectSymbol, SymbolKind, macho,
    read::macho::{Fixup, LoadCommandVariant},
};

pub struct Pointer {
    pub offset: usize,
    pub target: u64,
    pub protected: bool,
    mask: u64,
    subtract: u64,
}

impl Pointer {
    pub fn write(&self, data: &mut [u8], target: u64) -> Result<()> {
        let value = target.checked_sub(self.subtract).context("pointer target below image")?;
        ensure!(value & !self.mask == 0, "string pointer exceeds fixup range");
        let bytes = data.get_mut(self.offset..self.offset + 8).context("invalid string pointer")?;
        let original = u64::from_le_bytes(bytes.try_into()?);
        bytes.copy_from_slice(&(original & !self.mask | value).to_le_bytes());
        Ok(())
    }
}

pub fn collect(file: &object::File, strings: &Range<u64>) -> Result<Vec<Pointer>> {
    let mut pointers = BTreeMap::new();
    let exports: Vec<_> = file.exports()?.collect::<object::read::Result<Vec<_>>>()?;
    let symbols: Vec<_> = file.symbols().filter(|s| s.kind() == SymbolKind::Data).collect();
    let exposed: Vec<_> = symbols
        .iter()
        .filter(|s| exports.iter().any(|e| matches!(e.target(), object::ExportTarget::Address { address } if address == s.address())))
        .map(|s| {
            let end = symbols
                .iter()
                .filter(|next| {
                    next.section_index() == s.section_index() && next.address() > s.address()
                })
                .map(|s| s.address())
                .min()
                .unwrap_or(s.address() + s.size().max(8));
            s.address()..end
        })
        .collect();
    let protected = |address| {
        exposed.iter().any(|r| r.contains(&address))
            || file.sections().any(|s| {
                let name = s.name().unwrap_or("");
                (name.starts_with("__objc") || name.starts_with("__swift") || name == "__cfstring")
                    && (s.address()..s.address() + s.size()).contains(&address)
            })
    };
    for section in file.sections() {
        if section.name().ok() == Some("__cstring") {
            continue;
        }
        let Some((offset, _)) = section.file_range() else { continue };
        let bytes = section.data()?;
        for (index, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
            let target = u64::from_le_bytes(*chunk);
            if strings.contains(&target) {
                let address = section.address() + index as u64 * 8;
                let offset = offset as usize + index * 8;
                pointers.insert(
                    offset,
                    Pointer {
                        offset,
                        target,
                        protected: protected(address),
                        mask: u64::MAX,
                        subtract: 0,
                    },
                );
            }
        }
    }
    let object::File::MachO64(image) = file else { return Ok(pointers.into_values().collect()) };
    let endian = image.endian();
    let segments: Vec<_> = file.segments().collect();
    let base = segments
        .iter()
        .find(|s| s.name().ok().flatten() == Some("__TEXT"))
        .context("missing text segment")?
        .address();
    let mut commands = image.macho_load_commands()?;
    while let Some(command) = commands.next()? {
        let LoadCommandVariant::LinkeditData(command) = command.variant()? else { continue };
        if command.cmd.get(endian) != macho::LC_DYLD_CHAINED_FIXUPS {
            continue;
        }
        let fixups = command.chained_fixups(endian, image.data())?;
        for segment in fixups.segments(endian)? {
            let segment = segment?;
            let mapped = &segments[segment.index() as usize];
            let format = segment.header().pointer_format.get(endian);
            let data = mapped.data()?;
            for item in segment.fixups(endian, base, data) {
                let (relative, fixup) = item?;
                let Fixup::Rebase(rebase) = fixup else { continue };
                let target = base.wrapping_add(rebase.target_offset);
                if !strings.contains(&target) {
                    continue;
                }
                let (mask, subtract) = match format {
                    macho::DYLD_CHAINED_PTR_64 => ((1u64 << 36) - 1, 0),
                    macho::DYLD_CHAINED_PTR_64_OFFSET => ((1u64 << 36) - 1, base),
                    macho::DYLD_CHAINED_PTR_ARM64E
                    | macho::DYLD_CHAINED_PTR_ARM64E_USERLAND
                    | macho::DYLD_CHAINED_PTR_ARM64E_USERLAND24 => {
                        if rebase.auth.is_some() {
                            (u32::MAX as u64, base)
                        } else {
                            (
                                (1u64 << 43) - 1,
                                if format == macho::DYLD_CHAINED_PTR_ARM64E { 0 } else { base },
                            )
                        }
                    }
                    _ => (0, 0),
                };
                let offset = (mapped.file_range().0 + relative) as usize;
                pointers.insert(
                    offset,
                    Pointer {
                        offset,
                        target,
                        protected: mask == 0 || protected(mapped.address() + relative),
                        mask,
                        subtract,
                    },
                );
            }
        }
    }
    Ok(pointers.into_values().collect())
}
