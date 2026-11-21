mod pointers;
mod references;
pub mod x86;

use std::{collections::BTreeMap, ops::Range};

use anyhow::{Context, Result, ensure};
use object::{Object, ObjectSection};
use scene_disasm::arm64::{Insn, target};
use scene_passes::{arm64::strings as native, strings::EncryptedString};

use super::{functions::Function, layout::CodeLayout};
use pointers::Pointer;
use references::Reference;

struct StringValue {
    range: Range<u64>,
    offset: usize,
    encrypted: EncryptedString,
}

pub struct Strings {
    section: Range<u64>,
    values: Vec<StringValue>,
    references: Vec<Reference>,
    pointers: Vec<Pointer>,
    kept: usize,
}

pub struct Rewrite<'a, 'data> {
    pub file: &'a object::File<'data>,
    pub out: &'a mut [u8],
    pub code: &'a mut Vec<u8>,
    pub layout: &'a CodeLayout,
    pub moved: &'a BTreeMap<u64, u64>,
    pub insns: &'a [Insn],
    pub functions: &'a [Function],
    pub entries: &'a mut Vec<u64>,
}

impl Strings {
    pub fn collect(file: &object::File, insns: &[Insn], functions: &[Function]) -> Result<Self> {
        let Some(section) = file.sections().find(|s| {
            s.name().ok() == Some("__cstring") && s.segment_name().ok().flatten() == Some("__TEXT")
        }) else {
            return Ok(Self {
                section: 0..0,
                values: Vec::new(),
                references: Vec::new(),
                pointers: Vec::new(),
                kept: 0,
            });
        };
        let range = section.address()..section.address() + section.size();
        let (offset, _) = section.file_range().context("strings have no file data")?;
        let ranges: Vec<_> = functions.iter().map(|f| f.range.clone()).collect();
        let (references, mut protected) = references::collect(insns, &ranges, &range);
        let pointers = pointers::collect(file, &range)?;
        protected.extend(pointers.iter().filter(|p| p.protected).map(|p| p.target..p.target + 1));
        protected.sort_unstable_by_key(|r| (r.start, r.end));
        protected.dedup();
        let mut values = Vec::new();
        let mut kept = 0;
        let mut cursor = 0;
        for value in section.data()?.split_inclusive(|&b| b == 0) {
            let start = range.start + cursor as u64;
            let end = start + value.len() as u64;
            if value.len() <= 1 || protected.iter().any(|r| r.start < end && start < r.end) {
                kept += 1;
            } else {
                values.push(StringValue {
                    range: start..end,
                    offset: offset as usize + cursor,
                    encrypted: EncryptedString::new(value)?,
                });
            }
            cursor += value.len();
        }
        Ok(Self { section: range, values, references, pointers, kept })
    }

    pub fn storage_size(&self) -> usize {
        if self.values.is_empty() {
            0
        } else {
            (self.section.end - self.section.start) as usize + 16
        }
    }

    fn output(&self, target: u64, layout: &CodeLayout) -> Option<u64> {
        self.values
            .iter()
            .any(|s| s.range.contains(&target))
            .then(|| layout.data_base + 16 + target - self.section.start)
    }

    pub fn apply(self, rewrite: Rewrite<'_, '_>) -> Result<()> {
        let Rewrite { file, out, code, layout, moved, insns, functions, entries } = rewrite;
        if self.values.is_empty() {
            eprintln!("strings: 0 encrypted, {} kept", self.kept);
            return Ok(());
        }
        let mut decoders = Vec::new();
        for value in &self.values {
            let base = layout.base + code.len() as u64;
            let output = self.output(value.range.start, layout).unwrap();
            let bytes = native::decoder(&value.encrypted, value.range.start, output, base)?;
            ensure!(
                layout.fits(code.len() + bytes.len()),
                "string decoder exceeds executable space"
            );
            code.extend(bytes);
            entries.push(base);
            decoders.push(base);
        }
        let initialize = layout.base + code.len() as u64;
        code.extend(native::initializer(initialize, layout.data_base, &decoders)?);
        entries.push(initialize);
        for reference in &self.references {
            let Some(output) = self.output(reference.target, layout) else { continue };
            let instruction =
                moved.get(&reference.instruction).copied().unwrap_or(reference.instruction);
            let base = layout.base + code.len() as u64;
            code.extend(native::reference(base, reference.register, output, instruction + 4)?);
            patch(file, out, code, layout.base, instruction, base)?;
        }
        for function in functions {
            let first = &insns[function.range.start];
            if first.data {
                continue;
            }
            let first = if first.decode().is_some_and(|i| i.op() == bad64::Op::BTI) {
                insns.get(function.range.start + 1).context("missing entry after bti")?
            } else {
                first
            };
            let bytes = read(file, out, first.address)?;
            let word = u32::from_le_bytes(bytes.try_into()?);
            let original = Insn {
                address: first.address,
                word,
                target: target(word, first.address),
                data: false,
            };
            let base = layout.base + code.len() as u64;
            code.extend(
                native::guard(base, layout.data_base, initialize, &original).with_context(
                    || format!("relocating entry at {:#x}: {word:08x}", first.address),
                )?,
            );
            entries.push(base);
            patch(file, out, code, layout.base, first.address, base)?;
        }
        ensure!(layout.fits(code.len()), "string protection exceeds executable space");
        for pointer in &self.pointers {
            if let Some(output) = self.output(pointer.target, layout) {
                pointer.write(out, output)?;
            }
        }
        for value in &self.values {
            out[value.offset..value.offset + value.encrypted.ciphertext.len()]
                .copy_from_slice(&value.encrypted.ciphertext);
        }
        eprintln!("strings: {} encrypted, {} kept", self.values.len(), self.kept);
        Ok(())
    }
}

fn read<'a>(file: &object::File, bytes: &'a [u8], address: u64) -> Result<&'a [u8]> {
    for section in file.sections() {
        if (section.address()..section.address() + section.size()).contains(&address) {
            let (offset, _) = section.file_range().context("instruction has no file data")?;
            let at = (offset + address - section.address()) as usize;
            return bytes.get(at..at + 4).context("instruction exceeds input");
        }
    }
    anyhow::bail!("instruction address is unmapped")
}

fn patch(
    file: &object::File,
    out: &mut [u8],
    code: &mut [u8],
    code_base: u64,
    from: u64,
    to: u64,
) -> Result<()> {
    let branch = scene_asm::arm64::retarget(0x1400_0000, from, to)?.to_le_bytes();
    if from >= code_base && from - code_base < code.len() as u64 {
        let offset = (from - code_base) as usize;
        code[offset..offset + 4].copy_from_slice(&branch);
    } else {
        for section in file.sections() {
            if (section.address()..section.address() + section.size()).contains(&from) {
                let (offset, _) = section.file_range().context("patch has no file data")?;
                let at = (offset + from - section.address()) as usize;
                out[at..at + 4].copy_from_slice(&branch);
                return Ok(());
            }
        }
        anyhow::bail!("patch address is unmapped");
    }
    Ok(())
}
