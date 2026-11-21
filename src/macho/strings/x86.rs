use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use anyhow::{Context, Result, ensure};
use iced_x86::{
    Decoder, DecoderOptions, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
};
use object::{Object, ObjectSection};
use scene_disasm::x86::Insn;
use scene_passes::x86::unwind::Row;
use scene_passes::{strings::EncryptedString, x86::strings as native};

use super::pointers;
use crate::macho::{layout::CodeLayout, unwind::Unwind};

struct Value {
    range: Range<u64>,
    offset: usize,
    encrypted: EncryptedString,
}

pub struct Strings {
    start: u64,
    size: usize,
    values: Vec<Value>,
    references: Vec<Instruction>,
    kept: usize,
}

pub struct Rewrite<'a, 'data> {
    pub file: &'a object::File<'data>,
    pub out: &'a mut [u8],
    pub code: &'a mut Vec<u8>,
    pub layout: &'a CodeLayout,
    pub moved: &'a BTreeMap<u64, u64>,
    pub entries: &'a mut Vec<u64>,
    pub unwind: &'a mut Unwind,
    pub rows: &'a BTreeMap<u64, Row>,
    pub after: &'a BTreeMap<u64, Row>,
}

impl Strings {
    pub fn collect(
        file: &object::File,
        insns: &[Insn],
        targets: &BTreeSet<u64>,
        rows: &BTreeMap<u64, Row>,
        encrypt: bool,
    ) -> Result<Self> {
        let mut result =
            Self { start: 0, size: 0, values: Vec::new(), references: Vec::new(), kept: 0 };
        if !encrypt {
            return Ok(result);
        }
        let Some(section) = file.section_by_name("__cstring") else { return Ok(result) };
        result.start = section.address();
        result.size = section.size() as usize;
        let range = result.start..result.start + section.size();
        let (offset, _) = section.file_range().context("strings have no file data")?;
        let mut protected: Vec<_> =
            pointers::collect(file, &range)?.into_iter().map(|p| p.target..p.target + 1).collect();
        let mut factory = InstructionInfoFactory::new();
        for insn in insns {
            let Insn::Decoded(insn) = insn else { continue };
            for operand in 0..insn.op_count() {
                if insn.op_kind(operand) == OpKind::Immediate64
                    && range.contains(&insn.immediate(operand))
                {
                    let target = insn.immediate(operand);
                    protected.push(target..target + 1);
                }
            }
            if insn.is_ip_rel_memory_operand() && insn.mnemonic() != Mnemonic::Lea {
                let start = insn.ip_rel_memory_address();
                let size = insn.memory_size().size().max(1) as u64;
                if size > 1
                    || factory
                        .info(insn)
                        .used_memory()
                        .iter()
                        .any(|m| !matches!(m.access(), OpAccess::Read | OpAccess::CondRead))
                {
                    protected.push(start..start.saturating_add(size));
                }
            }
        }
        let mut cursor = 0;
        for value in section.data()?.split_inclusive(|&b| b == 0) {
            let start = result.start + cursor as u64;
            let end = start + value.len() as u64;
            let references: Vec<_> = insns
                .iter()
                .filter_map(|s| match s {
                    Insn::Decoded(s)
                        if s.is_ip_rel_memory_operand()
                            && (start..end).contains(&s.ip_rel_memory_address()) =>
                    {
                        Some(*s)
                    }
                    _ => None,
                })
                .collect();
            if value.len() <= 1
                || value.last() != Some(&0)
                || protected.iter().any(|p| p.start < end && start < p.end)
                || references.is_empty()
                || references.iter().any(|i| {
                    i.len() < 5
                        || !rows.contains_key(&i.ip())
                        || targets.range(i.ip() + 1..i.next_ip()).next().is_some()
                })
            {
                result.kept += 1;
            } else {
                result.values.push(Value {
                    range: start..end,
                    offset: offset as usize + cursor,
                    encrypted: EncryptedString::new(value)?,
                });
                result.references.extend(references);
            }
            cursor += value.len();
        }
        Ok(result)
    }

    pub fn storage_size(&self) -> usize {
        if self.values.is_empty() { 0 } else { self.size + 16 }
    }

    pub fn unwind_budget(&self) -> usize {
        if self.values.is_empty() {
            0
        } else {
            self.values.len() * 80 + self.references.len() * 256 + 48
        }
    }

    pub fn code_budget(&self) -> usize {
        if self.values.is_empty() {
            0
        } else {
            self.values.len() * 850 + self.references.len() * 300 + 256
        }
    }

    pub fn apply(self, rewrite: Rewrite<'_, '_>) -> Result<()> {
        let Rewrite { file, out, code, layout, moved, entries, unwind, rows, after } = rewrite;
        if self.values.is_empty() {
            eprintln!("strings: 0 encrypted, {} kept", self.kept);
            return Ok(());
        }
        let output = |address| layout.data_base + 16 + address - self.start;
        let mut decoders = Vec::new();
        for value in &self.values {
            let base = layout.base + code.len() as u64;
            decoders.push(base);
            let generated = native::decoder(
                &value.encrypted,
                value.range.start,
                output(value.range.start),
                base,
            )?;
            unwind.add(base, generated.code.len(), &generated.unwind)?;
            code.extend(generated.code);
            entries.push(base);
        }
        let initialize = layout.base + code.len() as u64;
        let generated = native::initializer(
            initialize,
            native::Storage {
                state: layout.data_base,
                mapped_size: layout.storage_size,
                source: self.start,
                length: self.size,
            },
            &decoders,
        )?;
        unwind.add(initialize, generated.code.len(), &generated.unwind)?;
        code.extend(generated.code);
        entries.push(initialize);
        for reference in self.references {
            let row = &rows[&reference.ip()];
            let after = &after[&reference.ip()];
            let target = reference.ip_rel_memory_address();
            let reference = if let Some(&address) = moved.get(&reference.ip()) {
                let at = (address - layout.base) as usize;
                let mut decoder = Decoder::with_ip(64, &code[at..], address, DecoderOptions::NONE);
                let mut insn = decoder.decode();
                while insn.mnemonic() == Mnemonic::Nop {
                    insn = decoder.decode();
                }
                ensure!(
                    insn.is_ip_rel_memory_operand() && insn.ip_rel_memory_address() == target,
                    "lost relocated string reference"
                );
                insn
            } else {
                reference
            };
            let base = layout.base + code.len() as u64;
            let generated = native::reference(
                base,
                layout.data_base,
                initialize,
                &reference,
                output(target),
                row,
                after,
            )?;
            unwind.add(base, generated.code.len(), &generated.unwind)?;
            code.extend(generated.code);
            entries.push(base);
            let jump = scene_asm::x86::jump(reference.ip(), base)?;
            if reference.ip() >= layout.base && reference.ip() - layout.base < code.len() as u64 {
                let at = (reference.ip() - layout.base) as usize;
                code[at..at + reference.len()].fill(0x90);
                code[at..at + jump.len()].copy_from_slice(&jump);
            } else {
                patch(file, out, &reference, &jump)?;
            }
        }
        ensure!(layout.fits(code.len()), "string protection exceeds executable space");
        for value in &self.values {
            out[value.offset..value.offset + value.encrypted.ciphertext.len()]
                .copy_from_slice(&value.encrypted.ciphertext);
        }
        eprintln!("strings: {} encrypted, {} kept", self.values.len(), self.kept);
        Ok(())
    }
}

fn patch(file: &object::File, out: &mut [u8], insn: &Instruction, bytes: &[u8]) -> Result<()> {
    let section = file
        .sections()
        .find(|s| (s.address()..s.address() + s.size()).contains(&insn.ip()))
        .context("string reference is unmapped")?;
    let (offset, _) = section.file_range().context("string reference has no file data")?;
    let at = (offset + insn.ip() - section.address()) as usize;
    let mut decoder = Decoder::with_ip(64, &out[at..], insn.ip(), DecoderOptions::NONE);
    let current = decoder.decode();
    ensure!(current.code() == insn.code(), "string reference was overwritten without relocation");
    out[at..at + insn.len()].fill(0x90);
    out[at..at + bytes.len()].copy_from_slice(bytes);
    Ok(())
}
