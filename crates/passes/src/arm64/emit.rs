use anyhow::{Result, ensure};
use dynasmrt::{DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation, dynasm};
use scene_disasm::arm64::{Insn, target};
use std::collections::BTreeMap;

pub use dynasmrt::DynamicLabel as Label;

pub struct Emitter {
    base: u64,
    pub asm: VecAssembler<Aarch64Relocation>,
    pub substitutions: usize,
    pub resumes: BTreeMap<u64, u64>,
    pub moved: BTreeMap<u64, u64>,
    vectors: BTreeMap<[u8; 16], Label>,
}

impl Emitter {
    pub fn new(base: u64) -> Result<Self> {
        ensure!(base.is_multiple_of(4), "unaligned output address {base:#x}");
        Ok(Self {
            base,
            asm: VecAssembler::new(base.try_into()?),
            substitutions: 0,
            resumes: BTreeMap::new(),
            moved: BTreeMap::new(),
            vectors: BTreeMap::new(),
        })
    }

    pub fn label(&mut self) -> Label {
        self.asm.new_dynamic_label()
    }

    pub fn bind(&mut self, label: Label) {
        dynasm!(self.asm; .arch aarch64; =>label);
    }

    pub fn address(&self, label: Label) -> Result<u64> {
        Ok(self.base + self.asm.labels().resolve_dynamic(label)?.0 as u64)
    }

    #[allow(clippy::useless_conversion)]
    pub fn branch(&mut self, word: u32, label: Label) {
        let reg = (word & 31) as u8;
        match word & 0x7E00_0000 {
            0x3600_0000 => {
                let bit = (word >> 19 & 31) | (word >> 26 & 32);
                if word & 0x0100_0000 == 0 {
                    dynasm!(self.asm; .arch aarch64; tbz X(reg), bit, =>label);
                } else {
                    dynasm!(self.asm; .arch aarch64; tbnz X(reg), bit, =>label);
                }
            }
            0x3400_0000 => match (word >> 31, word >> 24 & 1) {
                (0, 0) => dynasm!(self.asm; .arch aarch64; cbz W(reg), =>label),
                (0, 1) => dynasm!(self.asm; .arch aarch64; cbnz W(reg), =>label),
                (1, 0) => dynasm!(self.asm; .arch aarch64; cbz X(reg), =>label),
                (1, 1) => dynasm!(self.asm; .arch aarch64; cbnz X(reg), =>label),
                _ => unreachable!(),
            },
            _ => {
                macro_rules! conditions {
                    ($($code:literal => $condition:ident),* $(,)?) => {
                        match word & 15 {
                            $($code => dynasm!(self.asm; .arch aarch64; b.$condition =>label),)*
                            _ => unreachable!(),
                        }
                    };
                }
                conditions!(
                    0 => eq, 1 => ne, 2 => hs, 3 => lo,
                    4 => mi, 5 => pl, 6 => vs, 7 => vc,
                    8 => hi, 9 => ls, 10 => ge, 11 => lt,
                    12 => gt, 13 => le, 14 => al, 15 => nv,
                );
            }
        }
    }

    pub fn jump(&mut self, label: Label) {
        dynasm!(self.asm; .arch aarch64; b =>label);
    }

    pub fn jump_to(&mut self, address: u64) {
        dynasm!(self.asm; .arch aarch64; b extern address as usize);
    }

    pub fn raw(&mut self, word: u32) {
        self.asm.extend(word.to_le_bytes());
    }

    pub fn resume(&mut self, address: u64) {
        self.resumes.insert(address, self.base + self.asm.offset().0 as u64);
    }

    pub fn record(&mut self, address: u64) {
        self.moved.insert(address, self.base + self.asm.offset().0 as u64);
    }

    pub fn original(&mut self, insn: &Insn) -> Result<()> {
        let pc = self.base + self.asm.offset().0 as u64;
        let word = match target(insn.word, insn.address) {
            Some(target) => scene_asm::arm64::retarget(insn.word, pc, target)?,
            None => insn.word,
        };
        self.asm.extend(word.to_le_bytes());
        Ok(())
    }

    #[allow(clippy::useless_conversion)]
    pub fn vector(&mut self, register: u8, value: [u8; 16]) {
        let label = if let Some(&label) = self.vectors.get(&value) {
            label
        } else {
            let label = self.label();
            self.vectors.insert(value, label);
            label
        };
        dynasm!(self.asm; .arch aarch64; ldr Q(register), =>label);
    }

    pub fn finish(mut self) -> Result<Vec<Insn>> {
        let data = self.base + self.asm.offset().0 as u64;
        for (value, label) in std::mem::take(&mut self.vectors) {
            self.bind(label);
            self.asm.extend(value);
        }
        scene_disasm::arm64::decode(&self.asm.finalize()?, self.base, |r| r.start >= data)
    }
}
