use anyhow::{Result, ensure};
use dynasmrt::{DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation, dynasm};
use scene_disasm::arm64::{Insn, target};

pub use dynasmrt::DynamicLabel as Label;

pub struct Emitter {
    base: u64,
    pub asm: VecAssembler<Aarch64Relocation>,
    pub substitutions: usize,
}

impl Emitter {
    pub fn new(base: u64) -> Result<Self> {
        ensure!(base.is_multiple_of(4), "unaligned output address {base:#x}");
        Ok(Self { base, asm: VecAssembler::new(base.try_into()?), substitutions: 0 })
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

    pub fn ret(&mut self) {
        dynasm!(self.asm; .arch aarch64; ret);
    }

    #[allow(clippy::useless_conversion)]
    pub fn constant(&mut self, reg: u8, value: u32) {
        dynasm!(self.asm
            ; .arch aarch64
            ; movz X(reg), value & 0xFFFF
            ; movk X(reg), value >> 16, LSL 16
        );
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

    pub fn finish(self) -> Result<Vec<Insn>> {
        scene_disasm::arm64::decode(&self.asm.finalize()?, self.base, |_| false)
    }
}
