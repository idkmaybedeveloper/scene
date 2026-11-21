pub mod arm64;
pub mod x86;

use anyhow::{Context, Result, anyhow, ensure};
use iced_x86::Encoder;
use scene_disasm::{Listing, x86::Insn};

const X86_NOP: &[u8] = &[0x90];
const ARM64_NOP: &[u8] = &0xD503_201Fu32.to_le_bytes();

pub fn assemble(listing: &Listing, base: u64, size: usize) -> Result<Vec<u8>> {
    match listing {
        Listing::X86 { bitness, insns } => {
            let mut image = Image::new(base, size, X86_NOP);
            let mut encoder = Encoder::new(*bitness);
            for insn in insns {
                match insn {
                    Insn::Decoded(insn) => {
                        encoder
                            .encode(insn, insn.ip())
                            .map_err(|e| anyhow!("{:#x}: {insn}: {e}", insn.ip()))?;
                        image.place(insn.ip(), &encoder.take_buffer())?;
                    }
                    Insn::Raw { address, bytes } => image.place(*address, bytes)?,
                }
            }
            image.finish()
        }
        Listing::Arm64(insns) => {
            let mut image = Image::new(base, size, ARM64_NOP);
            for insn in insns {
                let word = match insn.target {
                    Some(target) => arm64::retarget(insn.word, insn.address, target)
                        .with_context(|| format!("{:#x}: {:08x}", insn.address, insn.word))?,
                    None => insn.word,
                };
                image.place(insn.address, &word.to_le_bytes())?;
            }
            image.finish()
        }
    }
}

struct Image {
    base: u64,
    bytes: Vec<u8>,
    cursor: usize,
    filler: &'static [u8],
}

impl Image {
    fn new(base: u64, size: usize, filler: &'static [u8]) -> Self {
        Self { base, bytes: vec![0; size], cursor: 0, filler }
    }

    fn place(&mut self, address: u64, data: &[u8]) -> Result<()> {
        let offset = address
            .checked_sub(self.base)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or_else(|| anyhow!("{address:#x}: below section base {:#x}", self.base))?;
        ensure!(
            offset >= self.cursor,
            "{address:#x}: overlaps previous instruction ending at {:#x}",
            self.base + self.cursor as u64
        );
        ensure!(offset + data.len() <= self.bytes.len(), "{address:#x}: runs past end of section");
        self.pad_to(offset)?;
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
        self.cursor = offset + data.len();
        Ok(())
    }

    fn pad_to(&mut self, offset: usize) -> Result<()> {
        let gap = &mut self.bytes[self.cursor..offset];
        ensure!(
            gap.len().is_multiple_of(self.filler.len()),
            "{:#x}: gap of {} bytes cant be filled with nops!!",
            self.base + self.cursor as u64,
            gap.len()
        );
        for (byte, fill) in gap.iter_mut().zip(self.filler.iter().cycle()) {
            *byte = *fill;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>> {
        self.pad_to(self.bytes.len())?;
        Ok(self.bytes)
    }
}
