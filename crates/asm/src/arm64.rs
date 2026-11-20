use anyhow::{Result, anyhow, ensure};
use scene_disasm::arm64::{PcRel, pc_rel};

pub fn retarget(word: u32, pc: u64, target: u64) -> Result<u32> {
    let kind = pc_rel(word).ok_or_else(|| anyhow!("not a pc-relative instruction"))?;
    let delta = target.wrapping_sub(pc) as i64;
    Ok(match kind {
        PcRel::Imm26 => word & !0x03FF_FFFF | field(delta, 2, 26)?,
        PcRel::Imm19 => word & !0x00FF_FFE0 | field(delta, 2, 19)? << 5,
        PcRel::Imm14 => word & !0x0007_FFE0 | field(delta, 2, 14)? << 5,
        PcRel::Adr => word & !0x60FF_FFE0 | adr_bits(field(delta, 0, 21)?),
        PcRel::Adrp => {
            let pages = (target & !0xFFF).wrapping_sub(pc & !0xFFF) as i64;
            word & !0x60FF_FFE0 | adr_bits(field(pages, 12, 21)?)
        }
    })
}

fn field(delta: i64, shift: u32, bits: u32) -> Result<u32> {
    ensure!(
        delta & ((1 << shift) - 1) == 0,
        "offset {delta:#x} is not {}-byte aligned",
        1 << shift
    );
    let value = delta >> shift;
    let limit = 1i64 << (bits - 1);
    ensure!((-limit..limit).contains(&value), "offset {delta:#x} doesn't fit in imm{bits}");
    Ok(value as u32 & ((1 << bits) - 1))
}

fn adr_bits(imm: u32) -> u32 {
    (imm & 3) << 29 | (imm >> 2) << 5
}

#[cfg(test)]
mod tests {
    use super::*;
    use scene_disasm::arm64::target;

    const WORDS: &[(u32, &str)] = &[
        (0x9400_0400, "bl +0x1000"),
        (0x17FF_FFFF, "b -4"),
        (0x5400_0041, "b.ne +8"),
        (0xB400_0060, "cbz x0, +0xc"),
        (0x3708_0040, "tbnz w0, #1, +8"),
        (0x1000_0080, "adr x0, +0x10"),
        (0xB000_0000, "adrp x0, +0x1000"),
        (0x5800_0040, "ldr x0, +8"),
    ];

    #[test]
    fn retarget_in_place_is_identity() {
        for &(word, name) in WORDS {
            let pc = 0x1_0000_4000;
            let dst = target(word, pc).expect(name);
            assert_eq!(retarget(word, pc, dst).unwrap(), word, "{name}");
        }
    }

    #[test]
    fn retarget_after_move_keeps_target() {
        for &(word, name) in WORDS {
            let pc = 0x1_0000_4000;
            let moved = pc + 0x1230;
            let dst = target(word, pc).expect(name);
            let patched = retarget(word, moved, dst).unwrap();
            assert_eq!(target(patched, moved), Some(dst), "{name}");
        }
    }

    #[test]
    fn out_of_range_is_an_error() {
        assert!(retarget(0x5400_0041, 0, 0x1000_0000).is_err());
    }
}
