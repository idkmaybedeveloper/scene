use std::ops::Range;

use anyhow::Result;
use rand::{Rng, seq::SliceRandom};
use scene_disasm::{Listing, arm64};

use super::mutation::Mutation;

pub fn apply(
    code: &mut Vec<u8>,
    base: u64,
    mut regions: Vec<Range<usize>>,
    mutation: &mut Mutation,
    strength: u32,
) -> Result<usize> {
    regions.shuffle(&mut mutation.rng);
    let mut substitutions = 0;
    for range in regions {
        let start = base + range.start as u64;
        let insns = arm64::decode(&code[range], start, |_| false)?;
        let destination = base + code.len() as u64;
        let output = super::super::transform(
            &insns,
            destination,
            super::super::Options {
                mba: strength,
                cff: if strength > 1 { 2 } else { 1 },
                seed: mutation.rng.r#gen(),
            },
        )?;
        let size = output.insns.len() * 4;
        let bytes = scene_asm::assemble(&Listing::Arm64(output.insns), destination, size)?;
        for (&address, &moved) in &output.moved {
            if output.kept.contains(&address) {
                continue;
            }
            let at = (address - base) as usize;
            let target = if address == output.entry_patch { destination } else { moved };
            code[at..at + 4].copy_from_slice(
                &scene_asm::arm64::retarget(0x1400_0000, address, target)?.to_le_bytes(),
            );
        }
        substitutions += output.substitutions;
        code.extend(bytes);
    }
    Ok(substitutions)
}
