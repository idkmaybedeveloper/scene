use anyhow::Result;
use scene_disasm::arm64::{Insn, target};

use super::{cfg, emit::Emitter};

pub fn remaining(out: &mut Emitter, insns: &[Insn]) -> Result<()> {
    let literals: Vec<_> = insns
        .iter()
        .filter_map(|insn| {
            if insn.data || insn.word & 0x3B00_0000 != 0x1800_0000 {
                return None;
            }
            let size = match (insn.word >> 26 & 1, insn.word >> 30) {
                (0, 0 | 2) | (1, 0) => 4,
                (0, 1) | (1, 1) => 8,
                (1, 2) => 16,
                _ => return None,
            };
            let start = target(insn.word, insn.address)?;
            Some(start..start.saturating_add(size))
        })
        .collect();
    for insn in insns {
        if out.moved.contains_key(&insn.address)
            || insn.data
            || insn.word == 0xD503_201F
            || literals.iter().any(|r| r.start < insn.address + 4 && insn.address < r.end)
        {
            continue;
        }
        let Some(decoded) = insn.decode() else { continue };
        out.record(insn.address);
        if cfg::is_call(decoded.op()) {
            out.jump_to(insn.address);
            continue;
        }
        let word = insn.word;
        if word & 0xFF00_0010 == 0x5400_0000
            || word & 0x7E00_0000 == 0x3400_0000
            || word & 0x7E00_0000 == 0x3600_0000
        {
            let taken = out.label();
            out.branch(word, taken);
            out.jump_to(insn.address + 4);
            out.bind(taken);
            out.jump_to(target(word, insn.address).unwrap());
        } else {
            out.original(insn)?;
            out.jump_to(insn.address + 4);
        }
    }
    Ok(())
}
