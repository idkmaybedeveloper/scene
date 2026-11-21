use anyhow::Result;
use bad64::{Op, Operand};
use scene_disasm::arm64::{Insn, is_conditional_branch, label, target};

use super::{cfg, emit::Emitter};

pub fn remaining(out: &mut Emitter, insns: &[Insn]) -> Result<()> {
    let literals: Vec<_> = insns
        .iter()
        .filter_map(|insn| {
            if insn.data {
                return None;
            }
            let decoded = insn.decode()?;
            let size = match (decoded.op(), decoded.operands()) {
                (Op::LDR, [Operand::Reg { reg, .. }, Operand::Label(_)]) => reg.size() as u64,
                (Op::LDRSW, [_, Operand::Label(_)]) => 4,
                _ => return None,
            };
            let start = label(&decoded)?;
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
        if is_conditional_branch(decoded.op()) {
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
