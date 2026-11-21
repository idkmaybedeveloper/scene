mod mba;

use anyhow::Result;
use iced_x86::{FlowControl, Instruction, Mnemonic};

pub fn substitute(insns: &[Instruction], base: u64) -> Result<Option<Vec<u8>>> {
    let Some(insn) = insns.first() else { return Ok(None) };
    if insn.len() < 5 {
        return Ok(None);
    }
    let flags_dead = matches!(insn.mnemonic(), Mnemonic::Add | Mnemonic::Sub) && flags_dead(insns);
    let Some(replacement) = mba::substitute(insn, flags_dead)? else {
        return Ok(None);
    };
    let mut bytes = scene_asm::x86::relocate(64, &replacement, base)?;
    bytes.extend(scene_asm::x86::jump(base + bytes.len() as u64, insn.next_ip())?);
    Ok(Some(bytes))
}

fn flags_dead(insns: &[Instruction]) -> bool {
    let mut pending = insns[0].rflags_modified();
    for insn in &insns[1..] {
        if insn.rflags_read() & pending != 0 {
            return false;
        }
        pending &= !insn.rflags_modified();
        if pending == 0 {
            return true;
        }
        if insn.flow_control() != FlowControl::Next {
            return false;
        }
    }
    false
}
