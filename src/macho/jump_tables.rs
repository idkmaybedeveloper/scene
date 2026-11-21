use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use iced_x86::{Instruction, Mnemonic, OpKind};
use object::{Object, ObjectSection};

pub fn collect(file: &object::File, insns: &[Instruction]) -> Result<BTreeMap<u64, Vec<u64>>> {
    let mut tables = BTreeMap::new();
    for (index, jump) in insns.iter().enumerate() {
        if !jump.is_jmp_near_indirect() || jump.op0_kind() != OpKind::Register || index < 3 {
            continue;
        }
        let add = &insns[index - 1];
        let load = &insns[index - 2];
        let register = jump.op0_register();
        if add.mnemonic() != Mnemonic::Add
            || add.op0_kind() != OpKind::Register
            || add.op1_kind() != OpKind::Register
            || add.op0_register() != register
            || load.mnemonic() != Mnemonic::Movsxd
            || load.op0_register() != register
            || load.op1_kind() != OpKind::Memory
            || load.memory_base() != add.op1_register()
            || load.memory_index_scale() != 4
            || load.memory_displacement64() != 0
        {
            continue;
        }
        let Some(base) = insns[..index - 2]
            .iter()
            .rev()
            .find(|s| s.op0_kind() == OpKind::Register && s.op0_register() == load.memory_base())
        else {
            continue;
        };
        if base.mnemonic() != Mnemonic::Lea || !base.is_ip_rel_memory_operand() {
            continue;
        }
        let mut selector = load.memory_index().full_register();
        let mut count = None;
        for at in (index.saturating_sub(16)..index - 2).rev() {
            let insn = &insns[at];
            if insn.mnemonic() == Mnemonic::Mov
                && insn.op0_kind() == OpKind::Register
                && insn.op0_register().full_register() == selector
                && insn.op1_kind() == OpKind::Register
            {
                selector = insn.op1_register().full_register();
            }
            if insn.mnemonic() == Mnemonic::Ja && at != 0 {
                let compare = &insns[at - 1];
                if compare.mnemonic() == Mnemonic::Cmp
                    && compare.op0_kind() == OpKind::Register
                    && compare.op0_register().full_register() == selector
                    && matches!(compare.op1_kind(), OpKind::Immediate8to32 | OpKind::Immediate32)
                {
                    count =
                        usize::try_from(compare.immediate(1)).ok().and_then(|n| n.checked_add(1));
                }
                break;
            }
        }
        let Some(count) = count.filter(|&n| n > 0 && n <= 4096) else {
            continue;
        };
        let address = base.ip_rel_memory_address();
        let section = file
            .sections()
            .find(|s| {
                s.address() <= address && address + count as u64 * 4 <= s.address() + s.size()
            })
            .context("jump table exceeds section")?;
        let offset = (address - section.address()) as usize;
        let bytes = section
            .data()?
            .get(offset..offset + count * 4)
            .context("jump table has no file data")?;
        let mut targets = Vec::new();
        for entry in bytes.as_chunks::<4>().0 {
            let target = address.wrapping_add_signed(i32::from_le_bytes(*entry) as i64);
            ensure!(
                insns.binary_search_by_key(&target, |s| s.ip()).is_ok(),
                "jump table target is not an instruction boundary"
            );
            targets.push(target);
        }
        targets.sort_unstable();
        targets.dedup();
        tables.insert(jump.ip(), targets);
    }
    Ok(tables)
}
