use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail, ensure};
use scene_disasm::arm64::{Insn, target};

use super::bytecode::{Kind, Program, RECORD_SIZE, Record};

pub fn lift(insns: &[Insn]) -> Result<Program> {
    ensure!(!insns.is_empty(), "vm: empty function");
    let start = insns[0].address;
    let mut pending = vec![0];
    let mut visited = BTreeSet::new();
    let mut records = BTreeMap::new();
    while let Some(index) = pending.pop() {
        ensure!(index < insns.len(), "vm: function falls past its end");
        if !visited.insert(index) {
            continue;
        }
        let insn = &insns[index];
        ensure!(insn.address == start + index as u64 * 4, "vm: noncontiguous function");
        ensure!(!insn.data && insn.decode().is_some(), "vm: data or invalid instruction");
        let record = translate(insn)?;
        if let Some(address) = record.target {
            let offset = address.wrapping_sub(start);
            ensure!(
                offset.is_multiple_of(4) && offset / 4 < insns.len() as u64,
                "vm: branch leaves function"
            );
            pending.push((offset / 4) as usize);
        }
        if !matches!(record.opcode.kind, Kind::Jump | Kind::Return) {
            pending.push(index + 1);
        }
        records.insert(insn.address, record);
    }
    let offsets: BTreeMap<_, _> = records
        .keys()
        .enumerate()
        .map(|(i, &address)| (address, (i * RECORD_SIZE) as u64))
        .collect();
    let sources =
        records.keys().map(|address| insns[((address - start) / 4) as usize].clone()).collect();
    let mut records: Vec<_> = records.into_values().collect();
    for record in &mut records {
        if let Some(address) = record.target {
            record.immediate = offsets[&address];
        }
    }
    let entry_patch = start + if insns[0].decode().unwrap().op() == bad64::Op::BTI { 4 } else { 0 };
    ensure!(insns.iter().any(|i| i.address == entry_patch), "vm: missing entry instruction");
    Ok(Program { records, sources, entry_patch })
}

fn translate(insn: &Insn) -> Result<Record> {
    let word = insn.word;
    if word == 0xd503_201f || insn.decode().unwrap().op() == bad64::Op::BTI {
        return Ok(Record::new(Kind::Nop, word));
    }
    if word == 0xd65f_03c0 {
        return Ok(Record::new(Kind::Return, word));
    }
    if word & 0xfc00_0000 == 0x1400_0000
        || word & 0xff00_0010 == 0x5400_0000
        || word & 0x7e00_0000 == 0x3400_0000
        || word & 0x7e00_0000 == 0x3600_0000
    {
        let kind = match word & 0x7e00_0000 {
            0x1400_0000 | 0x1600_0000 => Kind::Jump,
            0x5400_0000 => Kind::Condition,
            0x3400_0000 => Kind::Zero,
            _ => Kind::Bit,
        };
        let mut record = Record::new(kind, word);
        record.lhs = (word & 31) as u8;
        record.aux = match kind {
            Kind::Condition => word & 15,
            Kind::Zero => word >> 24 & 1,
            Kind::Bit => (word >> 19 & 31) | (word >> 26 & 32) | (word >> 24 & 1) << 8,
            _ => 0,
        };
        record.target = target(word, insn.address);
        return Ok(record);
    }
    if word & 0x1f00_0000 == 0x1100_0000 {
        let mut record = Record::new(if word >> 30 & 1 == 0 { Kind::Add } else { Kind::Sub }, word);
        record.opcode.flags = word >> 29 & 1 != 0;
        ensure!(
            record.lhs != 31 && (record.dst != 31 || record.opcode.flags),
            "vm: stack pointer arithmetic unsupported"
        );
        record.rhs = 255;
        record.immediate =
            ((word >> 10 & 0xfff) as u64) << (if word >> 22 & 1 == 0 { 0 } else { 12 });
        return Ok(record);
    }
    if word & 0x1f20_0000 == 0x0b00_0000 {
        let mut record = Record::new(if word >> 30 & 1 == 0 { Kind::Add } else { Kind::Sub }, word);
        record.opcode.flags = word >> 29 & 1 != 0;
        record.aux = (word >> 22 & 3) | (word >> 10 & 63) << 2;
        ensure!(record.aux & 3 != 3, "vm: reserved arithmetic shift");
        return Ok(record);
    }
    if word & 0x1f00_0000 == 0x0a00_0000 {
        let kind = match word >> 29 & 3 {
            0 | 3 => Kind::And,
            1 => Kind::Or,
            _ => Kind::Xor,
        };
        let mut record = Record::new(kind, word);
        record.opcode.flags = word >> 29 & 3 == 3;
        record.aux = (word >> 22 & 3) | (word >> 10 & 63) << 2 | (word >> 21 & 1) << 8;
        return Ok(record);
    }
    if word & 0x1f80_0000 == 0x1280_0000 {
        let variant = word >> 29 & 3;
        ensure!(variant != 1, "vm: reserved move-wide instruction");
        let mut record = Record::new(if variant == 3 { Kind::Keep } else { Kind::Move }, word);
        let shift = (word >> 21 & 3) * 16;
        record.immediate = ((word >> 5 & 0xffff) as u64) << shift;
        if variant == 0 {
            record.immediate = !record.immediate;
        }
        record.aux = shift;
        return Ok(record);
    }
    bail!("vm: unsupported instruction {}", insn.decode().unwrap())
}
