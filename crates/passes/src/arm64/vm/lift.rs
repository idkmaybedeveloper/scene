use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use bad64::{FlagEffect, Instruction, Op, Operand, Reg, Shift};
use scene_disasm::arm64::{Insn, branch_condition, label};

use super::{
    bytecode::{Kind, Program, RECORD_SIZE, Record},
    operands,
};

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
        ensure!(!insn.data, "vm: data in function");
        let translated = translate(insn)?;
        let record = &translated[0];
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
        records.insert(insn.address, translated);
    }
    let mut protected = BTreeSet::from([start]);
    for (address, translated) in &records {
        for record in translated {
            protected.extend(record.target);
            if record.opcode.kind == Kind::Call {
                protected.insert(address + 4);
            }
        }
    }
    let addresses: Vec<_> = records.keys().copied().collect();
    let mut elided = Vec::new();
    for pair in addresses.windows(2) {
        let (first, next) = (pair[0], pair[1]);
        if next != first + 4 || protected.contains(&next) {
            continue;
        }
        let (Some(a), Some(b)) = (records.get(&first), records.get(&next)) else { continue };
        if a.len() != 1
            || b.len() != 1
            || a[0].opcode.kind != Kind::Move
            || b[0].opcode != a[0].opcode
            || a[0].dst >= 31
            || b[0].dst >= 31
        {
            continue;
        }
        let second = b[0].clone();
        let first = &mut records.get_mut(&first).unwrap()[0];
        first.opcode.kind = Kind::MovePair;
        first.aux = u32::from(second.dst) << 16;
        first.extra = second.immediate;
        records.remove(&next);
        elided.push(next);
    }
    let mut offsets = BTreeMap::new();
    let mut sources = Vec::new();
    let mut flattened = Vec::new();
    for (address, translated) in records {
        offsets.insert(address, (flattened.len() * RECORD_SIZE) as u64);
        for record in translated {
            flattened.push(record);
            sources.push(insns[((address - start) / 4) as usize].clone());
        }
    }
    let mut records = flattened;
    for record in &mut records {
        if let Some(address) = record.target {
            record.immediate = offsets[&address];
        }
    }
    let entry_patch = start + if insns[0].decode().unwrap().op() == bad64::Op::BTI { 4 } else { 0 };
    ensure!(insns.iter().any(|i| i.address == entry_patch), "vm: missing entry instruction");
    ensure!(
        !records
            .iter()
            .zip(&sources)
            .any(|(record, source)| record.opcode.kind == Kind::Call
                && source.address == entry_patch),
        "vm: call overlaps entry trampoline"
    );
    Ok(Program { records, sources, entry_patch, elided })
}

fn translate(insn: &Insn) -> Result<Vec<Record>> {
    let decoded = insn.decode().context("vm: invalid instruction")?;
    if let Some(records) = super::memory::lift(&decoded)? {
        return Ok(records);
    }
    Ok(vec![translate_one(&decoded)?])
}

fn translate_one(decoded: &Instruction) -> Result<Record> {
    let args = decoded.operands();
    match decoded.op() {
        Op::NOP | Op::BTI => Ok(Record::new(Kind::Nop, true)),
        Op::BL | Op::BLR => {
            let mut record = Record::new(Kind::Call, true);
            record.immediate = decoded.address();
            Ok(record)
        }
        Op::ADR | Op::ADRP => {
            let mut record = Record::new(Kind::Address, true);
            record.dst = operands::register(&args[0])?.index;
            record.immediate = label(decoded).context("vm: address has no label")?;
            Ok(record)
        }
        Op::RET => {
            ensure!(
                args.is_empty() || matches!(args, [Operand::Reg { reg: Reg::X30, arrspec: None }]),
                "vm: unsupported return register"
            );
            Ok(Record::new(Kind::Return, true))
        }
        Op::B | Op::CBZ | Op::CBNZ | Op::TBZ | Op::TBNZ => branch(decoded),
        op if branch_condition(op).is_some() => branch(decoded),
        Op::MOV | Op::MOVZ | Op::MOVN | Op::MOVK => move_value(decoded),
        Op::ADD
        | Op::ADDS
        | Op::SUB
        | Op::SUBS
        | Op::AND
        | Op::ANDS
        | Op::ORR
        | Op::EOR
        | Op::BIC
        | Op::BICS
        | Op::ORN
        | Op::EON
        | Op::CMP
        | Op::CMN
        | Op::TST
        | Op::NEG
        | Op::NEGS
        | Op::MVN => arithmetic(decoded),
        _ => bail!("vm: unsupported instruction {decoded}"),
    }
}

fn branch(decoded: &Instruction) -> Result<Record> {
    let op = decoded.op();
    let args = decoded.operands();
    let mut record = if let Some(condition) = branch_condition(op) {
        let mut record = Record::new(Kind::Condition, true);
        record.aux = condition as u32;
        record
    } else if op == Op::B {
        Record::new(Kind::Jump, true)
    } else {
        let source = operands::register(&args[0])?;
        let bit = matches!(op, Op::TBZ | Op::TBNZ);
        let mut record = Record::new(if bit { Kind::Bit } else { Kind::Zero }, source.wide);
        record.lhs = source.index;
        if bit {
            let index = operands::integer(&args[1])?;
            ensure!(index < 64, "vm: invalid bit index");
            record.aux = index as u32 | u32::from(op == Op::TBNZ) << 8;
        } else {
            record.aux = u32::from(op == Op::CBNZ);
        }
        record
    };
    record.target = Some(label(decoded).context("vm: branch has no label")?);
    Ok(record)
}

fn move_value(decoded: &Instruction) -> Result<Record> {
    let [dst, source] = decoded.operands() else {
        bail!("vm: unsupported move {decoded}");
    };
    let dst = operands::register(dst)?;
    let mut record =
        Record::new(if decoded.op() == Op::MOVK { Kind::Keep } else { Kind::Move }, dst.wide);
    record.dst = dst.index;
    if matches!(source, Operand::Reg { .. } | Operand::ShiftReg { .. }) {
        record.opcode.kind = Kind::Or;
        rhs(&mut record, source)?;
    } else {
        record.immediate = operands::integer(source)?;
        if decoded.op() == Op::MOVN {
            record.immediate = !record.immediate;
        }
        if record.opcode.kind == Kind::Keep {
            record.aux = match source {
                Operand::Imm32 { shift: Some(Shift::LSL(amount)), .. }
                | Operand::Imm64 { shift: Some(Shift::LSL(amount)), .. } => *amount,
                _ => 0,
            };
        }
    }
    Ok(record)
}

fn arithmetic(decoded: &Instruction) -> Result<Record> {
    let op = decoded.op();
    let args = decoded.operands();
    let kind = match op {
        Op::ADD | Op::ADDS | Op::CMN => Kind::Add,
        Op::SUB | Op::SUBS | Op::CMP | Op::NEG | Op::NEGS => Kind::Sub,
        Op::AND | Op::ANDS | Op::BIC | Op::BICS | Op::TST => Kind::And,
        Op::ORR | Op::ORN | Op::MVN => Kind::Or,
        _ => Kind::Xor,
    };
    let comparison = matches!(op, Op::CMP | Op::CMN | Op::TST);
    let unary = matches!(op, Op::NEG | Op::NEGS | Op::MVN);
    ensure!(
        args.len() == if comparison || unary { 2 } else { 3 },
        "vm: unsupported arithmetic operands {decoded}"
    );
    let first = operands::register(&args[0])?;
    let mut record = Record::new(kind, first.wide);
    record.opcode.flags = decoded.flags_set() == Some(FlagEffect::Integer);
    record.dst = if comparison { 31 } else { first.index };
    record.lhs = if comparison {
        first.index
    } else if unary {
        31
    } else {
        operands::register(&args[1])?.index
    };
    rhs(&mut record, args.last().unwrap())?;
    if matches!(op, Op::BIC | Op::BICS | Op::ORN | Op::EON | Op::MVN) {
        record.aux |= 1 << 8;
    }
    Ok(record)
}

fn rhs(record: &mut Record, operand: &Operand) -> Result<()> {
    match *operand {
        Operand::Reg { .. } => record.rhs = operands::register(operand)?.index,
        Operand::ShiftReg { reg, shift } => {
            record.rhs = operands::general_register(reg)?.index;
            record.aux = operands::shift(shift)?;
        }
        _ => {
            record.rhs = 255;
            record.immediate = operands::integer(operand)?;
        }
    }
    Ok(())
}
