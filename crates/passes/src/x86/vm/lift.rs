use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail, ensure};
use iced_x86::{Code, FlowControl, Instruction, Mnemonic, OpKind, Register};

use super::super::unwind::{self, Frames};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Mov,
    Movzx,
    Movsx,
    Lea,
    Add,
    Sub,
    And,
    Or,
    Xor,
    Cmp,
    Test,
    Inc,
    Dec,
    Neg,
    Not,
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
    Imul,
    Push,
    Pop,
    Leave,
    Call,
    Jump,
    Condition,
    Return,
    Nop,
    MovPair,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Opcode {
    pub kind: Kind,
    pub width: usize,
}

#[derive(Clone, Copy)]
pub enum Operand {
    None,
    Register {
        index: usize,
        high: bool,
        width: usize,
    },
    Immediate(u64),
    Memory {
        base: Option<usize>,
        index: Option<usize>,
        scale: u32,
        displacement: u64,
        relative: bool,
        width: usize,
    },
}

pub struct Record {
    pub opcode: Opcode,
    pub operands: [Operand; 2],
    pub condition: u8,
    pub target: Option<u64>,
    pub source: Instruction,
    pub extra: Option<(Operand, u64)>,
}

pub struct Program {
    pub records: Vec<Record>,
    pub sources: Vec<u64>,
    pub frames: Frames,
}

pub fn register(reg: Register) -> Result<usize> {
    ensure!(reg.is_gpr(), "vm: unsupported register {reg:?}");
    Ok(reg.full_register().number())
}

fn operand(insn: &Instruction, index: u32) -> Result<Operand> {
    Ok(match insn.op_kind(index) {
        OpKind::Register => {
            let reg = insn.op_register(index);
            Operand::Register {
                index: register(reg)?,
                high: reg.is_gpr8()
                    && matches!(reg, Register::AH | Register::BH | Register::CH | Register::DH),
                width: reg.size(),
            }
        }
        OpKind::Memory => {
            ensure!(
                !insn.has_segment_prefix() && !insn.is_vsib(),
                "vm: unsupported segmented/vector memory"
            );
            let reg = |r| {
                if r == Register::None || r == Register::RIP {
                    Ok(None)
                } else {
                    register(r).map(Some)
                }
            };
            ensure!(
                insn.memory_base() != Register::EIP
                    && (insn.memory_base() == Register::None || insn.memory_base().size() == 8),
                "vm: unsupported address width"
            );
            Operand::Memory {
                base: reg(insn.memory_base())?,
                index: reg(insn.memory_index())?,
                scale: insn.memory_index_scale(),
                displacement: if insn.is_ip_rel_memory_operand() {
                    insn.ip_rel_memory_address()
                } else {
                    insn.memory_displacement64()
                },
                relative: insn.is_ip_rel_memory_operand(),
                width: insn.memory_size().size(),
            }
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Operand::Immediate(insn.immediate(index)),
        _ => bail!("vm: unsupported operand {insn}"),
    })
}

fn translate(insn: Instruction) -> Result<Record> {
    ensure!(
        !insn.has_lock_prefix() && !insn.has_rep_prefix() && !insn.has_repne_prefix(),
        "vm: unsupported instruction prefix"
    );
    let kind = match insn.mnemonic() {
        Mnemonic::Mov => Kind::Mov,
        Mnemonic::Movzx => Kind::Movzx,
        Mnemonic::Movsx | Mnemonic::Movsxd => Kind::Movsx,
        Mnemonic::Lea => Kind::Lea,
        Mnemonic::Add => Kind::Add,
        Mnemonic::Sub => Kind::Sub,
        Mnemonic::And => Kind::And,
        Mnemonic::Or => Kind::Or,
        Mnemonic::Xor => Kind::Xor,
        Mnemonic::Cmp => Kind::Cmp,
        Mnemonic::Test => Kind::Test,
        Mnemonic::Inc => Kind::Inc,
        Mnemonic::Dec => Kind::Dec,
        Mnemonic::Neg => Kind::Neg,
        Mnemonic::Not => Kind::Not,
        Mnemonic::Shl | Mnemonic::Sal => Kind::Shl,
        Mnemonic::Shr => Kind::Shr,
        Mnemonic::Sar => Kind::Sar,
        Mnemonic::Rol => Kind::Rol,
        Mnemonic::Ror => Kind::Ror,
        Mnemonic::Imul if insn.op_count() == 2 => Kind::Imul,
        Mnemonic::Push if insn.stack_pointer_increment() == -8 => Kind::Push,
        Mnemonic::Pop
            if insn.stack_pointer_increment() == 8
                && insn.op0_kind() == OpKind::Register
                && insn.op0_register() != Register::RSP =>
        {
            Kind::Pop
        }
        Mnemonic::Leave => Kind::Leave,
        Mnemonic::Call
            if matches!(insn.flow_control(), FlowControl::Call | FlowControl::IndirectCall) =>
        {
            Kind::Call
        }
        Mnemonic::Jmp if insn.flow_control() == FlowControl::UnconditionalBranch => Kind::Jump,
        Mnemonic::Ret if insn.code() == Code::Retnq => Kind::Return,
        Mnemonic::Nop | Mnemonic::Endbr64 => Kind::Nop,
        _ if insn.is_jcc_short_or_near() => Kind::Condition,
        _ => bail!("vm: unsupported instruction {insn}"),
    };
    let mut operands = [Operand::None; 2];
    if !matches!(
        kind,
        Kind::Call | Kind::Jump | Kind::Condition | Kind::Return | Kind::Leave | Kind::Nop
    ) {
        for index in 0..insn.op_count() {
            ensure!(index < 2, "vm: too many operands");
            operands[index as usize] = operand(&insn, index)?;
        }
    }
    let width = match operands[0] {
        Operand::Register { width, .. } | Operand::Memory { width, .. } => width,
        _ => 8,
    };
    ensure!([1, 2, 4, 8].contains(&width), "vm: unsupported operand width");
    if kind == Kind::Imul {
        ensure!(width != 1, "vm: unsupported multiply width");
    }
    if kind == Kind::Lea {
        ensure!(width == 8, "vm: unsupported lea width");
    }
    let target = matches!(kind, Kind::Jump | Kind::Condition).then(|| insn.near_branch_target());
    Ok(Record {
        opcode: Opcode { kind, width },
        operands,
        target,
        condition: insn.condition_code() as u8,
        source: insn,
        extra: None,
    })
}

pub fn lift(insns: &[Instruction]) -> Result<Program> {
    ensure!(!insns.is_empty(), "vm: empty function");
    let indices: BTreeMap<_, _> = insns.iter().enumerate().map(|(i, s)| (s.ip(), i)).collect();
    let mut pending = vec![0];
    let mut visited = BTreeSet::new();
    let mut records = BTreeMap::new();
    while let Some(index) = pending.pop() {
        ensure!(index < insns.len(), "vm: function falls past its end");
        if !visited.insert(index) {
            continue;
        }
        let insn = insns[index];
        let record = translate(insn)?;
        if let Some(target) = record.target {
            pending.push(
                *indices
                    .get(&target)
                    .ok_or_else(|| anyhow::anyhow!("vm: branch leaves function"))?,
            );
        }
        if !matches!(record.opcode.kind, Kind::Jump | Kind::Return) {
            ensure!(
                index + 1 < insns.len() && insn.next_ip() == insns[index + 1].ip(),
                "vm: function falls past its end"
            );
            pending.push(index + 1);
        }
        records.insert(insn.ip(), record);
    }
    let sources = records.keys().copied().collect();
    let mut protected: BTreeSet<_> = records.values().filter_map(|r| r.target).collect();
    protected.extend(
        records.values().filter(|r| r.opcode.kind == Kind::Call).map(|r| r.source.next_ip()),
    );
    let addresses: Vec<_> = records.keys().copied().collect();
    for pair in addresses.windows(2) {
        let (Some(a), Some(b)) = (records.get(&pair[0]), records.get(&pair[1])) else { continue };
        if protected.contains(&pair[1])
            || a.source.next_ip() != b.source.ip()
            || a.opcode.kind != Kind::Mov
            || a.opcode != b.opcode
        {
            continue;
        }
        if let (
            Operand::Register { index: aidx, .. },
            Operand::Immediate(_),
            Operand::Register { index: bidx, .. },
            Operand::Immediate(value),
        ) = (a.operands[0], a.operands[1], b.operands[0], b.operands[1])
            && aidx != 4
            && bidx != 4
        {
            let extra = (b.operands[0], value);
            let a = records.get_mut(&pair[0]).unwrap();
            a.opcode.kind = Kind::MovPair;
            a.extra = Some(extra);
            records.remove(&pair[1]);
        }
    }
    Ok(Program {
        records: records.into_values().collect(),
        sources,
        frames: unwind::analyze(insns, &BTreeMap::new())?,
    })
}
