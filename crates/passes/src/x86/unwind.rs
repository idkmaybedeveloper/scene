use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail, ensure};
use iced_x86::{
    FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};

pub const NONVOLATILE: &[Register] =
    &[Register::RBX, Register::RBP, Register::R12, Register::R13, Register::R14, Register::R15];
pub const FRAME_SIZE: i64 = 256;
pub const CFA_SLOT: i64 = 48;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cfa {
    Register(Register, i64),
    Stack(i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rule {
    Offset(i64),
    Stack(i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub cfa: Cfa,
    pub registers: BTreeMap<Register, Rule>,
}

impl Row {
    pub fn leaf() -> Self {
        Self {
            cfa: Cfa::Register(Register::RSP, 8),
            registers: BTreeMap::from([(Register::RIP, Rule::Offset(-8))]),
        }
    }

    pub fn shifted(&self, delta: i64) -> Self {
        let mut row = self.clone();
        match &mut row.cfa {
            Cfa::Register(Register::RSP, offset) | Cfa::Stack(offset) => *offset += delta,
            _ => {}
        }
        for rule in row.registers.values_mut() {
            if let Rule::Stack(offset) = rule {
                *offset += delta;
            }
        }
        row
    }

    pub fn dispatcher(saved: &BTreeSet<Register>) -> Self {
        let mut row = Self::leaf();
        row.cfa = Cfa::Stack(CFA_SLOT);
        for &register in saved {
            row.registers.insert(register, Rule::Stack(slot(register)));
        }
        row
    }
}

pub fn slot(register: Register) -> i64 {
    64 + NONVOLATILE.iter().position(|&r| r == register).unwrap() as i64 * 8
}

pub struct Frames {
    pub rows: BTreeMap<u64, Row>,
    pub after: BTreeMap<u64, Row>,
    pub saved: BTreeSet<Register>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Frame {
    sp: Option<i64>,
    bp: Option<i64>,
    saved: BTreeMap<Register, i64>,
}

impl Frame {
    fn row(&self) -> Result<Row> {
        let mut row = Row::leaf();
        row.cfa = if let Some(sp) = self.sp {
            Cfa::Register(Register::RSP, -sp)
        } else if let Some(bp) = self.bp {
            Cfa::Register(Register::RBP, -bp)
        } else {
            bail!("unwind has no stable CFA register")
        };
        row.registers.extend(self.saved.iter().map(|(&reg, &offset)| (reg, Rule::Offset(offset))));
        Ok(row)
    }

    fn address(&self, insn: &Instruction) -> Option<i64> {
        if insn.memory_index() != Register::None {
            return None;
        }
        let base = match insn.memory_base() {
            Register::RSP => self.sp,
            Register::RBP => self.bp,
            _ => None,
        }?;
        Some(base.wrapping_add(insn.memory_displacement64() as i64))
    }

    fn pop(&mut self, register: Register) -> Result<()> {
        let sp = self.sp.ok_or_else(|| anyhow::anyhow!("unwind pop from dynamic stack"))?;
        if self.saved.get(&register) == Some(&sp) {
            self.saved.remove(&register);
        }
        if register == Register::RBP {
            self.bp = None;
        }
        self.sp = Some(sp + 8);
        Ok(())
    }

    fn step(&mut self, insn: &Instruction) -> Result<()> {
        if matches!(
            insn.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall | FlowControl::Return
        ) {
            return Ok(());
        }
        let register = if insn.op_count() != 0 && insn.op0_kind() == OpKind::Register {
            insn.op0_register().full_register()
        } else {
            Register::None
        };
        match insn.mnemonic() {
            Mnemonic::Push | Mnemonic::Pushfq => {
                self.sp = self.sp.map(|s| s - 8);
                if NONVOLATILE.contains(&register) {
                    let offset =
                        self.sp.ok_or_else(|| anyhow::anyhow!("unwind save on dynamic stack"))?;
                    self.saved.entry(register).or_insert(offset);
                }
                return Ok(());
            }
            Mnemonic::Pop | Mnemonic::Popfq => {
                ensure!(register != Register::RSP, "unwind pop rsp is unsupported");
                self.pop(register)?;
                return Ok(());
            }
            Mnemonic::Leave => {
                self.sp = self.bp;
                self.pop(Register::RBP)?;
                return Ok(());
            }
            Mnemonic::Mov
                if register == Register::RSP
                    && insn.op1_kind() == OpKind::Register
                    && insn.op1_register() == Register::RBP =>
            {
                self.sp = self.bp;
                return Ok(());
            }
            Mnemonic::Mov
                if register == Register::RBP
                    && insn.op1_kind() == OpKind::Register
                    && insn.op1_register() == Register::RSP =>
            {
                self.bp = self.sp;
                return Ok(());
            }
            Mnemonic::Lea if register == Register::RSP => {
                self.sp = self.address(insn);
                self.row()?;
                return Ok(());
            }
            Mnemonic::Lea if register == Register::RBP => {
                self.bp = self.address(insn);
                self.row()?;
                return Ok(());
            }
            Mnemonic::Add | Mnemonic::Sub
                if register == Register::RSP
                    && matches!(
                        insn.op1_kind(),
                        OpKind::Immediate8to64 | OpKind::Immediate32to64
                    ) =>
            {
                let delta = insn.immediate(1) as i64
                    * if insn.mnemonic() == Mnemonic::Sub { -1 } else { 1 };
                self.sp = self.sp.map(|s| s + delta);
                return Ok(());
            }
            Mnemonic::And if register == Register::RSP => {
                self.sp = None;
                self.row()?;
                return Ok(());
            }
            Mnemonic::Mov
                if insn.op0_kind() == OpKind::Memory
                    && insn.op1_kind() == OpKind::Register
                    && NONVOLATILE.contains(&insn.op1_register()) =>
            {
                if let Some(offset) = self.address(insn) {
                    self.saved.entry(insn.op1_register()).or_insert(offset);
                }
            }
            Mnemonic::Mov
                if NONVOLATILE.contains(&register)
                    && insn.op1_kind() == OpKind::Memory
                    && self.address(insn) == self.saved.get(&register).copied() =>
            {
                self.saved.remove(&register);
            }
            _ => {}
        }
        let mut factory = InstructionInfoFactory::new();
        for used in factory.info(insn).used_registers() {
            if matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                let written = used.register().full_register();
                ensure!(
                    written != Register::RSP,
                    "unsupported stack instruction in unwind analysis"
                );
                if written == Register::RBP {
                    self.bp = None;
                }
            }
        }
        self.row()?;
        Ok(())
    }
}

pub fn analyze(insns: &[Instruction], tables: &BTreeMap<u64, Vec<u64>>) -> Result<Frames> {
    ensure!(!insns.is_empty(), "empty unwind function");
    let indices: BTreeMap<_, _> = insns.iter().enumerate().map(|(i, s)| (s.ip(), i)).collect();
    let mut states = BTreeMap::new();
    let mut pending = vec![(0, Frame { sp: Some(-8), bp: None, saved: BTreeMap::new() })];
    let mut result =
        Frames { rows: BTreeMap::new(), after: BTreeMap::new(), saved: BTreeSet::new() };
    while let Some((index, frame)) = pending.pop() {
        if index >= insns.len() {
            continue;
        }
        if let Some(previous) = states.get(&index) {
            ensure!(*previous == frame, "inconsistent unwind state at control-flow merge");
            continue;
        }
        states.insert(index, frame.clone());
        let insn = &insns[index];
        result.rows.insert(insn.ip(), frame.row()?);
        let mut after = frame;
        after.step(insn)?;
        result.saved.extend(after.saved.keys().copied());
        result.after.insert(insn.ip(), after.row()?);
        match insn.flow_control() {
            FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
                pending.push((index + 1, after))
            }
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if let Some(&next) = indices.get(&insn.near_branch_target()) {
                    pending.push((next, after.clone()));
                }
                if insn.flow_control() == FlowControl::ConditionalBranch {
                    pending.push((index + 1, after));
                }
            }
            FlowControl::IndirectBranch => {
                for address in tables.get(&insn.ip()).ok_or_else(|| {
                    anyhow::anyhow!("unresolved indirect branch in unwind analysis")
                })? {
                    pending.push((
                        *indices
                            .get(address)
                            .ok_or_else(|| anyhow::anyhow!("unwind branch leaves function"))?,
                        after.clone(),
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(result)
}
