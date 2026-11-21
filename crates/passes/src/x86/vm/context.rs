use super::{
    super::{
        emit::{Emitter, Label},
        unwind::{Cfa, NONVOLATILE, Row, Rule},
    },
    emit::*,
};
use anyhow::{Result, bail};
use iced_x86::{Code, Instruction, Register};
use std::collections::BTreeMap;

pub const FLAGS: i64 = 128;
pub const PC: i64 = 136;
pub const BASE: i64 = 144;
pub const HASH: i64 = 152;
pub const DEST: i64 = 160;
pub const LEFT: i64 = 168;
pub const RIGHT: i64 = 176;
pub const CFA: i64 = 192;
pub const PLAINTEXT: i64 = 512;
pub const STATE: i64 = 576;
pub const FRAME: i64 = STATE + 128;

pub struct Context {
    pub slots: [u8; 16],
    pub order: Vec<usize>,
    /// emit exact unwind rows across the transient pushfq/popfq windows. only affordable when the
    /// eh_frame has room (the __SCENE segment); in __text padding we keep the steady row to stay
    /// small, which only costs precision for an async sample landing inside a 1-2 instruction window
    pub precise: bool,
}

pub fn row() -> Row {
    let mut registers = BTreeMap::from([(Register::RIP, Rule::Offset(-8))]);
    for (i, &r) in NONVOLATILE.iter().enumerate() {
        registers.insert(r, Rule::Stack(200 + i as i64 * 8));
    }
    Row { cfa: Cfa::Stack(CFA), registers }
}

impl Context {
    pub fn slot(&self, index: usize) -> i64 {
        i64::from(self.slots[index]) * 8
    }
    pub fn enter(&self, out: &mut Emitter, source: &Row) -> Result<()> {
        out.unwind(source.clone());
        out.push(Instruction::with2(
            Code::Lea_r64_m,
            Register::RSP,
            memory(Register::RSP, -FRAME),
        )?);
        out.unwind(source.shifted(FRAME));
        for &i in &self.order {
            if i != 4 {
                store(out, Register::RSP, self.slot(i), GPRS[i])?;
            }
        }
        out.push(Instruction::with(Code::Pushfq));
        out.unwind(source.shifted(FRAME + 8));
        out.push(Instruction::with1(Code::Pop_r64, Register::RAX)?);
        out.unwind(source.shifted(FRAME));
        store(out, Register::RSP, FLAGS, Register::RAX)?;
        out.push(Instruction::with2(Code::Lea_r64_m, Register::RAX, memory(Register::RSP, FRAME))?);
        store(out, Register::RSP, self.slot(4), Register::RAX)?;
        for i in 0..16 {
            out.push(Instruction::with2(
                Code::Movdqu_xmmm128_xmm,
                memory(Register::RSP, 256 + i * 16),
                Register::try_from(Register::XMM0 as usize + i as usize).unwrap(),
            )?);
        }
        let Cfa::Register(reg, offset) = source.cfa else { bail!("vm: unsupported source CFA") };
        load(out, Register::RAX, Register::RSP, self.slot(reg.number()))?;
        out.push(Instruction::with2(
            Code::Lea_r64_m,
            Register::RAX,
            memory(Register::RAX, offset),
        )?);
        store(out, Register::RSP, CFA, Register::RAX)?;
        for (i, &reg) in NONVOLATILE.iter().enumerate() {
            match source.registers.get(&reg) {
                Some(Rule::Offset(offset)) => load(out, Register::RDX, Register::RAX, *offset)?,
                None => load(out, Register::RDX, Register::RSP, self.slot(reg.number()))?,
                _ => bail!("vm: unsupported source unwind rule"),
            }
            store(out, Register::RSP, 200 + i as i64 * 8, Register::RDX)?;
        }
        out.unwind(row());
        Ok(())
    }

    pub fn restore(&self, out: &mut Emitter, source: &Row) -> Result<()> {
        for i in 0..16 {
            out.push(Instruction::with2(
                Code::Movdqu_xmm_xmmm128,
                Register::try_from(Register::XMM0 as usize + i as usize).unwrap(),
                memory(Register::RSP, 256 + i * 16),
            )?);
        }
        flags(out, false, self.precise)?;
        for &i in self.order.iter().rev() {
            if i != 4 {
                load(out, GPRS[i], Register::RSP, self.slot(i))?;
            }
        }
        out.push(Instruction::with2(Code::Lea_r64_m, Register::RSP, memory(Register::RSP, FRAME))?);
        out.unwind(source.clone());
        Ok(())
    }

    pub fn move_stack(&self, out: &mut Emitter, dispatch: Label) -> Result<()> {
        let backward = out.label();
        let forward_loop = out.label();
        let backward_loop = out.label();
        let done = out.label();
        load(out, Register::RAX, Register::RSP, self.slot(4))?;
        out.push(Instruction::with2(
            Code::Lea_r64_m,
            Register::RAX,
            memory(Register::RAX, -FRAME),
        )?);
        out.push(Instruction::with2(Code::Cmp_rm64_r64, Register::RAX, Register::RSP)?);
        branch(out, Code::Je_rel32_64, dispatch)?;
        branch(out, Code::Ja_rel32_64, backward)?;
        constant(out, Register::RCX, 0)?;
        out.bind(forward_loop);
        read(out, Register::RDX, indexed(Register::RSP, Register::RCX, 1, 0), 8)?;
        write(out, indexed(Register::RAX, Register::RCX, 1, 0), Register::RDX, 8)?;
        out.push(Instruction::with2(Code::Add_rm64_imm8, Register::RCX, 8i32)?);
        compare(out, Register::RCX, STATE as i32)?;
        branch(out, Code::Jb_rel32_64, forward_loop)?;
        out.jump(done)?;
        out.bind(backward);
        constant(out, Register::RCX, STATE as u64)?;
        out.bind(backward_loop);
        out.push(Instruction::with2(Code::Sub_rm64_imm8, Register::RCX, 8i32)?);
        read(out, Register::RDX, indexed(Register::RSP, Register::RCX, 1, 0), 8)?;
        write(out, indexed(Register::RAX, Register::RCX, 1, 0), Register::RDX, 8)?;
        compare(out, Register::RCX, 0)?;
        branch(out, Code::Jne_rel32_64, backward_loop)?;
        out.bind(done);
        out.push(Instruction::with2(Code::Mov_r64_rm64, Register::RSP, Register::RAX)?);
        out.jump(dispatch)?;
        Ok(())
    }
}

pub fn flags(out: &mut Emitter, save: bool, precise: bool) -> Result<()> {
    // pushfq/popfq shift rsp for a single instruction. describing that window precisely forces the
    // fde to re-emit every rsp-relative register rule (~40 bytes) on each arithmetic handler, which
    // is only affordable when the eh_frame lives in __SCENE; against __text padding we omit the
    // window rows and keep the steady row, which is exact for synchronous unwinding (no call site
    // sits in the window) and only loses an async sample landing between the two instructions.
    if save {
        out.push(Instruction::with(Code::Pushfq));
        if precise {
            out.unwind(row().shifted(8));
        }
        out.push(Instruction::with1(Code::Pop_r64, Register::RDX)?);
        if precise {
            out.unwind(row());
        }
        store(out, Register::RSP, FLAGS, Register::RDX)?;
    } else {
        out.push(Instruction::with1(Code::Push_rm64, memory(Register::RSP, FLAGS))?);
        if precise {
            out.unwind(row().shifted(8));
        }
        out.push(Instruction::with(Code::Popfq));
        if precise {
            out.unwind(row());
        }
    }
    Ok(())
}
