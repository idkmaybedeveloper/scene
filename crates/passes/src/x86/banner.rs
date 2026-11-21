use anyhow::{Context, Result, ensure};
use iced_x86::{Code, Encoder, Instruction, MemoryOperand, Register};

pub struct Banner {
    pub code: Vec<u8>,
    pub entries: Vec<u64>,
}

pub fn emit(base: u64, lines: &[Vec<u8>], main: Option<u64>) -> Result<Banner> {
    ensure!(!lines.is_empty(), "empty banner");
    let prefix = if main.is_some() { 14 } else { 0 };
    let trailing = if main.is_some() { 5 } else { 1 };
    let function_len = (prefix + lines.len() * 12 + trailing) as u64;
    let sink = base + function_len;
    let mut address = sink + 4;
    let mut line_addresses = Vec::with_capacity(lines.len());
    for line in lines {
        line_addresses.push(address);
        address += line.len() as u64 + 1;
    }
    let mut encoder = Encoder::new(64);
    let mut code = Vec::new();
    let mut push = |code: &mut Vec<u8>, insn: Instruction| -> Result<()> {
        encoder.encode(&insn, base + code.len() as u64).context("encoding banner instruction")?;
        code.extend(encoder.take_buffer());
        Ok(())
    };
    if let Some(main) = main {
        push(&mut code, Instruction::with2(Code::Test_rm64_r64, Register::RDI, Register::RDI)?)?;
        push(&mut code, Instruction::with_branch(Code::Js_rel32_64, base + prefix as u64)?)?;
        push(&mut code, Instruction::with_branch(Code::Jmp_rel32_64, main)?)?;
    }
    for &line in &line_addresses {
        push(
            &mut code,
            Instruction::with2(
                Code::Lea_r64_m,
                Register::RDI,
                MemoryOperand::with_base_displ(Register::RIP, line as i64),
            )?,
        )?;
        push(&mut code, Instruction::with_branch(Code::Call_rel32_64, sink)?)?;
    }
    match main {
        Some(main) => push(&mut code, Instruction::with_branch(Code::Jmp_rel32_64, main)?)?,
        None => push(&mut code, Instruction::with(Code::Retnq))?,
    }
    ensure!(base + code.len() as u64 == sink, "banner encoded to an unexpected size");
    push(
        &mut code,
        Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base(Register::RDI),
            Register::RDI,
        )?,
    )?;
    push(&mut code, Instruction::with(Code::Retnq))?;
    for line in lines {
        code.extend_from_slice(line);
        code.push(0);
    }
    Ok(Banner { code, entries: vec![base, sink] })
}
