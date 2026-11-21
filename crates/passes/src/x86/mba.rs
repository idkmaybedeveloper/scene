use anyhow::Result;
use iced_x86::{Code, Instruction, Mnemonic, OpKind, Register};

pub fn substitute(insn: &Instruction, flags_dead: bool) -> Result<Option<Vec<Instruction>>> {
    if insn.op_count() != 2
        || insn.op0_kind() != OpKind::Register
        || !matches!(insn.op1_kind(), OpKind::Immediate32 | OpKind::Immediate32to64)
        || insn.has_lock_prefix()
        || insn.has_rep_prefix()
        || insn.has_repne_prefix()
    {
        return Ok(None);
    }
    let register = insn.op0_register();
    if !register.is_gpr32() && !register.is_gpr64()
        || matches!(register, Register::ESP | Register::RSP)
    {
        return Ok(None);
    }
    let wide = register.is_gpr64();
    let not = Instruction::with1(if wide { Code::Not_rm64 } else { Code::Not_rm32 }, register)?;
    let immediate = insn.immediate32() as i32;
    let binary = |narrow, wide_code, value: i32| {
        Instruction::with2(if wide { wide_code } else { narrow }, register, value)
    };
    let mut replacement = vec![not];
    match insn.mnemonic() {
        Mnemonic::Xor => {
            replacement.push(binary(Code::Xor_rm32_imm32, Code::Xor_rm64_imm32, !immediate)?);
        }
        Mnemonic::And | Mnemonic::Or => {
            let (narrow, wide_code) = if insn.mnemonic() == Mnemonic::And {
                (Code::Or_rm32_imm32, Code::Or_rm64_imm32)
            } else {
                (Code::And_rm32_imm32, Code::And_rm64_imm32)
            };
            replacement.push(binary(narrow, wide_code, !immediate)?);
            replacement.push(not);
            replacement.push(Instruction::with2(
                if wide { Code::Test_rm64_r64 } else { Code::Test_rm32_r32 },
                register,
                register,
            )?);
        }
        Mnemonic::Add | Mnemonic::Sub if flags_dead => {
            let (narrow, wide_code) = if insn.mnemonic() == Mnemonic::Add {
                (Code::Sub_rm32_imm32, Code::Sub_rm64_imm32)
            } else {
                (Code::Add_rm32_imm32, Code::Add_rm64_imm32)
            };
            replacement.push(binary(narrow, wide_code, immediate)?);
            replacement.push(not);
        }
        _ => return Ok(None),
    }
    Ok(Some(replacement))
}
