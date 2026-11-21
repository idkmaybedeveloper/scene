use anyhow::{Context, Result, ensure};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, Encoder, Instruction, InstructionBlock};

pub fn relocate(bitness: u32, insns: &[Instruction], base: u64) -> Result<Vec<u8>> {
    let block = InstructionBlock::new(insns, base);
    Ok(BlockEncoder::encode(bitness, block, BlockEncoderOptions::NONE)
        .context("relocating x86 instructions")?
        .code_buffer)
}

pub fn jump(from: u64, to: u64) -> Result<Vec<u8>> {
    let insn = Instruction::with_branch(Code::Jmp_rel32_64, to)?;
    let mut encoder = Encoder::new(64);
    encoder.encode(&insn, from).context("x86 trampoline exceeds rel32 range")?;
    let bytes = encoder.take_buffer();
    ensure!(bytes.len() == 5, "unexpected trampoline size");
    Ok(bytes)
}
