use dynasmrt::{DynasmApi, VecAssembler, aarch64::Aarch64Relocation, dynasm};

pub const ZERO_OFFSET: u32 = 31 * 8;
pub const FLAGS_OFFSET: u32 = 32 * 8;
pub const NZCV: u32 = 0x5a10;
const FRAME_SIZE: u32 = 272;

#[allow(clippy::useless_conversion)]
pub fn enter(asm: &mut VecAssembler<Aarch64Relocation>) {
    dynasm!(asm; .arch aarch64; sub sp, sp, FRAME_SIZE);
    for reg in 0..31u8 {
        dynasm!(asm; .arch aarch64; str X(reg), [sp, u32::from(reg) * 8]);
    }
    dynasm!(asm; .arch aarch64
        ; str xzr, [sp, ZERO_OFFSET]
        ; mrs x17, NZCV
        ; str x17, [sp, FLAGS_OFFSET]
    );
}

#[allow(clippy::useless_conversion)]
pub fn exit(asm: &mut VecAssembler<Aarch64Relocation>) {
    dynasm!(asm; .arch aarch64; ldr x17, [sp, FLAGS_OFFSET]; msr NZCV, x17);
    for reg in 0..31u8 {
        dynasm!(asm; .arch aarch64; ldr X(reg), [sp, u32::from(reg) * 8]);
    }
    dynasm!(asm; .arch aarch64; add sp, sp, FRAME_SIZE; ret);
}
