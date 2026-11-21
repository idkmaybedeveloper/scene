use dynasmrt::{DynasmApi, VecAssembler, aarch64::Aarch64Relocation, dynasm};

pub const SP_OFFSET: u32 = 32 * 8;
pub const FLAGS_OFFSET: u32 = SP_OFFSET + 8;
pub const PLAINTEXT_OFFSET: u32 = 352;
pub const NZCV: u32 = 0x5a10;
pub const STATE_SIZE: u32 = 368;
pub const FRAME_SIZE: u32 = STATE_SIZE + 128;

use super::mutation::Mutation;

#[allow(clippy::useless_conversion)]
pub fn enter(asm: &mut VecAssembler<Aarch64Relocation>, mutation: &Mutation) {
    dynasm!(asm; .arch aarch64; sub sp, sp, FRAME_SIZE);
    for &reg in &mutation.save_order {
        dynasm!(asm; .arch aarch64; str X(reg), [sp, u32::from(mutation.slots[reg as usize]) * 8]);
    }
    dynasm!(asm; .arch aarch64
        ; str xzr, [sp, mutation.zero_offset()]
        ; mrs x17, NZCV
        ; str x17, [sp, FLAGS_OFFSET]
        ; add x17, sp, FRAME_SIZE
        ; str x17, [sp, SP_OFFSET]
    );
    for reg in 0..5u8 {
        dynasm!(asm; .arch aarch64; str Q(reg), [sp, 272 + u32::from(reg) * 16]);
    }
}

#[allow(clippy::useless_conversion)]
pub fn exit(asm: &mut VecAssembler<Aarch64Relocation>, mutation: &Mutation) {
    restore(asm, mutation);
    dynasm!(asm; .arch aarch64; ret);
}

#[allow(clippy::useless_conversion)]
pub fn restore(asm: &mut VecAssembler<Aarch64Relocation>, mutation: &Mutation) {
    dynasm!(asm; .arch aarch64; ldr x17, [sp, FLAGS_OFFSET]; msr NZCV, x17);
    for reg in 0..5u8 {
        dynasm!(asm; .arch aarch64; ldr Q(reg), [sp, 272 + u32::from(reg) * 16]);
    }
    for &reg in mutation.save_order.iter().rev() {
        dynasm!(asm; .arch aarch64; ldr X(reg), [sp, u32::from(mutation.slots[reg as usize]) * 8]);
    }
    dynasm!(asm; .arch aarch64; add sp, sp, FRAME_SIZE);
}
