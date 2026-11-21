use std::ops::Range;

use anyhow::{Result, ensure};
use dynasmrt::{DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation, dynasm};
use scene_disasm::{Listing, arm64::Insn};

use super::{Options, transform};
use crate::strings::EncryptedString;

type Assembler = VecAssembler<Aarch64Relocation>;
const NZCV: u32 = 0x5a10;
const VM_PROT_READ: u32 = 1;
const VM_PROT_WRITE: u32 = 2;
const VM_PROT_COPY: u32 = 0x10;

pub fn decoder(value: &EncryptedString, source: u64, output: u64, base: u64) -> Result<Vec<u8>> {
    let mut asm = Assembler::new(base as usize);
    let keys = asm.new_dynamic_label();
    let nonce = asm.new_dynamic_label();
    let block = asm.new_dynamic_label();
    let round = asm.new_dynamic_label();
    let byte = asm.new_dynamic_label();
    let done = asm.new_dynamic_label();
    address(&mut asm, 9, source);
    address(&mut asm, 10, output);
    constant(&mut asm, 11, value.ciphertext.len() as u64);
    dynasm!(asm
        ; .arch aarch64
        ; sub sp, sp, 16
        ; adr x12, =>nonce
        ; ldp q0, q1, [x12]
        ; eor v0.b16, v0.b16, v1.b16
        ; umov x14, v0.d[0]
        ; umov x15, v0.d[1]
        ; rev x14, x14
        ; rev x15, x15
        ; =>block
        ; rev x16, x14
        ; rev x17, x15
        ; fmov d0, x16
        ; ins v0.d[1], x17
        ; adds x15, x15, 1
        ; adc x14, x14, xzr
        ; adr x12, =>keys
        ; mov w13, 9
        ; =>round
        ; ldp q1, q2, [x12], 32
        ; eor v1.b16, v1.b16, v2.b16
        ; aese v0.b16, v1.b16
        ; aesmc v0.b16, v0.b16
        ; subs w13, w13, 1
        ; b.ne =>round
        ; ldp q1, q2, [x12], 32
        ; eor v1.b16, v1.b16, v2.b16
        ; aese v0.b16, v1.b16
        ; ldp q1, q2, [x12]
        ; eor v1.b16, v1.b16, v2.b16
        ; eor v0.b16, v0.b16, v1.b16
        ; str q0, [sp]
        ; mov x13, 0
        ; =>byte
        ; ldrb w16, [x9], 1
        ; ldrb w17, [sp, x13]
        ; eor w16, w16, w17
        ; strb w16, [x10], 1
        ; subs x11, x11, 1
        ; b.eq =>done
        ; add x13, x13, 1
        ; cmp x13, 16
        ; b.ne =>byte
        ; b =>block
        ; =>done
        ; add sp, sp, 16
        ; ret
    );
    let code_size = asm.offset().0;
    dynasm!(asm; .arch aarch64; .align 16; =>keys);
    asm.extend(&value.keys);
    dynasm!(asm; .arch aarch64; =>nonce);
    asm.extend(value.nonce);
    let mut original = asm.finalize()?;
    let insns =
        scene_disasm::arm64::decode(&original, base, |r| r.start >= base + code_size as u64)?;
    let moved_base = base + original.len() as u64;
    let transformed =
        transform(&insns, moved_base, Options { seed: value.seed, ..Options::default() })?;
    for (&from, &to) in &transformed.moved {
        if !transformed.kept.contains(&from) {
            patch(&mut original, base, from, to)?;
        }
    }
    patch(&mut original, base, transformed.entry_patch, moved_base)?;
    let size = transformed.insns.len() * 4;
    original.extend(scene_asm::assemble(&Listing::Arm64(transformed.insns), moved_base, size)?);
    Ok(original)
}

pub fn initializer(
    base: u64,
    state: u64,
    storage_size: u64,
    decoders: &[u64],
    pages: &[Range<u64>],
) -> Result<Vec<u8>> {
    let mut asm = Assembler::new(base as usize);
    let retry = asm.new_dynamic_label();
    let wait = asm.new_dynamic_label();
    let done = asm.new_dynamic_label();
    let failed = asm.new_dynamic_label();
    dynasm!(asm
        ; .arch aarch64
        ; stp x0, x1, [sp, -208]!
        ; stp x2, x3, [sp, 16]
        ; stp x4, x5, [sp, 32]
        ; stp x6, x7, [sp, 48]
        ; stp x8, x9, [sp, 64]
        ; stp x10, x11, [sp, 80]
        ; stp x12, x13, [sp, 96]
        ; stp x14, x15, [sp, 112]
        ; str x30, [sp, 128]
        ; stp q0, q1, [sp, 144]
        ; stp q2, q3, [sp, 176]
    );
    protect(&mut asm, &(state..state + storage_size), VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    dynasm!(asm; .arch aarch64; cbnz w0, =>failed);
    address(&mut asm, 16, state);
    dynasm!(asm
        ; .arch aarch64
        ; =>retry
        ; ldaxr w17, [x16]
        ; cmp w17, 2
        ; b.eq =>done
        ; cbnz w17, =>wait
        ; mov w15, 1
        ; stxr w17, w15, [x16]
        ; cbnz w17, =>retry
    );
    for page in pages {
        protect(&mut asm, page, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        dynasm!(asm; .arch aarch64; cbnz w0, =>failed);
    }
    for &decoder in decoders {
        dynasm!(asm; .arch aarch64; bl extern decoder as usize);
    }
    for page in pages {
        protect(&mut asm, page, VM_PROT_READ);
        dynasm!(asm; .arch aarch64; cbnz w0, =>failed);
    }
    address(&mut asm, 16, state);
    dynasm!(asm
        ; .arch aarch64
        ; mov w17, 2
        ; stlr w17, [x16]
        ; b =>done
        ; =>wait
        ; clrex
        ; yield
        ; b =>retry
        ; =>done
        ; clrex
        ; ldp q2, q3, [sp, 176]
        ; ldp q0, q1, [sp, 144]
        ; ldr x30, [sp, 128]
        ; ldp x14, x15, [sp, 112]
        ; ldp x12, x13, [sp, 96]
        ; ldp x10, x11, [sp, 80]
        ; ldp x8, x9, [sp, 64]
        ; ldp x6, x7, [sp, 48]
        ; ldp x4, x5, [sp, 32]
        ; ldp x2, x3, [sp, 16]
        ; ldp x0, x1, [sp], 208
        ; ret
        ; =>failed
        ; brk 0
    );
    Ok(asm.finalize()?)
}

fn protect(asm: &mut Assembler, pages: &Range<u64>, protection: u32) {
    //NOTE: Darwin Mach traps: task_self (28), mach_vm_protect (14).
    // ref: https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/syscall_sw.c
    // VM_PROT_COPY allows private writes to the read-only constant mapping.
    // Executable pages must be excluded before requesting write permission.
    dynasm!(asm; .arch aarch64; movn x16, 27; svc 0x80);
    address(asm, 1, pages.start);
    constant(asm, 2, pages.end - pages.start);
    dynasm!(asm; .arch aarch64
        ; mov w3, 0
        ; movz w4, protection
        ; movn x16, 13
        ; svc 0x80
    );
}

pub fn guard(base: u64, state: u64, initialize: u64, original: &Insn) -> Result<Vec<u8>> {
    let mut asm = Assembler::new(base as usize);
    let ready = asm.new_dynamic_label();
    dynasm!(asm
        ; .arch aarch64
        ; stp x16, x17, [sp, -160]!
        ; mrs x17, NZCV
        ; str x17, [sp, 16]
        ; str x30, [sp, 24]
    );
    address(&mut asm, 16, state);
    dynasm!(asm
        ; .arch aarch64
        ; ldar w16, [x16]
        ; cmp w16, 2
        ; b.eq =>ready
        ; bl extern initialize as usize
        ; =>ready
        ; ldr x17, [sp, 16]
        ; msr NZCV, x17
        ; ldr x30, [sp, 24]
        ; ldp x16, x17, [sp], 160
    );
    if original.word & 0xFC00_0000 == 0x9400_0000 {
        address(&mut asm, 30, original.address + 4);
        let target = scene_disasm::arm64::target(original.word, original.address).unwrap();
        dynasm!(asm; .arch aarch64; b extern target as usize);
    } else if original.decode().is_some_and(|d| super::cfg::is_call(d.op())) {
        ensure!(
            (original.word >> 5 & 31) != 30 && (original.word & 31) != 30,
            "entry call uses lr as a target"
        );
        address(&mut asm, 30, original.address + 4);
        asm.extend((original.word & !0x0020_0000).to_le_bytes());
    } else {
        let at = base + asm.offset().0 as u64;
        let resume = original.address + 4;
        if let Some(target) = scene_disasm::arm64::target(original.word, original.address) {
            relocate_entry(&mut asm, original.word, at, target, resume)?;
        } else {
            asm.extend(original.word.to_le_bytes());
            dynasm!(asm; .arch aarch64; b extern resume as usize);
        }
    }
    Ok(asm.finalize()?)
}

#[allow(clippy::useless_conversion)]
fn relocate_entry(asm: &mut Assembler, word: u32, at: u64, target: u64, resume: u64) -> Result<()> {
    if bad64::decode(word, at)
        .ok()
        .is_some_and(|d| scene_disasm::arm64::is_conditional_branch(d.op()))
    {
        asm.extend(scene_asm::arm64::retarget(word, at, at + 8)?.to_le_bytes());
        dynasm!(asm; .arch aarch64; b extern resume as usize; b extern target as usize);
        return Ok(());
    }
    if word & 0x9F00_0000 == 0x1000_0000 {
        if word & 31 != 31 {
            address(asm, (word & 31) as u8, target);
        }
    } else if word & 0x3B00_0000 == 0x1800_0000 {
        let register = (word & 31) as u8;
        let scratch = if register == 16 { 17 } else { 16 };
        dynasm!(asm; .arch aarch64; str X(scratch), [sp, -144]!);
        address(asm, scratch, target);
        let load = match (word >> 26 & 1, word >> 30) {
            (0, 0) => 0xB940_0000,
            (0, 1) => 0xF940_0000,
            (0, 2) => 0xB980_0000,
            (0, 3) => 0xF980_0000,
            (1, 0) => 0xBD40_0000,
            (1, 1) => 0xFD40_0000,
            (1, 2) => 0x3DC0_0000,
            _ => anyhow::bail!("invalid literal load"),
        };
        asm.extend((load | (scratch as u32) << 5 | register as u32).to_le_bytes());
        dynasm!(asm; .arch aarch64; ldr X(scratch), [sp], 144);
    } else {
        asm.extend(scene_asm::arm64::retarget(word, at, target)?.to_le_bytes());
    }
    dynasm!(asm; .arch aarch64; b extern resume as usize);
    Ok(())
}

pub fn reference(base: u64, register: u8, target: u64, resume: u64) -> Result<Vec<u8>> {
    let mut asm = Assembler::new(base as usize);
    address(&mut asm, register, target);
    dynasm!(asm; .arch aarch64; b extern resume as usize);
    Ok(asm.finalize()?)
}

#[allow(clippy::useless_conversion)]
fn address(asm: &mut Assembler, register: u8, target: u64) {
    dynasm!(asm; .arch aarch64
        ; adrp X(register), extern (target & !0xfff) as usize
        ; add XSP(register), XSP(register), (target & 0xfff) as u32
    );
}

#[allow(clippy::useless_conversion)]
fn constant(asm: &mut Assembler, register: u8, value: u64) {
    dynasm!(asm; .arch aarch64; movz X(register), (value & 0xffff) as u32);
    for shift in [16, 32, 48] {
        dynasm!(asm; .arch aarch64; movk X(register), ((value >> shift) & 0xffff) as u32, LSL shift);
    }
}

fn patch(bytes: &mut [u8], base: u64, from: u64, to: u64) -> Result<()> {
    let offset = (from - base) as usize;
    bytes[offset..offset + 4]
        .copy_from_slice(&scene_asm::arm64::retarget(0x1400_0000, from, to)?.to_le_bytes());
    Ok(())
}
