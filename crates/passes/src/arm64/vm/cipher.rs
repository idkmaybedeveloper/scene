use dynasmrt::{
    DynamicLabel, DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation, dynasm,
};
use rand::Rng;

use super::{context::PLAINTEXT_OFFSET, mutation::Mutation};

type Assembler = VecAssembler<Aarch64Relocation>;

pub use crate::vm::{Anchor, Binding};

#[allow(clippy::useless_conversion)]
pub fn bind(asm: &mut Assembler, addresses: &[u64], mutation: &mut Mutation) -> Vec<Anchor> {
    let mut anchors = Vec::new();
    for &address in addresses {
        let salt = mutation.rng.r#gen::<u64>();
        let rotation = mutation.rng.gen_range(1..64);
        anchors.push(Anchor { address, salt, rotation });
    }
    restore(asm, &anchors, mutation);
    anchors
}

#[allow(clippy::useless_conversion)]
pub fn restore(asm: &mut Assembler, anchors: &[Anchor], mutation: &Mutation) {
    let r = &mutation.registers;
    dynasm!(asm; .arch aarch64; mov X(r.immediate), xzr);
    for anchor in anchors {
        let address = anchor.address;
        dynasm!(asm; .arch aarch64
            ; adrp X(r.rhs), extern (address & !0xfff) as usize
            ; add XSP(r.rhs), XSP(r.rhs), (address & 0xfff) as u32
            ; ldr W(r.aux), [X(r.rhs)]
            ; eor X(r.immediate), X(r.immediate), X(r.aux)
            ; ror X(r.immediate), X(r.immediate), anchor.rotation
        );
        constant(asm, r.aux, anchor.salt);
        dynasm!(asm; .arch aarch64; add X(r.immediate), X(r.immediate), X(r.aux));
    }
    dynasm!(asm; .arch aarch64
        ; dup v3.d2, X(r.immediate)
    );
}

#[allow(clippy::useless_conversion)]
pub fn decode(
    asm: &mut Assembler,
    keys: DynamicLabel,
    nonce: DynamicLabel,
    mutation: &Mutation,
    offset: u32,
) {
    let r = &mutation.registers;
    let round = asm.new_dynamic_label();
    dynasm!(asm; .arch aarch64
        ; adr X(r.rhs), =>nonce
        ; ldp q0, q1, [X(r.rhs)]
        ; eor v0.b16, v0.b16, v1.b16
        ; umov X(r.opcode), v0.d[0]
        ; umov X(r.dst), v0.d[1]
        ; rev X(r.opcode), X(r.opcode)
        ; rev X(r.dst), X(r.dst)
        ; sub X(r.aux), X(r.pc), X(r.base)
        ; lsr X(r.aux), X(r.aux), #4
        ; adds X(r.dst), X(r.dst), X(r.aux)
        ; adc X(r.opcode), X(r.opcode), xzr
        ; rev X(r.opcode), X(r.opcode)
        ; rev X(r.dst), X(r.dst)
        ; fmov d0, X(r.opcode)
        ; ins v0.d[1], X(r.dst)
        ; adr X(r.rhs), =>keys
        ; mov W(r.aux), #9
        ; =>round
        ; ldp q1, q2, [X(r.rhs)], #32
        ; eor v1.b16, v1.b16, v2.b16
        ; eor v1.b16, v1.b16, v3.b16
        ; aese v0.b16, v1.b16
        ; aesmc v0.b16, v0.b16
        ; subs W(r.aux), WSP(r.aux), #1
        ; b.ne =>round
        ; ldp q1, q2, [X(r.rhs)], #32
        ; eor v1.b16, v1.b16, v2.b16
        ; eor v1.b16, v1.b16, v3.b16
        ; aese v0.b16, v1.b16
        ; ldp q1, q2, [X(r.rhs)]
        ; eor v1.b16, v1.b16, v2.b16
        ; eor v1.b16, v1.b16, v3.b16
        ; eor v0.b16, v0.b16, v1.b16
        ; ldr q4, [X(r.pc)]
        ; eor v4.b16, v4.b16, v0.b16
        ; str q4, [sp, PLAINTEXT_OFFSET + offset]
    );
}

#[allow(clippy::useless_conversion)]
pub fn constant(asm: &mut Assembler, register: u8, value: u64) {
    dynasm!(asm; .arch aarch64; movz X(register), (value & 0xffff) as u32);
    for shift in [16, 32, 48] {
        dynasm!(asm; .arch aarch64; movk X(register), (value >> shift & 0xffff) as u32, LSL shift);
    }
}
