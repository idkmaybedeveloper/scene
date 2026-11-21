use dynasmrt::{DynasmApi, dynasm};

use super::emit::Emitter;

#[derive(Clone, Copy, PartialEq)]
enum Op {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Bic,
}

/// recursively rewrites `dst = lhs <op> rhs` into a nest of mixed boolean-arithmetic
/// identities `depth` levels deep. each level saves and restores the two scratch
/// registers it uses, so inner levels reuse register numbers freely while the outer
/// level's live values sit on the stack. the exclusion set is at most {dst, lhs, rhs},
/// so two scratch registers are always available out of x9..x17 and the recursion never
/// runs out of registers at any depth.
pub fn emit(word: u32, out: &mut Emitter, depth: u32) -> bool {
    let op = match word & 0x7FE0_FC00 {
        0x0B00_0000 => Op::Add,
        0x4B00_0000 => Op::Sub,
        0x0A00_0000 => Op::And,
        0x2A00_0000 => Op::Or,
        0x4A00_0000 => Op::Xor,
        _ => return false,
    };
    let dst = (word & 31) as u8;
    let lhs = (word >> 5 & 31) as u8;
    let rhs = (word >> 16 & 31) as u8;
    if dst == 31 {
        return false;
    }
    let wide = word & 0x8000_0000 != 0;
    //note: apple reserves a 128-byte red zone below sp; step past it once so the nested
    // scratch saves never clobber the surrounding code's red-zone locals
    dynasm!(out.asm; .arch aarch64; sub sp, sp, 128);
    expand(out, op, wide, dst, lhs, rhs, depth.max(1));
    dynasm!(out.asm; .arch aarch64; add sp, sp, 128);
    true
}

fn scratch(exclude: [u8; 3]) -> (u8, u8) {
    let mut free = (9u8..=17).filter(|r| !exclude.contains(r));
    (free.next().unwrap(), free.next().unwrap())
}

fn expand(out: &mut Emitter, op: Op, wide: bool, dst: u8, lhs: u8, rhs: u8, depth: u32) {
    if depth == 0 {
        real(out, op, wide, dst, lhs, rhs);
        return;
    }
    // (f1, f2 with its operand order, shift the f2 result left by one, combine)
    let (f1, f2, f2l, f2r, shift, combine) = match op {
        Op::Add => (Op::Xor, Op::And, lhs, rhs, true, Op::Add),
        Op::Or => (Op::Xor, Op::And, lhs, rhs, false, Op::Add),
        Op::Xor => (Op::Or, Op::And, lhs, rhs, false, Op::Sub),
        Op::And => (Op::Add, Op::Or, lhs, rhs, false, Op::Sub),
        Op::Sub => (Op::Xor, Op::Bic, rhs, lhs, true, Op::Sub),
        Op::Bic => {
            real(out, op, wide, dst, lhs, rhs);
            return;
        }
    };
    let (a, b) = scratch([dst, lhs, rhs]);
    dynasm!(out.asm; .arch aarch64; stp X(a), X(b), [sp, -16]!);
    expand(out, f1, wide, a, lhs, rhs, depth - 1);
    real(out, f2, wide, b, f2l, f2r);
    if shift {
        if wide {
            dynasm!(out.asm; .arch aarch64; lsl X(b), X(b), 1);
        } else {
            dynasm!(out.asm; .arch aarch64; lsl W(b), W(b), 1);
        }
    }
    expand(out, combine, wide, dst, a, b, depth - 1);
    dynasm!(out.asm; .arch aarch64; ldp X(a), X(b), [sp], 16);
}

#[allow(clippy::useless_conversion)]
fn real(out: &mut Emitter, op: Op, wide: bool, dst: u8, lhs: u8, rhs: u8) {
    macro_rules! each {
        ($reg:ident) => {
            match op {
                Op::Add => dynasm!(out.asm; .arch aarch64; add $reg(dst), $reg(lhs), $reg(rhs)),
                Op::Sub => dynasm!(out.asm; .arch aarch64; sub $reg(dst), $reg(lhs), $reg(rhs)),
                Op::And => dynasm!(out.asm; .arch aarch64; and $reg(dst), $reg(lhs), $reg(rhs)),
                Op::Or => dynasm!(out.asm; .arch aarch64; orr $reg(dst), $reg(lhs), $reg(rhs)),
                Op::Xor => dynasm!(out.asm; .arch aarch64; eor $reg(dst), $reg(lhs), $reg(rhs)),
                Op::Bic => dynasm!(out.asm; .arch aarch64; bic $reg(dst), $reg(lhs), $reg(rhs)),
            }
        };
    }
    if wide {
        each!(X);
    } else {
        each!(W);
    }
}
