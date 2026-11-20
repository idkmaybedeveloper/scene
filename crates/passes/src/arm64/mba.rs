use dynasmrt::{DynasmApi, dynasm};

use super::emit::Emitter;

enum Operation {
    Add,
    Sub,
    And,
    Or,
    Xor,
}

#[allow(clippy::useless_conversion)]
pub fn emit(word: u32, out: &mut Emitter) -> bool {
    let operation = match word & 0x7FE0_FC00 {
        0x0B00_0000 => Operation::Add,
        0x4B00_0000 => Operation::Sub,
        0x0A00_0000 => Operation::And,
        0x2A00_0000 => Operation::Or,
        0x4A00_0000 => Operation::Xor,
        _ => return false,
    };
    let dst = (word & 31) as u8;
    let lhs = (word >> 5 & 31) as u8;
    let rhs = (word >> 16 & 31) as u8;
    if dst == 31 {
        return false;
    }
    let mut scratch = (9..=17).filter(|r| ![dst, lhs, rhs].contains(r));
    let a = scratch.next().unwrap();
    let b = scratch.next().unwrap();

    //note: apple reserves a 128-byte red zone below sp
    dynasm!(out.asm; .arch aarch64; stp X(a), X(b), [sp, -144]!);
    macro_rules! identity {
        ($reg:ident) => {
            match operation {
                Operation::Add => dynasm!(out.asm
                    ; .arch aarch64
                    ; eor $reg(a), $reg(lhs), $reg(rhs)
                    ; and $reg(b), $reg(lhs), $reg(rhs)
                    ; add $reg(dst), $reg(a), $reg(b), LSL 1
                ),
                Operation::Sub => dynasm!(out.asm
                    ; .arch aarch64
                    ; eor $reg(a), $reg(lhs), $reg(rhs)
                    ; bic $reg(b), $reg(rhs), $reg(lhs)
                    ; sub $reg(dst), $reg(a), $reg(b), LSL 1
                ),
                Operation::And => dynasm!(out.asm
                    ; .arch aarch64
                    ; add $reg(a), $reg(lhs), $reg(rhs)
                    ; orr $reg(b), $reg(lhs), $reg(rhs)
                    ; sub $reg(dst), $reg(a), $reg(b)
                ),
                Operation::Or => dynasm!(out.asm
                    ; .arch aarch64
                    ; eor $reg(a), $reg(lhs), $reg(rhs)
                    ; and $reg(b), $reg(lhs), $reg(rhs)
                    ; add $reg(dst), $reg(a), $reg(b)
                ),
                Operation::Xor => dynasm!(out.asm
                    ; .arch aarch64
                    ; orr $reg(a), $reg(lhs), $reg(rhs)
                    ; and $reg(b), $reg(lhs), $reg(rhs)
                    ; sub $reg(dst), $reg(a), $reg(b)
                ),
            }
        };
    }
    if word & 0x8000_0000 != 0 {
        identity!(X);
    } else {
        identity!(W);
    }
    dynasm!(out.asm; .arch aarch64; ldp X(a), X(b), [sp], 144);
    true
}
