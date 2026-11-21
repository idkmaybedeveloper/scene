use std::ops::Range;

use bad64::{Op, Operand, Reg};
use scene_disasm::arm64::{Insn, target};

pub struct Reference {
    pub instruction: u64,
    pub register: u8,
    pub target: u64,
}

#[derive(Clone, Copy)]
struct Address {
    value: u64,
    redirected: bool,
}

pub fn collect(
    insns: &[Insn],
    functions: &[Range<usize>],
    strings: &Range<u64>,
) -> (Vec<Reference>, Vec<Range<u64>>) {
    let mut references = Vec::new();
    let mut protected = Vec::new();
    for range in functions {
        let mut values = [None::<Address>; 32];
        for insn in &insns[range.clone()] {
            let Some(decoded) = insn.decode().filter(|_| !insn.data) else {
                values.fill(None);
                continue;
            };
            let word = insn.word;
            let dst = (word & 31) as usize;
            if word & 0x9F00_0000 == 0x9000_0000 {
                values[dst] =
                    target(word, insn.address).map(|value| Address { value, redirected: false });
                continue;
            }
            if word & 0x9F00_0000 == 0x1000_0000 {
                let address = target(word, insn.address).unwrap();
                if dst != 31 && strings.contains(&address) {
                    references.push(Reference {
                        instruction: insn.address,
                        register: dst as u8,
                        target: address,
                    });
                }
                values[dst] =
                    Some(Address { value: address, redirected: strings.contains(&address) });
                continue;
            }
            if word & 0xFF80_0000 == 0x9100_0000 {
                let source = (word >> 5 & 31) as usize;
                let shift = if word & (1 << 22) != 0 { 12 } else { 0 };
                values[dst] = values[source].map(|a| Address {
                    value: a.value + ((((word >> 10) & 0xfff) as u64) << shift),
                    redirected: a.redirected,
                });
                if let Some(address) = values[dst]
                    && dst != 31
                    && strings.contains(&address.value)
                {
                    references.push(Reference {
                        instruction: insn.address,
                        register: dst as u8,
                        target: address.value,
                    });
                    values[dst].as_mut().unwrap().redirected = true;
                }
                continue;
            }
            if word & 0xFFE0_FFE0 == 0xAA00_03E0 {
                values[dst] = values[(word >> 16 & 31) as usize];
                continue;
            }
            if word & 0x3B00_0000 == 0x1800_0000
                && let Some(address) = target(word, insn.address)
                && strings.contains(&address)
            {
                protected.push(address..address + 16);
            }
            let call = matches!(
                decoded.op(),
                Op::BL | Op::BLR | Op::BLRAA | Op::BLRAAZ | Op::BLRAB | Op::BLRABZ
            );
            let branch = word & 0x1C00_0000 == 0x1400_0000;
            if call {
                for address in values[..9].iter().flatten().filter(|a| !a.redirected) {
                    protect_page(&mut protected, address.value, strings);
                }
                values[..19].fill(None);
                continue;
            }
            if branch && decoded.op() != Op::NOP {
                for address in values.iter().flatten().filter(|a| !a.redirected) {
                    protect_page(&mut protected, address.value, strings);
                }
                values.fill(None);
                continue;
            }
            for operand in decoded.operands() {
                match operand {
                    Operand::Reg { reg, .. } | Operand::ShiftReg { reg, .. } => {
                        if let Some(index) = register(*reg)
                            && let Some(address) = values[index]
                            && !address.redirected
                        {
                            protect_page(&mut protected, address.value, strings);
                        }
                    }
                    _ => {
                        let source = (word >> 5 & 31) as usize;
                        if let Some(address) = values[source]
                            && !address.redirected
                        {
                            protect_page(&mut protected, address.value, strings);
                        }
                    }
                }
            }
            let name = decoded.op().to_string();
            if !name.starts_with("st") && !matches!(decoded.op(), Op::CMP | Op::CMN | Op::TST) {
                if let Some(Operand::Reg { reg, .. }) = decoded.operands().first()
                    && let Some(index) = register(*reg)
                {
                    values[index] = None;
                }
                if name.starts_with("ldp") {
                    values[(word >> 10 & 31) as usize] = None;
                }
            }
        }
    }
    (references, protected)
}

fn register(reg: Reg) -> Option<usize> {
    if reg.is_simd() || reg.is_sve() || reg.is_pred() {
        return None;
    }
    let name = reg.name();
    match name {
        "fp" => Some(29),
        "lr" => Some(30),
        "sp" | "wsp" | "xzr" | "wzr" => Some(31),
        _ => name.strip_prefix('x').or_else(|| name.strip_prefix('w')).and_then(|n| n.parse().ok()),
    }
}

fn protect_page(protected: &mut Vec<Range<u64>>, address: u64, strings: &Range<u64>) {
    let page = address & !0xfff;
    if page < strings.end && strings.start < page + 0x1000 {
        protected.push(page..page + 0x1000);
    }
}
