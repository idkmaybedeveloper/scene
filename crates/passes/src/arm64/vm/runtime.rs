use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use dynasmrt::{
    DynamicLabel, DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation, dynasm,
};

use super::{
    Output,
    bytecode::{Kind, Opcode, Program, RECORD_SIZE},
    context,
};

type Assembler = VecAssembler<Aarch64Relocation>;
use context::{FLAGS_OFFSET, NZCV, ZERO_OFFSET};

#[allow(clippy::useless_conversion)]
pub fn emit(program: &Program, base: u64, seed: u32) -> Result<Output> {
    ensure!(base.is_multiple_of(4), "vm: unaligned output address");
    let mut asm = Assembler::new(base.try_into()?);
    let dispatch = asm.new_dynamic_label();
    let store = asm.new_dynamic_label();
    let bytecode = asm.new_dynamic_label();
    let immediate = asm.new_dynamic_label();
    let loaded = asm.new_dynamic_label();
    let table = asm.new_dynamic_label();
    let invalid = asm.new_dynamic_label();
    let mut handlers = BTreeMap::new();
    for record in &program.records {
        handlers.entry(record.opcode).or_insert_with(|| (0u8, asm.new_dynamic_label()));
    }
    let mut codes: Vec<u8> = (1..=handlers.len() as u8).collect();
    let mut random = seed.max(1);
    for i in (1..codes.len()).rev() {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        codes.swap(i, random as usize % (i + 1));
    }
    for ((_, (code, _)), value) in handlers.iter_mut().zip(codes) {
        *code = value;
    }
    context::enter(&mut asm);
    dynasm!(asm; .arch aarch64
        ; adr x16, =>bytecode
        ; mov x9, x16
        ; =>dispatch
        ; ldrb w10, [x9]
        ; ldrb w11, [x9, #1]
        ; ldrb w12, [x9, #2]
        ; ldrb w13, [x9, #3]
        ; ldr w14, [x9, #4]
        ; ldr x15, [x9, #8]
        ; add x9, x9, #16
        ; ldr x12, [sp, x12, LSL #3]
        ; cmp w13, #255
        ; b.eq =>immediate
        ; ldr x13, [sp, x13, LSL #3]
        ; b =>loaded
        ; =>immediate
        ; mov x13, x15
        ; =>loaded
    );
    dynasm!(asm; .arch aarch64
        ; cmp w10, handlers.len() as u32
        ; b.hi =>invalid
        ; adr x17, =>table
        ; ldrsw x10, [x17, x10, LSL #2]
        ; add x17, x17, x10
        ; br x17
        ; =>invalid
        ; hint #36
        ; brk #0
    );
    for (&opcode, &(_, label)) in &handlers {
        dynasm!(asm; .arch aarch64; =>label; hint #36);
        handler(&mut asm, opcode, dispatch, store);
    }
    dynasm!(asm; .arch aarch64
        ; =>store
        ; str x12, [sp, x11, LSL #3]
        ; str xzr, [sp, ZERO_OFFSET]
        ; b =>dispatch
        ; =>table
    );
    let table_offset = asm.offset().0 as i64;
    let mut targets = vec![invalid; handlers.len() + 1];
    for &(code, label) in handlers.values() {
        targets[code as usize] = label;
    }
    for label in targets {
        let delta = asm.labels().resolve_dynamic(label)?.0 as i64 - table_offset;
        asm.extend(i32::try_from(delta)?.to_le_bytes());
    }
    dynasm!(asm; .arch aarch64
        ; .align 8
        ; =>bytecode
    );
    let start = asm.offset().0;
    for record in &program.records {
        asm.extend([handlers[&record.opcode].0, record.dst, record.lhs, record.rhs]);
        asm.extend(record.aux.to_le_bytes());
        asm.extend(record.immediate.to_le_bytes());
    }
    let end = asm.offset().0;
    Ok(Output {
        code: asm.finalize()?,
        bytecode: start..end,
        instructions: program.records.len(),
        entry_patch: program.entry_patch,
        sources: program.sources.iter().map(|i| i.address).collect(),
        listing: program
            .records
            .iter()
            .zip(&program.sources)
            .enumerate()
            .map(|(index, (record, source))| super::DumpRow {
                offset: index * RECORD_SIZE,
                source: source.address,
                source_text: source.decode().unwrap().to_string(),
                opcode: handlers[&record.opcode].0,
                operation: record.to_string(),
            })
            .collect(),
    })
}

#[allow(clippy::useless_conversion)]
fn handler(asm: &mut Assembler, opcode: Opcode, dispatch: DynamicLabel, store: DynamicLabel) {
    let wide = opcode.wide;
    match opcode.kind {
        Kind::Add | Kind::Sub | Kind::And | Kind::Or | Kind::Xor => {
            shift(asm, wide);
            let plain = asm.new_dynamic_label();
            dynasm!(asm; .arch aarch64; tbz x14, #8, =>plain; mvn x13, x13; =>plain);
            macro_rules! binary {
                ($op:ident) => {
                    if wide {
                        dynasm!(asm; .arch aarch64; $op x12, x12, x13);
                    } else {
                        dynasm!(asm; .arch aarch64; $op w12, w12, w13);
                    }
                };
            }
            match (opcode.kind, opcode.flags) {
                (Kind::Add, false) => binary!(add),
                (Kind::Add, true) => binary!(adds),
                (Kind::Sub, false) => binary!(sub),
                (Kind::Sub, true) => binary!(subs),
                (Kind::And, false) => binary!(and),
                (Kind::And, true) => binary!(ands),
                (Kind::Or, _) => binary!(orr),
                (Kind::Xor, _) => binary!(eor),
                _ => unreachable!(),
            }
            if opcode.flags {
                dynasm!(asm; .arch aarch64; mrs x17, NZCV; str x17, [sp, FLAGS_OFFSET]);
            }
            dynasm!(asm; .arch aarch64; b =>store);
        }
        Kind::Move | Kind::Keep => {
            if opcode.kind == Kind::Keep {
                dynasm!(asm; .arch aarch64
                    ; ldr x12, [sp, x11, LSL #3]
                    ; mov x17, #65535
                    ; lsl x17, x17, x14
                    ; bic x12, x12, x17
                    ; orr x12, x12, x15
                );
            } else {
                dynasm!(asm; .arch aarch64; mov x12, x15);
            }
            if !wide {
                dynasm!(asm; .arch aarch64; mov w12, w12);
            }
            dynasm!(asm; .arch aarch64; b =>store);
        }
        Kind::Jump => dynasm!(asm; .arch aarch64; add x9, x16, x15; b =>dispatch),
        Kind::Condition => {
            let taken = asm.new_dynamic_label();
            let conditions: Vec<_> = (0..16).map(|_| asm.new_dynamic_label()).collect();
            for (condition, label) in conditions.iter().enumerate() {
                dynasm!(asm; .arch aarch64; cmp w14, condition as u32; b.eq =>*label);
            }
            dynasm!(asm; .arch aarch64; brk #0);
            macro_rules! conditions {
                ($($index:literal => $condition:ident),* $(,)?) => {$(
                    dynasm!(asm; .arch aarch64
                        ; =>conditions[$index]
                        ; ldr x17, [sp, FLAGS_OFFSET]
                        ; msr NZCV, x17
                        ; b.$condition =>taken
                        ; b =>dispatch
                    );
                )*};
            }
            conditions!(0 => eq, 1 => ne, 2 => hs, 3 => lo, 4 => mi, 5 => pl,
                6 => vs, 7 => vc, 8 => hi, 9 => ls, 10 => ge, 11 => lt,
                12 => gt, 13 => le, 14 => al, 15 => nv);
            dynasm!(asm; .arch aarch64; =>taken; add x9, x16, x15; b =>dispatch);
        }
        Kind::Zero | Kind::Bit => {
            if opcode.kind == Kind::Bit {
                dynasm!(asm; .arch aarch64
                    ; and x17, x14, #63
                    ; lsr x12, x12, x17
                    ; and x12, x12, #1
                    ; lsr w14, w14, #8
                );
            } else if !wide {
                dynasm!(asm; .arch aarch64; mov w12, w12);
            }
            let nonzero = asm.new_dynamic_label();
            let taken = asm.new_dynamic_label();
            dynasm!(asm; .arch aarch64
                ; cbnz w14, =>nonzero
                ; cbz x12, =>taken
                ; b =>dispatch
                ; =>nonzero
                ; cbnz x12, =>taken
                ; b =>dispatch
                ; =>taken
                ; add x9, x16, x15
                ; b =>dispatch
            );
        }
        Kind::Return => {
            context::exit(asm);
        }
        Kind::Nop => dynasm!(asm; .arch aarch64; b =>dispatch),
    }
}

fn shift(asm: &mut Assembler, wide: bool) {
    let done = asm.new_dynamic_label();
    let shifts: Vec<_> = (0..4).map(|_| asm.new_dynamic_label()).collect();
    dynasm!(asm; .arch aarch64; ubfx x17, x14, #2, #6; and w10, w14, #3);
    for (index, label) in shifts.iter().enumerate() {
        dynasm!(asm; .arch aarch64; cmp w10, index as u32; b.eq =>*label);
    }
    macro_rules! shifts {
        ($($index:literal => $op:ident),* $(,)?) => {$(
            dynasm!(asm; .arch aarch64; =>shifts[$index]);
            if wide {
                dynasm!(asm; .arch aarch64; $op x13, x13, x17);
            } else {
                dynasm!(asm; .arch aarch64; $op w13, w13, w17);
            }
            dynasm!(asm; .arch aarch64; b =>done);
        )*};
    }
    shifts!(0 => lsl, 1 => lsr, 2 => asr, 3 => ror);
    dynasm!(asm; .arch aarch64; =>done);
}
