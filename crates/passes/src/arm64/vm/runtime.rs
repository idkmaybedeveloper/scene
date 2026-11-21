use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use anyhow::{Result, ensure};
use dynasmrt::{
    DynamicLabel, DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation, dynasm,
};
use rand::{Rng, seq::SliceRandom};

use super::{
    Options, Output,
    bytecode::{Kind, Opcode, Program, RECORD_SIZE},
    cipher::{self, Binding},
    context,
    context::{FLAGS_OFFSET, NZCV, PLAINTEXT_OFFSET},
    harden, memory,
    mutation::Mutation,
};
use crate::strings::EncryptedString;

type Assembler = VecAssembler<Aarch64Relocation>;

struct Handler {
    opcode: Opcode,
    code: u8,
    label: DynamicLabel,
    variant: u8,
}

#[allow(clippy::useless_conversion)]
pub fn emit(program: &Program, base: u64, options: Options) -> Result<Output> {
    ensure!(base.is_multiple_of(4), "vm: unaligned output address");
    ensure!(options.strength <= 4, "vm: strength exceeds 4");
    let mut mutation = Mutation::new(options.seed, options.mutation_seed)?;
    let records = crate::vm::Records::new(program.records.len(), 32, &mut mutation.rng);
    let table_dispatch = mutation.rng.gen_bool(0.5);
    let table_key = mutation.rng.r#gen::<u64>();
    let table_rotation = mutation.rng.gen_range(1..64u32);
    let r = mutation.registers.clone();
    let mut asm = Assembler::new(base.try_into()?);
    let dispatch = asm.new_dynamic_label();
    let store = asm.new_dynamic_label();
    let bytecode = asm.new_dynamic_label();
    let keys = asm.new_dynamic_label();
    let nonce = asm.new_dynamic_label();
    let immediate = asm.new_dynamic_label();
    let loaded = asm.new_dynamic_label();
    let operand_valid = asm.new_dynamic_label();
    let table = asm.new_dynamic_label();
    let invalid = asm.new_dynamic_label();
    let move_stack = asm.new_dynamic_label();
    let calls: Vec<_> = program
        .records
        .iter()
        .filter(|r| r.opcode.kind == Kind::Call)
        .map(|r| r.immediate)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut resume_labels = BTreeMap::new();
    for &call in &calls {
        let mut next = call + 4;
        while calls.contains(&next) {
            next += 4;
        }
        ensure!(program.sources.iter().any(|i| i.address == next), "vm: call has no continuation");
        resume_labels.entry(next).or_insert_with(|| asm.new_dynamic_label());
    }
    let mut aliases = BTreeMap::<Opcode, Vec<u8>>::new();
    for record in &program.records {
        aliases.entry(record.opcode).or_default();
    }
    let mut handlers = Vec::new();
    for (&opcode, codes) in &mut aliases {
        for variant in 0..mutation.rng.gen_range(2..=4u8) {
            let code = u8::try_from(handlers.len() + 1)?;
            handlers.push(Handler { opcode, code, label: asm.new_dynamic_label(), variant });
            codes.push(code);
        }
    }
    let mut codes: Vec<_> = (1..=handlers.len() as u8).collect();
    codes.shuffle(&mut mutation.rng);
    for handler in &mut handlers {
        handler.code = codes[handler.code as usize - 1];
    }
    for values in aliases.values_mut() {
        for value in values {
            *value = codes[*value as usize - 1];
        }
    }
    handlers.shuffle(&mut mutation.rng);
    context::enter(&mut asm, &mutation);
    let anchors = cipher::bind(&mut asm, &options.anchors, &mut mutation);
    dynasm!(asm; .arch aarch64
        ; adr X(r.base), =>bytecode
        ; mov X(r.pc), X(r.base)
        ; =>dispatch
    );
    cipher::decode(&mut asm, keys, nonce, &mutation, 0);
    dynasm!(asm; .arch aarch64; add XSP(r.pc), XSP(r.pc), #16);
    cipher::decode(&mut asm, keys, nonce, &mutation, 16);
    dynasm!(asm; .arch aarch64; sub XSP(r.pc), XSP(r.pc), #16);
    dynasm!(asm; .arch aarch64
        ; ldrb W(r.opcode), [sp, PLAINTEXT_OFFSET + mutation.header + mutation.fields[0]]
        ; ldrb W(r.dst), [sp, PLAINTEXT_OFFSET + mutation.header + mutation.fields[1]]
        ; ldrb W(r.lhs), [sp, PLAINTEXT_OFFSET + mutation.header + mutation.fields[2]]
        ; ldrb W(r.rhs), [sp, PLAINTEXT_OFFSET + mutation.header + mutation.fields[3]]
        ; ldr W(r.aux), [sp, PLAINTEXT_OFFSET + mutation.header + 4]
        ; ldr X(r.immediate), [sp, PLAINTEXT_OFFSET + mutation.immediate]
        ; lsr W(r.scratch), W(r.aux), #24
        ; add XSP(r.pc), XSP(r.pc), X(r.scratch)
        ; and WSP(r.aux), W(r.aux), #0xffffff
        ; cmp WSP(r.opcode), handlers.len() as u32
        ; b.hi =>invalid
        ; cbz W(r.opcode), =>invalid
        ; cmp WSP(r.dst), #32
        ; b.hi =>invalid
        ; cmp WSP(r.lhs), #32
        ; b.hi =>invalid
        ; cmp WSP(r.rhs), #255
        ; b.eq =>operand_valid
        ; cmp WSP(r.rhs), #32
        ; b.hi =>invalid
        ; =>operand_valid
        ; ldr X(r.lhs), [sp, X(r.lhs), LSL #3]
        ; cmp WSP(r.rhs), #255
        ; b.eq =>immediate
        ; ldr X(r.rhs), [sp, X(r.rhs), LSL #3]
        ; b =>loaded
        ; =>immediate
        ; mov X(r.rhs), X(r.immediate)
        ; =>loaded
    );
    if table_dispatch {
        dynasm!(asm; .arch aarch64
            ; adr X(r.scratch), =>table
            ; ldr X(r.opcode), [X(r.scratch), X(r.opcode), LSL #3]
            ; fmov d4, X(r.aux)
            ; umov X(r.aux), v3.d[0]
            ; eor X(r.opcode), X(r.opcode), X(r.aux)
        );
        cipher::constant(&mut asm, r.aux, table_key);
        dynasm!(asm; .arch aarch64
            ; eor X(r.opcode), X(r.opcode), X(r.aux)
            ; ror X(r.opcode), X(r.opcode), table_rotation
            ; fmov X(r.aux), d4
            ; add X(r.scratch), X(r.scratch), X(r.opcode)
            ; br X(r.scratch)
        );
    } else {
        let mut sorted: Vec<_> = handlers.iter().collect();
        sorted.sort_by_key(|h| h.code);
        dispatch_tree(&mut asm, &sorted, r.opcode, invalid);
    }
    dynasm!(asm; .arch aarch64
        ; =>invalid
        ; hint #36
        ; brk #0
    );
    let mut regions = Vec::with_capacity(handlers.len() + 2);
    regions.push(0..asm.offset().0);
    for emitted in &handlers {
        let start = asm.offset().0;
        dynasm!(asm; .arch aarch64; =>emitted.label; hint #36);
        handler(&mut asm, emitted.opcode, dispatch, store, &mutation, emitted.variant, &calls);
        regions.push(start..asm.offset().0);
    }
    let store_start = asm.offset().0;
    dynasm!(asm; .arch aarch64
        ; =>store
        ; cmp WSP(r.dst), #32
        ; b.eq =>move_stack
        ; str X(r.lhs), [sp, X(r.dst), LSL #3]
        ; str xzr, [sp, mutation.zero_offset()]
        ; b =>dispatch
    );
    regions.push(store_start..asm.offset().0);
    dynasm!(asm; .arch aarch64; =>move_stack);
    memory::move_stack(&mut asm, &mutation, dispatch);
    for (&address, &label) in &resume_labels {
        let start = asm.offset().0;
        dynasm!(asm; .arch aarch64; =>label);
        context::enter(&mut asm, &mutation);
        cipher::restore(&mut asm, &anchors, &mutation);
        dynasm!(asm; .arch aarch64; adr X(r.base), =>bytecode);
        let index = program.sources.iter().position(|i| i.address == address).unwrap();
        cipher::constant(&mut asm, r.pc, records.offsets[index] as u64);
        dynasm!(asm; .arch aarch64; add X(r.pc), X(r.pc), X(r.base); b =>dispatch);
        regions.push(start..asm.offset().0);
    }
    dynasm!(asm; .arch aarch64; =>table);
    let table_offset = asm.offset().0 as i64;
    let table_start = asm.offset().0;
    let mut targets = vec![invalid; handlers.len() + 1];
    for handler in &handlers {
        targets[handler.code as usize] = handler.label;
    }
    if table_dispatch {
        for label in targets {
            let delta = asm.labels().resolve_dynamic(label)?.0 as i64 - table_offset;
            asm.extend(((delta as u64).rotate_left(table_rotation) ^ table_key).to_le_bytes());
        }
    }
    let table_end = asm.offset().0;
    let mut plaintext = vec![0; records.len()];
    let bytecode_address = base + ((asm.offset().0 + 15) & !15) as u64 + 352 + 32;
    mutation.rng.fill(&mut plaintext[..]);
    let mut listing = Vec::new();
    for (index, (record, source)) in program.records.iter().zip(&program.sources).enumerate() {
        let code = *aliases[&record.opcode].choose(&mut mutation.rng).unwrap();
        let bytes = &mut plaintext[records.offsets[index]..records.offsets[index + 1]];
        let fields = [
            code,
            mutation.slot(record.dst),
            mutation.slot(record.lhs),
            if record.rhs == 255 { 255 } else { mutation.slot(record.rhs) },
        ];
        for (field, value) in mutation.fields.iter().zip(fields) {
            bytes[mutation.header as usize + *field as usize] = value;
        }
        let aux = if record.opcode.kind == Kind::MovePair {
            u32::from(mutation.slot((record.aux >> 16) as u8)) << 16
        } else if matches!(record.opcode.kind, Kind::LoadPair | Kind::StorePair) {
            u32::from(mutation.slot(record.aux as u8))
        } else {
            record.aux
        };
        bytes[mutation.header as usize + 4..mutation.header as usize + 8]
            .copy_from_slice(&(aux | (records.size(index) as u32) << 24).to_le_bytes());
        let immediate = if record.target.is_some() {
            records.offsets[record.immediate as usize / RECORD_SIZE] as u64
        } else if record.opcode.kind == Kind::Address {
            record.immediate.wrapping_sub(bytecode_address)
        } else if record.opcode.kind == Kind::Call {
            calls.iter().position(|&s| s == record.immediate).unwrap() as u64
        } else {
            record.immediate
        };
        bytes[mutation.immediate as usize..mutation.immediate as usize + 8]
            .copy_from_slice(&immediate.to_le_bytes());
        bytes[16..24].copy_from_slice(&record.extra.to_le_bytes());
        let mut displayed = record.clone();
        displayed.immediate = immediate;
        listing.push(super::DumpRow {
            offset: records.offsets[index],
            source: source.address,
            source_text: source.decode().unwrap().to_string(),
            opcode: code,
            operation: displayed.to_string(),
        });
    }
    let encrypted = EncryptedString::new(&plaintext)?;
    dynasm!(asm; .arch aarch64; .align 16; =>keys);
    let key_start = asm.offset().0;
    asm.extend(&encrypted.keys);
    let key_end = asm.offset().0;
    dynasm!(asm; .arch aarch64; =>nonce);
    asm.extend(encrypted.nonce);
    dynasm!(asm; .arch aarch64; =>bytecode);
    let start = asm.offset().0;
    asm.extend(encrypted.ciphertext);
    let end = asm.offset().0;
    let resumes = resume_labels
        .into_iter()
        .map(|(address, label)| Ok((address, base + asm.labels().resolve_dynamic(label)?.0 as u64)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut code = asm.finalize()?;
    let raw_runtime_size = code.len() - (end - start);
    let substitutions = if options.strength == 0 {
        0
    } else {
        harden::apply(&mut code, base, regions, &mut mutation, options.strength)?
    };
    let runtime_size = code.len() - (end - start);
    Ok(Output {
        code,
        bytecode: start..end,
        instructions: program.records.len(),
        entry_patch: program.entry_patch,
        sources: program
            .sources
            .iter()
            .map(|i| i.address)
            .chain(program.elided.iter().copied())
            .collect(),
        listing,
        binding: Binding {
            anchors,
            keys: key_start..key_end,
            tables: if table_dispatch { vec![Range { start: table_start, end: table_end }] } else { Vec::new() },
        },
        raw_runtime_size,
        runtime_size,
        substitutions,
        handlers: handlers.len(),
        mutation_seed: mutation.seed,
        kept: calls.iter().copied().collect(),
        resumes,
    })
}

#[allow(clippy::useless_conversion)]
fn dispatch_tree(asm: &mut Assembler, handlers: &[&Handler], register: u8, invalid: DynamicLabel) {
    if handlers.is_empty() {
        dynasm!(asm; .arch aarch64; b =>invalid);
        return;
    }
    let middle = handlers.len() / 2;
    let handler = handlers[middle];
    let upper = asm.new_dynamic_label();
    dynasm!(asm; .arch aarch64; cmp WSP(register), u32::from(handler.code); b.eq =>handler.label; b.hi =>upper);
    dispatch_tree(asm, &handlers[..middle], register, invalid);
    dynasm!(asm; .arch aarch64; =>upper);
    dispatch_tree(asm, &handlers[middle + 1..], register, invalid);
}

#[allow(clippy::useless_conversion)]
fn handler(
    asm: &mut Assembler,
    opcode: Opcode,
    dispatch: DynamicLabel,
    store: DynamicLabel,
    mutation: &Mutation,
    variant: u8,
    calls: &[u64],
) {
    let r = &mutation.registers;
    let wide = opcode.wide;
    match opcode.kind {
        Kind::Address => {
            dynasm!(asm; .arch aarch64; add X(r.lhs), X(r.base), X(r.immediate); b =>store);
        }
        Kind::Load | Kind::Store | Kind::LoadPair | Kind::StorePair => {
            memory::emit(asm, opcode.kind, wide, mutation, store, dispatch);
        }
        Kind::Call => {
            let labels: Vec<_> = calls.iter().map(|_| asm.new_dynamic_label()).collect();
            for (index, &label) in labels.iter().enumerate() {
                cipher::constant(asm, r.scratch, index as u64);
                dynasm!(asm; .arch aarch64; cmp X(r.immediate), X(r.scratch); b.eq =>label);
            }
            dynasm!(asm; .arch aarch64; brk #0);
            for (&site, &label) in calls.iter().zip(&labels) {
                dynasm!(asm; .arch aarch64; =>label);
                context::restore(asm, mutation);
                dynasm!(asm; .arch aarch64; b extern site as usize);
            }
        }
        Kind::Add | Kind::Sub | Kind::And | Kind::Or | Kind::Xor => {
            shift(asm, wide, mutation);
            identity(asm, mutation, variant);
            let plain = asm.new_dynamic_label();
            dynasm!(asm; .arch aarch64; tbz X(r.aux), #8, =>plain; mvn X(r.rhs), X(r.rhs); =>plain);
            macro_rules! binary {
                ($op:ident) => {
                    if wide {
                        dynasm!(asm; .arch aarch64; $op X(r.lhs), X(r.lhs), X(r.rhs));
                    } else {
                        dynasm!(asm; .arch aarch64; $op W(r.lhs), W(r.lhs), W(r.rhs));
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
                dynasm!(asm; .arch aarch64; mrs X(r.scratch), NZCV; str X(r.scratch), [sp, FLAGS_OFFSET]);
            }
            dynasm!(asm; .arch aarch64; b =>store);
        }
        Kind::Move | Kind::Keep => {
            if opcode.kind == Kind::Keep {
                dynasm!(asm; .arch aarch64
                    ; ldr X(r.lhs), [sp, X(r.dst), LSL #3]
                    ; mov X(r.scratch), #65535
                    ; lsl X(r.scratch), X(r.scratch), X(r.aux)
                    ; bic X(r.lhs), X(r.lhs), X(r.scratch)
                    ; orr X(r.lhs), X(r.lhs), X(r.immediate)
                );
            } else {
                dynasm!(asm; .arch aarch64; mov X(r.lhs), X(r.immediate));
                identity(asm, mutation, variant);
            }
            if !wide {
                dynasm!(asm; .arch aarch64; mov W(r.lhs), W(r.lhs));
            }
            dynasm!(asm; .arch aarch64; b =>store);
        }
        Kind::MovePair => {
            dynasm!(asm; .arch aarch64; mov X(r.lhs), X(r.immediate));
            if !wide {
                dynasm!(asm; .arch aarch64; mov W(r.lhs), W(r.lhs));
            }
            dynasm!(asm; .arch aarch64
                ; str X(r.lhs), [sp, X(r.dst), LSL #3]
                ; ldr X(r.lhs), [sp, PLAINTEXT_OFFSET + 16]
                ; ubfx X(r.dst), X(r.aux), #16, #8
            );
            if !wide {
                dynasm!(asm; .arch aarch64; mov W(r.lhs), W(r.lhs));
            }
            dynasm!(asm; .arch aarch64; b =>store);
        }
        Kind::Jump => {
            dynasm!(asm; .arch aarch64; add X(r.pc), X(r.base), X(r.immediate); b =>dispatch)
        }
        Kind::Condition => {
            let taken = asm.new_dynamic_label();
            let conditions: Vec<_> = (0..16).map(|_| asm.new_dynamic_label()).collect();
            for (condition, label) in conditions.iter().enumerate() {
                dynasm!(asm; .arch aarch64; cmp WSP(r.aux), condition as u32; b.eq =>*label);
            }
            dynasm!(asm; .arch aarch64; brk #0);
            macro_rules! conditions {
                ($($index:literal => $condition:ident),* $(,)?) => {$(
                    dynasm!(asm; .arch aarch64
                        ; =>conditions[$index]
                        ; ldr X(r.scratch), [sp, FLAGS_OFFSET]
                        ; msr NZCV, X(r.scratch)
                        ; b.$condition =>taken
                        ; b =>dispatch
                    );
                )*};
            }
            conditions!(0 => eq, 1 => ne, 2 => hs, 3 => lo, 4 => mi, 5 => pl,
                6 => vs, 7 => vc, 8 => hi, 9 => ls, 10 => ge, 11 => lt,
                12 => gt, 13 => le, 14 => al, 15 => nv);
            dynasm!(asm; .arch aarch64; =>taken; add X(r.pc), X(r.base), X(r.immediate); b =>dispatch);
        }
        Kind::Zero | Kind::Bit => {
            if opcode.kind == Kind::Bit {
                dynasm!(asm; .arch aarch64
                    ; and XSP(r.scratch), X(r.aux), #63
                    ; lsr X(r.lhs), X(r.lhs), X(r.scratch)
                    ; and XSP(r.lhs), X(r.lhs), #1
                    ; lsr W(r.aux), W(r.aux), #8
                );
            } else if !wide {
                dynasm!(asm; .arch aarch64; mov W(r.lhs), W(r.lhs));
            }
            let nonzero = asm.new_dynamic_label();
            let taken = asm.new_dynamic_label();
            dynasm!(asm; .arch aarch64
                ; cbnz W(r.aux), =>nonzero
                ; cbz X(r.lhs), =>taken
                ; b =>dispatch
                ; =>nonzero
                ; cbnz X(r.lhs), =>taken
                ; b =>dispatch
                ; =>taken
                ; add X(r.pc), X(r.base), X(r.immediate)
                ; b =>dispatch
            );
        }
        Kind::Return => {
            identity(asm, mutation, variant);
            context::exit(asm, mutation);
        }
        Kind::Nop => dynasm!(asm; .arch aarch64; b =>dispatch),
    }
}

#[allow(clippy::useless_conversion)]
fn shift(asm: &mut Assembler, wide: bool, mutation: &Mutation) {
    let r = &mutation.registers;
    let done = asm.new_dynamic_label();
    let shifts: Vec<_> = (0..4).map(|_| asm.new_dynamic_label()).collect();
    dynasm!(asm; .arch aarch64; ubfx X(r.scratch), X(r.aux), #2, #6; and WSP(r.opcode), W(r.aux), #3);
    for (index, label) in shifts.iter().enumerate() {
        dynasm!(asm; .arch aarch64; cmp WSP(r.opcode), index as u32; b.eq =>*label);
    }
    macro_rules! shifts {
        ($($index:literal => $op:ident),* $(,)?) => {$(
            dynasm!(asm; .arch aarch64; =>shifts[$index]);
            if wide {
                dynasm!(asm; .arch aarch64; $op X(r.rhs), X(r.rhs), X(r.scratch));
            } else {
                dynasm!(asm; .arch aarch64; $op W(r.rhs), W(r.rhs), W(r.scratch));
            }
            dynasm!(asm; .arch aarch64; b =>done);
        )*};
    }
    shifts!(0 => lsl, 1 => lsr, 2 => asr, 3 => ror);
    dynasm!(asm; .arch aarch64; =>done);
}

#[allow(clippy::useless_conversion)]
fn identity(asm: &mut Assembler, mutation: &Mutation, variant: u8) {
    let r = &mutation.registers;
    match variant % 3 {
        0 => {
            dynasm!(asm; .arch aarch64; eor X(r.lhs), X(r.lhs), X(r.scratch); eor X(r.lhs), X(r.lhs), X(r.scratch))
        }
        1 => {
            dynasm!(asm; .arch aarch64; add X(r.lhs), X(r.lhs), X(r.scratch); sub X(r.lhs), X(r.lhs), X(r.scratch))
        }
        _ => dynasm!(asm; .arch aarch64; mvn X(r.lhs), X(r.lhs); mvn X(r.lhs), X(r.lhs)),
    }
}
