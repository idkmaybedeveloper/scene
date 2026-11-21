use std::collections::BTreeMap;
use std::ops::Range;

use anyhow::Result;
use iced_x86::{Code, Instruction, Register};
use rand::{
    Rng, SeedableRng,
    rngs::StdRng,
    seq::{IteratorRandom, SliceRandom},
};

use super::super::{
    emit::{Emitter, Label},
    unwind::Row,
};
use super::{
    Options, Output,
    context::{self, BASE, Context, DEST, HASH, LEFT, PC, PLAINTEXT, RIGHT},
    emit::*,
    lift::{Kind, Opcode, Operand, Program},
};
use crate::{
    strings::EncryptedString,
    vm::{Anchor, Binding, Records},
};

struct Handler {
    opcode: Opcode,
    code: u8,
    label: Label,
}

pub fn emit(program: &Program, base: u64, options: Options) -> Result<Output> {
    let seed = match options.mutation_seed {
        Some(seed) => seed,
        None => {
            let mut b = [0; 8];
            getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("vm entropy: {e}"))?;
            u64::from_le_bytes(b) ^ u64::from(options.seed)
        }
    };
    let mut rng = StdRng::seed_from_u64(seed);
    let mut slots = std::array::from_fn(|i| i as u8);
    slots.shuffle(&mut rng);
    let mut order: Vec<_> = (0..16).collect();
    order.shuffle(&mut rng);
    let context = Context { slots, order, precise: options.precise };
    let mut out = Emitter::new();
    let records = Records::new(program.records.len(), 64, &mut rng);
    let offsets: BTreeMap<_, _> = program
        .records
        .iter()
        .enumerate()
        .map(|(i, r)| (r.source.ip(), records.offsets[i]))
        .collect();
    let dispatch = out.label();
    let move_stack = out.label();
    let invalid = out.label();
    let table_mode = rng.gen_bool(0.5);
    let table_key = rng.r#gen::<u64>();
    let rotation = rng.gen_range(1..64u32);
    let mut fields = [0, 1, 2, 3];
    fields.shuffle(&mut rng);
    let header = if rng.gen_bool(0.5) { 0 } else { 8 };
    let mut aliases = BTreeMap::<Opcode, Vec<u8>>::new();
    let mut handlers = Vec::new();
    for record in &program.records {
        aliases.entry(record.opcode).or_default();
    }
    for (&opcode, codes) in &mut aliases {
        for _ in 0..rng.gen_range(2..=4) {
            let code = u8::try_from(handlers.len() + 1)?;
            handlers.push(Handler { opcode, code, label: out.label() });
            codes.push(code);
        }
    }
    let codes: Vec<u8> = (1..=255).choose_multiple(&mut rng, handlers.len());
    for handler in &mut handlers {
        handler.code = codes[handler.code as usize - 1];
    }
    for values in aliases.values_mut() {
        for code in values {
            *code = codes[*code as usize - 1];
        }
    }
    handlers.shuffle(&mut rng);
    let mut plaintext = vec![0; records.len()];
    rng.fill(&mut plaintext[..]);
    for (i, record) in program.records.iter().enumerate() {
        let bytes = &mut plaintext[records.offsets[i]..records.offsets[i + 1]];
        bytes[header + fields[0]] = *aliases[&record.opcode].choose(&mut rng).unwrap();
        bytes[header + fields[1]] = records.size(i) as u8;
        bytes[header + fields[2]] = record.condition;
        for (j, &operand) in record.operands.iter().enumerate() {
            encode_operand(
                &mut bytes[16 + j * 16..32 + j * 16],
                operand,
                &context,
                record.opcode.kind == Kind::Lea && j == 1,
            );
        }
        if let Some(target) = record.target {
            encode_operand(
                &mut bytes[16..32],
                Operand::Immediate(offsets[&target] as u64),
                &context,
                false,
            );
        }
        if record.opcode.kind == Kind::Call {
            encode_operand(
                &mut bytes[16..32],
                Operand::Immediate(record.source.ip()),
                &context,
                false,
            );
        }
        if let Some((operand, value)) = record.extra {
            encode_operand(&mut bytes[48..64], operand, &context, false);
            bytes[56..64].copy_from_slice(&value.to_le_bytes());
        }
    }
    let encrypted = EncryptedString::new(&plaintext)?;
    let keys = out.data(encrypted.keys);
    let nonce = out.data(encrypted.nonce.to_vec());
    let bytecode = out.data(encrypted.ciphertext);
    let table = out.data(vec![0; 256 * 8]);
    let anchors: Vec<_> = options
        .anchors
        .iter()
        .map(|&address| Anchor { address, salt: rng.r#gen(), rotation: rng.gen_range(1..64) })
        .collect();
    context.enter(&mut out, &program.frames.rows[&program.records[0].source.ip()])?;
    bind(&mut out, &anchors)?;
    lea(&mut out, Register::RAX, bytecode)?;
    store(&mut out, Register::RSP, BASE, Register::RAX)?;
    store(&mut out, Register::RSP, PC, Register::RAX)?;
    out.bind(dispatch);
    out.unwind(context::row());
    decrypt(&mut out, keys, nonce)?;
    read(
        &mut out,
        Register::R14,
        memory(Register::RSP, PLAINTEXT + header as i64 + fields[0] as i64),
        1,
    )?;
    read(
        &mut out,
        Register::RAX,
        memory(Register::RSP, PLAINTEXT + header as i64 + fields[1] as i64),
        1,
    )?;
    load(&mut out, Register::RDX, Register::RSP, PC)?;
    out.push(Instruction::with2(Code::Add_rm64_r64, Register::RDX, Register::RAX)?);
    store(&mut out, Register::RSP, PC, Register::RDX)?;
    load_operand(&mut out, 16)?;
    store(&mut out, Register::RSP, DEST, Register::RAX)?;
    store(&mut out, Register::RSP, LEFT, Register::R8)?;
    load_operand(&mut out, 32)?;
    store(&mut out, Register::RSP, RIGHT, Register::R8)?;
    if table_mode {
        lea(&mut out, Register::RAX, table)?;
        read(&mut out, Register::R11, indexed(Register::RAX, Register::R14, 8, 0), 8)?;
        load(&mut out, Register::RDX, Register::RSP, HASH)?;
        out.push(Instruction::with2(Code::Xor_rm64_r64, Register::R11, Register::RDX)?);
        constant(&mut out, Register::RDX, table_key)?;
        out.push(Instruction::with2(Code::Xor_rm64_r64, Register::R11, Register::RDX)?);
        out.push(Instruction::with2(Code::Ror_rm64_imm8, Register::R11, rotation)?);
        out.push(Instruction::with2(Code::Add_rm64_r64, Register::R11, Register::RAX)?);
        out.push(Instruction::with1(Code::Jmp_rm64, Register::R11)?);
    } else {
        let mut sorted: Vec<_> = handlers.iter().collect();
        sorted.sort_by_key(|h| h.code);
        tree(&mut out, &sorted, invalid)?;
    }
    let mut calls = BTreeMap::new();
    for record in &program.records {
        if record.opcode.kind == Kind::Call {
            calls.insert(record.source.ip(), (record.source, out.label()));
        }
    }
    for handler in &handlers {
        out.bind(handler.label);
        out.unwind(context::row());
        load(&mut out, Register::R8, Register::RSP, LEFT)?;
        load(&mut out, Register::R9, Register::RSP, RIGHT)?;
        handler_body(
            &mut out,
            handler.opcode,
            &context,
            dispatch,
            move_stack,
            &calls,
            header + fields[2],
        )?;
    }
    for (&address, (instruction, resume)) in &calls {
        out.bind(*resume);
        context.restore(&mut out, &program.frames.rows[&address])?;
        out.push(*instruction);
        let next = instruction.next_ip();
        context.enter(&mut out, &program.frames.rows[&next])?;
        bind(&mut out, &anchors)?;
        lea(&mut out, Register::RAX, bytecode)?;
        store(&mut out, Register::RSP, BASE, Register::RAX)?;
        constant(&mut out, Register::RDX, offsets[&next] as u64)?;
        out.push(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::RDX)?);
        store(&mut out, Register::RSP, PC, Register::RAX)?;
        out.jump(dispatch)?;
    }
    out.bind(move_stack);
    out.unwind(context::row());
    context.move_stack(&mut out, dispatch)?;
    out.bind(invalid);
    out.push(Instruction::with(Code::Ud2));
    let encoded = out.finish(base)?;
    let key_start = (encoded.address(keys)? - base) as usize;
    let table_start = (encoded.address(table)? - base) as usize;
    let start = (encoded.address(bytecode)? - base) as usize;
    let mut code = encoded.code.clone();
    for (i, record) in program.records.iter().enumerate() {
        for (j, operand) in record.operands.iter().enumerate() {
            if let Operand::Memory { displacement, relative: true, .. } = operand {
                let at = records.offsets[i] + 16 + j * 16 + 8;
                let address =
                    options.addresses.get(&record.source.ip()).copied().unwrap_or(*displacement);
                let relative = address.wrapping_sub(base + start as u64).to_le_bytes();
                for k in 0..8 {
                    code[start + at + k] ^= plaintext[at + k] ^ relative[k];
                }
            }
        }
    }
    if table_mode {
        let mut targets = [encoded.address(invalid)?; 256];
        for handler in &handlers {
            targets[handler.code as usize] = encoded.address(handler.label)?;
        }
        for (i, target) in targets.iter().enumerate() {
            let delta = target.wrapping_sub(base + table_start as u64);
            code[table_start + i * 8..table_start + i * 8 + 8]
                .copy_from_slice(&(delta.rotate_left(rotation) ^ table_key).to_le_bytes());
        }
    }
    Ok(Output {
        code,
        bytecode: start..start + records.len(),
        entry_patch: program.records[0].source.ip(),
        sources: program.sources.clone(),
        binding: Binding {
            anchors,
            keys: key_start..key_start + 352,
            tables: if table_mode {
                vec![Range { start: table_start, end: table_start + 2048 }]
            } else {
                Vec::new()
            },
        },
        instructions: program.records.len(),
        handlers: handlers.len(),
        unwind: encoded.unwind,
        moved: BTreeMap::new(),
    })
}

fn encode_operand(bytes: &mut [u8], operand: Operand, context: &Context, address: bool) {
    bytes.fill(0);
    let (tag, base, index, scale, width, value) = match operand {
        Operand::None => (0, 255, 255, 1, 8, 0),
        Operand::Register { index, high, width } => {
            (1, context.slot(index) as u8 + u8::from(high), 255, 1, width, 0)
        }
        Operand::Immediate(value) => (2, 255, 255, 1, 8, value),
        Operand::Memory { base, index, scale, displacement, relative, width } => (
            if address {
                5
            } else if relative {
                4
            } else {
                3
            },
            base.map_or(255, |r| context.slot(r) as u8),
            index.map_or(255, |r| context.slot(r) as u8),
            scale,
            width,
            displacement,
        ),
    };
    bytes[..5].copy_from_slice(&[tag, base, index, scale as u8, width as u8]);
    bytes[5] = u8::from(matches!(operand, Operand::Memory { relative: true, .. }));
    bytes[8..16].copy_from_slice(&value.to_le_bytes());
}

fn bind(out: &mut Emitter, anchors: &[Anchor]) -> Result<()> {
    constant(out, Register::R10, 0)?;
    for anchor in anchors {
        read(out, Register::R11, memory(Register::RIP, anchor.address as i64), 4)?;
        out.push(Instruction::with2(Code::Xor_rm64_r64, Register::R10, Register::R11)?);
        out.push(Instruction::with2(Code::Ror_rm64_imm8, Register::R10, anchor.rotation)?);
        constant(out, Register::R11, anchor.salt)?;
        out.push(Instruction::with2(Code::Add_rm64_r64, Register::R10, Register::R11)?);
    }
    store(out, Register::RSP, HASH, Register::R10)?;
    Ok(())
}

fn decrypt(out: &mut Emitter, keys: Label, nonce: Label) -> Result<()> {
    use Register::*;
    load(out, R10, RSP, HASH)?;
    out.push(Instruction::with2(Code::Movq_xmm_rm64, XMM3, R10)?);
    out.push(Instruction::with2(Code::Punpcklqdq_xmm_xmmm128, XMM3, XMM3)?);
    for block in 0..4i64 {
        lea(out, RAX, nonce)?;
        out.push(Instruction::with2(Code::Movdqu_xmm_xmmm128, XMM0, memory(RAX, 0))?);
        out.push(Instruction::with2(Code::Movdqu_xmm_xmmm128, XMM1, memory(RAX, 16))?);
        out.push(Instruction::with2(Code::Pxor_xmm_xmmm128, XMM0, XMM1)?);
        out.push(Instruction::with2(Code::Movdqu_xmmm128_xmm, memory(RSP, LEFT), XMM0)?);
        load(out, R8, RSP, LEFT)?;
        load(out, R9, RSP, RIGHT)?;
        out.push(Instruction::with1(Code::Bswap_r64, R8)?);
        out.push(Instruction::with1(Code::Bswap_r64, R9)?);
        load(out, R10, RSP, PC)?;
        load(out, R11, RSP, BASE)?;
        out.push(Instruction::with2(Code::Sub_rm64_r64, R10, R11)?);
        out.push(Instruction::with2(Code::Shr_rm64_imm8, R10, 4u32)?);
        out.push(Instruction::with2(Code::Add_rm64_imm8, R10, block as i32)?);
        out.push(Instruction::with2(Code::Add_rm64_r64, R9, R10)?);
        out.push(Instruction::with2(Code::Adc_rm64_imm8, R8, 0i32)?);
        out.push(Instruction::with1(Code::Bswap_r64, R8)?);
        out.push(Instruction::with1(Code::Bswap_r64, R9)?);
        store(out, RSP, LEFT, R8)?;
        store(out, RSP, RIGHT, R9)?;
        out.push(Instruction::with2(Code::Movdqu_xmm_xmmm128, XMM0, memory(RSP, LEFT))?);
        lea(out, RAX, keys)?;
        for round in 0..=10 {
            out.push(Instruction::with2(Code::Movdqu_xmm_xmmm128, XMM1, memory(RAX, round * 32))?);
            out.push(Instruction::with2(
                Code::Movdqu_xmm_xmmm128,
                XMM2,
                memory(RAX, round * 32 + 16),
            )?);
            out.push(Instruction::with2(Code::Pxor_xmm_xmmm128, XMM1, XMM2)?);
            out.push(Instruction::with2(Code::Pxor_xmm_xmmm128, XMM1, XMM3)?);
            out.push(Instruction::with2(
                match round {
                    0 => Code::Pxor_xmm_xmmm128,
                    10 => Code::Aesenclast_xmm_xmmm128,
                    _ => Code::Aesenc_xmm_xmmm128,
                },
                XMM0,
                XMM1,
            )?);
        }
        load(out, RAX, RSP, PC)?;
        out.push(Instruction::with2(Code::Movdqu_xmm_xmmm128, XMM4, memory(RAX, block * 16))?);
        out.push(Instruction::with2(Code::Pxor_xmm_xmmm128, XMM4, XMM0)?);
        out.push(Instruction::with2(
            Code::Movdqu_xmmm128_xmm,
            memory(RSP, PLAINTEXT + block * 16),
            XMM4,
        )?);
    }
    Ok(())
}

fn load_operand(out: &mut Emitter, offset: i64) -> Result<()> {
    use Register::*;
    let done = out.label();
    let immediate = out.label();
    let reg = out.label();
    let base_done = out.label();
    let index_done = out.label();
    let read_value = out.label();
    read(out, RDX, memory(RSP, PLAINTEXT + offset), 1)?;
    compare(out, RDX, 0)?;
    branch(out, Code::Je_rel32_64, immediate)?;
    compare(out, RDX, 2)?;
    branch(out, Code::Je_rel32_64, immediate)?;
    compare(out, RDX, 1)?;
    branch(out, Code::Je_rel32_64, reg)?;
    load(out, RAX, RSP, PLAINTEXT + offset + 8)?;
    read(out, RCX, memory(RSP, PLAINTEXT + offset + 1), 1)?;
    compare(out, RCX, 255)?;
    branch(out, Code::Je_rel32_64, base_done)?;
    read(out, R9, indexed(RSP, RCX, 1, 0), 8)?;
    out.push(Instruction::with2(Code::Add_rm64_r64, RAX, R9)?);
    out.bind(base_done);
    read(out, RCX, memory(RSP, PLAINTEXT + offset + 2), 1)?;
    compare(out, RCX, 255)?;
    branch(out, Code::Je_rel32_64, index_done)?;
    read(out, R9, indexed(RSP, RCX, 1, 0), 8)?;
    read(out, R10, memory(RSP, PLAINTEXT + offset + 3), 1)?;
    out.push(Instruction::with2(Code::Imul_r64_rm64, R9, R10)?);
    out.push(Instruction::with2(Code::Add_rm64_r64, RAX, R9)?);
    out.bind(index_done);
    let absolute = out.label();
    read(out, R10, memory(RSP, PLAINTEXT + offset + 5), 1)?;
    compare(out, R10, 0)?;
    branch(out, Code::Je_rel32_64, absolute)?;
    load(out, R10, RSP, BASE)?;
    out.push(Instruction::with2(Code::Add_rm64_r64, RAX, R10)?);
    out.bind(absolute);
    compare(out, RDX, 5)?;
    branch(out, Code::Jne_rel32_64, read_value)?;
    out.push(Instruction::with2(Code::Mov_r64_rm64, R8, RAX)?);
    out.jump(done)?;
    out.bind(reg);
    read(out, RCX, memory(RSP, PLAINTEXT + offset + 1), 1)?;
    out.push(Instruction::with2(Code::Lea_r64_m, RAX, indexed(RSP, RCX, 1, 0))?);
    out.bind(read_value);
    read(out, RDX, memory(RSP, PLAINTEXT + offset + 4), 1)?;
    for width in [1, 2, 4, 8] {
        let next = out.label();
        compare(out, RDX, width)?;
        branch(out, Code::Jne_rel32_64, next)?;
        read(out, R8, memory(RAX, 0), width as usize)?;
        out.jump(done)?;
        out.bind(next);
    }
    out.push(Instruction::with(Code::Ud2));
    out.bind(immediate);
    load(out, R8, RSP, PLAINTEXT + offset + 8)?;
    constant(out, RAX, 0)?;
    out.bind(done);
    Ok(())
}

fn tree(out: &mut Emitter, handlers: &[&Handler], invalid: Label) -> Result<()> {
    if handlers.is_empty() {
        out.jump(invalid)?;
        return Ok(());
    }
    let middle = handlers.len() / 2;
    let upper = out.label();
    compare(out, Register::R14, i32::from(handlers[middle].code))?;
    branch(out, Code::Je_rel32_64, handlers[middle].label)?;
    branch(out, Code::Ja_rel32_64, upper)?;
    tree(out, &handlers[..middle], invalid)?;
    out.bind(upper);
    tree(out, &handlers[middle + 1..], invalid)
}

fn result(
    out: &mut Emitter,
    context: &Context,
    width: usize,
    descriptor: i64,
    dispatch: Label,
    move_stack: Label,
    finish: bool,
) -> Result<()> {
    use Register::*;
    load(out, RAX, RSP, DEST)?;
    if width == 4 {
        let memory_target = out.label();
        let done = out.label();
        read(out, RDX, memory(RSP, PLAINTEXT + descriptor), 1)?;
        compare(out, RDX, 1)?;
        branch(out, Code::Jne_rel32_64, memory_target)?;
        out.push(Instruction::with2(Code::Mov_r32_rm32, R8D, R8D)?);
        write(out, memory(RAX, 0), R8, 8)?;
        out.jump(done)?;
        out.bind(memory_target);
        write(out, memory(RAX, 0), R8, 4)?;
        out.bind(done);
    } else {
        write(out, memory(RAX, 0), R8, width)?;
    }
    if finish {
        read(out, RDX, memory(RSP, PLAINTEXT + descriptor), 1)?;
        compare(out, RDX, 1)?;
        let normal = out.label();
        branch(out, Code::Jne_rel32_64, normal)?;
        read(out, RDX, memory(RSP, PLAINTEXT + descriptor + 1), 1)?;
        compare(out, RDX, context.slot(4) as i32)?;
        branch(out, Code::Je_rel32_64, move_stack)?;
        out.bind(normal);
        out.jump(dispatch)?;
    }
    Ok(())
}

fn handler_body(
    out: &mut Emitter,
    opcode: Opcode,
    context: &Context,
    dispatch: Label,
    move_stack: Label,
    calls: &BTreeMap<u64, (Instruction, Label)>,
    condition: usize,
) -> Result<()> {
    use Register::*;
    let width = opcode.width;
    let lhs = sized(R8, width);
    let rhs = sized(R9, width);
    match opcode.kind {
        Kind::Mov | Kind::Movzx | Kind::Lea | Kind::MovPair => {
            out.push(Instruction::with2(Code::Mov_r64_rm64, R8, R9)?);
            if opcode.kind == Kind::MovPair {
                result(out, context, width, 16, dispatch, move_stack, false)?;
                read(out, RAX, memory(RSP, PLAINTEXT + 49), 1)?;
                out.push(Instruction::with2(Code::Lea_r64_m, RAX, indexed(RSP, RAX, 1, 0))?);
                store(out, RSP, DEST, RAX)?;
                load(out, R8, RSP, PLAINTEXT + 56)?;
                result(out, context, width, 48, dispatch, move_stack, true)?;
            } else {
                result(out, context, width, 16, dispatch, move_stack, true)?;
            }
        }
        Kind::Movsx => {
            read(out, RDX, memory(RSP, PLAINTEXT + 36), 1)?;
            let done = out.label();
            for source_width in [1, 2, 4] {
                let next = out.label();
                compare(out, RDX, source_width)?;
                branch(out, Code::Jne_rel32_64, next)?;
                out.push(Instruction::with2(
                    match source_width {
                        1 => Code::Movsx_r64_rm8,
                        2 => Code::Movsx_r64_rm16,
                        _ => Code::Movsxd_r64_rm32,
                    },
                    R8,
                    sized(R9, source_width as usize),
                )?);
                out.jump(done)?;
                out.bind(next);
            }
            out.push(Instruction::with(Code::Ud2));
            out.bind(done);
            result(out, context, width, 16, dispatch, move_stack, true)?;
        }
        Kind::ImulImm => {
            // dest = src * imm; src is in r9
            let index = match width {
                2 => 1,
                4 => 2,
                _ => 3,
            };
            load(out, RAX, RSP, PLAINTEXT + 56)?;
            out.push(Instruction::with2(Code::Mov_r64_rm64, R8, R9)?);
            let code =
                [Code::INVALID, Code::Imul_r16_rm16, Code::Imul_r32_rm32, Code::Imul_r64_rm64]
                    [index];
            out.push(Instruction::with2(code, lhs, sized(RAX, width))?);
            context::flags(out, true, context.precise)?;
            result(out, context, width, 16, dispatch, move_stack, true)?;
        }
        Kind::Cmov => {
            let codes = cmov_codes(width);
            let apply = out.label();
            for (i, &code) in codes.iter().enumerate() {
                let next = out.label();
                read(out, RDX, memory(RSP, PLAINTEXT + condition as i64), 1)?;
                compare(out, RDX, i as i32 + 1)?;
                branch(out, Code::Jne_rel32_64, next)?;
                context::flags(out, false, context.precise)?;
                out.push(Instruction::with2(code, lhs, rhs)?);
                out.jump(apply)?;
                out.bind(next);
            }
            out.push(Instruction::with(Code::Ud2));
            out.bind(apply);
            result(out, context, width, 16, dispatch, move_stack, true)?;
        }
        Kind::Add
        | Kind::Sub
        | Kind::And
        | Kind::Or
        | Kind::Xor
        | Kind::Cmp
        | Kind::Test
        | Kind::Imul
        | Kind::Inc
        | Kind::Dec
        | Kind::Neg
        | Kind::Not
        | Kind::Shl
        | Kind::Shr
        | Kind::Sar
        | Kind::Rol
        | Kind::Ror => {
            context::flags(out, false, context.precise)?;
            let index = match width {
                1 => 0,
                2 => 1,
                4 => 2,
                _ => 3,
            };
            let code = match opcode.kind {
                Kind::Add => {
                    [Code::Add_rm8_r8, Code::Add_rm16_r16, Code::Add_rm32_r32, Code::Add_rm64_r64]
                        [index]
                }
                Kind::Sub => {
                    [Code::Sub_rm8_r8, Code::Sub_rm16_r16, Code::Sub_rm32_r32, Code::Sub_rm64_r64]
                        [index]
                }
                Kind::And => {
                    [Code::And_rm8_r8, Code::And_rm16_r16, Code::And_rm32_r32, Code::And_rm64_r64]
                        [index]
                }
                Kind::Or => {
                    [Code::Or_rm8_r8, Code::Or_rm16_r16, Code::Or_rm32_r32, Code::Or_rm64_r64]
                        [index]
                }
                Kind::Xor => {
                    [Code::Xor_rm8_r8, Code::Xor_rm16_r16, Code::Xor_rm32_r32, Code::Xor_rm64_r64]
                        [index]
                }
                Kind::Cmp => {
                    [Code::Cmp_rm8_r8, Code::Cmp_rm16_r16, Code::Cmp_rm32_r32, Code::Cmp_rm64_r64]
                        [index]
                }
                Kind::Test => [
                    Code::Test_rm8_r8,
                    Code::Test_rm16_r16,
                    Code::Test_rm32_r32,
                    Code::Test_rm64_r64,
                ][index],
                Kind::Imul => {
                    [Code::INVALID, Code::Imul_r16_rm16, Code::Imul_r32_rm32, Code::Imul_r64_rm64]
                        [index]
                }
                Kind::Inc => [Code::Inc_rm8, Code::Inc_rm16, Code::Inc_rm32, Code::Inc_rm64][index],
                Kind::Dec => [Code::Dec_rm8, Code::Dec_rm16, Code::Dec_rm32, Code::Dec_rm64][index],
                Kind::Neg => [Code::Neg_rm8, Code::Neg_rm16, Code::Neg_rm32, Code::Neg_rm64][index],
                Kind::Not => [Code::Not_rm8, Code::Not_rm16, Code::Not_rm32, Code::Not_rm64][index],
                Kind::Shl => {
                    [Code::Shl_rm8_CL, Code::Shl_rm16_CL, Code::Shl_rm32_CL, Code::Shl_rm64_CL]
                        [index]
                }
                Kind::Shr => {
                    [Code::Shr_rm8_CL, Code::Shr_rm16_CL, Code::Shr_rm32_CL, Code::Shr_rm64_CL]
                        [index]
                }
                Kind::Sar => {
                    [Code::Sar_rm8_CL, Code::Sar_rm16_CL, Code::Sar_rm32_CL, Code::Sar_rm64_CL]
                        [index]
                }
                Kind::Rol => {
                    [Code::Rol_rm8_CL, Code::Rol_rm16_CL, Code::Rol_rm32_CL, Code::Rol_rm64_CL]
                        [index]
                }
                _ => [Code::Ror_rm8_CL, Code::Ror_rm16_CL, Code::Ror_rm32_CL, Code::Ror_rm64_CL]
                    [index],
            };
            if matches!(opcode.kind, Kind::Inc | Kind::Dec | Kind::Neg | Kind::Not) {
                out.push(Instruction::with1(code, lhs)?);
            } else if matches!(
                opcode.kind,
                Kind::Shl | Kind::Shr | Kind::Sar | Kind::Rol | Kind::Ror
            ) {
                out.push(Instruction::with2(Code::Mov_r64_rm64, RCX, R9)?);
                out.push(Instruction::with2(code, lhs, Register::CL)?);
            } else {
                out.push(Instruction::with2(code, lhs, rhs)?);
            }
            context::flags(out, true, context.precise)?;
            if matches!(opcode.kind, Kind::Cmp | Kind::Test) {
                out.jump(dispatch)?;
            } else {
                result(out, context, width, 16, dispatch, move_stack, true)?;
            }
        }
        Kind::Push => {
            load(out, RAX, RSP, context.slot(4))?;
            out.push(Instruction::with2(Code::Lea_r64_m, RAX, memory(RAX, -8))?);
            store(out, RAX, 0, R8)?;
            store(out, RSP, context.slot(4), RAX)?;
            out.jump(move_stack)?;
        }
        Kind::Pop => {
            load(out, RAX, RSP, context.slot(4))?;
            load(out, R8, RAX, 0)?;
            result(out, context, 8, 16, dispatch, move_stack, false)?;
            load(out, RAX, RSP, context.slot(4))?;
            out.push(Instruction::with2(Code::Lea_r64_m, RAX, memory(RAX, 8))?);
            store(out, RSP, context.slot(4), RAX)?;
            out.jump(move_stack)?;
        }
        Kind::Leave => {
            load(out, RAX, RSP, context.slot(5))?;
            load(out, R8, RAX, 0)?;
            store(out, RSP, context.slot(5), R8)?;
            out.push(Instruction::with2(Code::Lea_r64_m, RAX, memory(RAX, 8))?);
            store(out, RSP, context.slot(4), RAX)?;
            out.jump(move_stack)?;
        }
        Kind::Jump => jump_guest(out, dispatch)?,
        Kind::Condition => {
            let codes = [
                Code::Jo_rel32_64,
                Code::Jno_rel32_64,
                Code::Jb_rel32_64,
                Code::Jae_rel32_64,
                Code::Je_rel32_64,
                Code::Jne_rel32_64,
                Code::Jbe_rel32_64,
                Code::Ja_rel32_64,
                Code::Js_rel32_64,
                Code::Jns_rel32_64,
                Code::Jp_rel32_64,
                Code::Jnp_rel32_64,
                Code::Jl_rel32_64,
                Code::Jge_rel32_64,
                Code::Jle_rel32_64,
                Code::Jg_rel32_64,
            ];
            let taken = out.label();
            for (i, code) in codes.iter().enumerate() {
                let next = out.label();
                read(out, RDX, memory(RSP, PLAINTEXT + condition as i64), 1)?;
                compare(out, RDX, i as i32 + 1)?;
                branch(out, Code::Jne_rel32_64, next)?;
                context::flags(out, false, context.precise)?;
                branch(out, *code, taken)?;
                out.jump(dispatch)?;
                out.bind(next);
            }
            out.push(Instruction::with(Code::Ud2));
            out.bind(taken);
            jump_guest(out, dispatch)?;
        }
        Kind::Call => {
            for (&site, (_, label)) in calls {
                constant(out, RAX, site)?;
                out.push(Instruction::with2(Code::Cmp_rm64_r64, R8, RAX)?);
                branch(out, Code::Je_rel32_64, *label)?;
            }
            out.push(Instruction::with(Code::Ud2));
        }
        Kind::Return => {
            context.restore(out, &Row::leaf())?;
            out.push(Instruction::with(Code::Retnq));
        }
        Kind::Nop => out.jump(dispatch)?,
    }
    Ok(())
}

fn cmov_codes(width: usize) -> [Code; 16] {
    match width {
        2 => [
            Code::Cmovo_r16_rm16,
            Code::Cmovno_r16_rm16,
            Code::Cmovb_r16_rm16,
            Code::Cmovae_r16_rm16,
            Code::Cmove_r16_rm16,
            Code::Cmovne_r16_rm16,
            Code::Cmovbe_r16_rm16,
            Code::Cmova_r16_rm16,
            Code::Cmovs_r16_rm16,
            Code::Cmovns_r16_rm16,
            Code::Cmovp_r16_rm16,
            Code::Cmovnp_r16_rm16,
            Code::Cmovl_r16_rm16,
            Code::Cmovge_r16_rm16,
            Code::Cmovle_r16_rm16,
            Code::Cmovg_r16_rm16,
        ],
        4 => [
            Code::Cmovo_r32_rm32,
            Code::Cmovno_r32_rm32,
            Code::Cmovb_r32_rm32,
            Code::Cmovae_r32_rm32,
            Code::Cmove_r32_rm32,
            Code::Cmovne_r32_rm32,
            Code::Cmovbe_r32_rm32,
            Code::Cmova_r32_rm32,
            Code::Cmovs_r32_rm32,
            Code::Cmovns_r32_rm32,
            Code::Cmovp_r32_rm32,
            Code::Cmovnp_r32_rm32,
            Code::Cmovl_r32_rm32,
            Code::Cmovge_r32_rm32,
            Code::Cmovle_r32_rm32,
            Code::Cmovg_r32_rm32,
        ],
        _ => [
            Code::Cmovo_r64_rm64,
            Code::Cmovno_r64_rm64,
            Code::Cmovb_r64_rm64,
            Code::Cmovae_r64_rm64,
            Code::Cmove_r64_rm64,
            Code::Cmovne_r64_rm64,
            Code::Cmovbe_r64_rm64,
            Code::Cmova_r64_rm64,
            Code::Cmovs_r64_rm64,
            Code::Cmovns_r64_rm64,
            Code::Cmovp_r64_rm64,
            Code::Cmovnp_r64_rm64,
            Code::Cmovl_r64_rm64,
            Code::Cmovge_r64_rm64,
            Code::Cmovle_r64_rm64,
            Code::Cmovg_r64_rm64,
        ],
    }
}

fn jump_guest(out: &mut Emitter, dispatch: Label) -> Result<()> {
    load(out, Register::RAX, Register::RSP, BASE)?;
    out.push(Instruction::with2(Code::Add_rm64_r64, Register::RAX, Register::R8)?);
    store(out, Register::RSP, PC, Register::RAX)?;
    out.jump(dispatch)
}
