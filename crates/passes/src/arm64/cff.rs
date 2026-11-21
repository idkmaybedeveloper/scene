use aes::{
    Aes128, Block,
    cipher::{BlockEncrypt, KeyInit},
};
use anyhow::Result;
use dynasmrt::{DynasmLabelApi, dynasm};

use super::{
    Options,
    cfg::{Destination, Exit, Function},
    emit::{Emitter, Label},
    emit_body,
};

struct State {
    input: [u8; 16],
    tag: [u8; 16],
    gate: Label,
}

impl State {
    fn order(&self) -> u32 {
        u32::from_le_bytes(self.tag[12..].try_into().unwrap())
    }
}

pub fn emit(
    function: &Function<'_>,
    labels: &[Label],
    out: &mut Emitter,
    options: Options,
) -> Result<()> {
    let dispatcher = out.label();
    let key: [u8; 16] =
        std::array::from_fn(|i| (options.seed.rotate_left((i * 7) as u32) >> (i % 4 * 8)) as u8);
    let cipher = Aes128::new(&key.into());
    let decoys = match options.cff {
        0 | 1 => 0,
        level => (labels.len() * (level as usize - 1) / 2).min(512),
    };
    let states: Vec<_> = (0..labels.len() + decoys)
        .map(|index| {
            let mut input = Block::from((index as u128).to_le_bytes());
            cipher.encrypt_block(&mut input);
            let mut tag = input;
            for (byte, key) in tag.iter_mut().zip(key) {
                *byte ^= key;
            }
            aes::hazmat::cipher_round(&mut tag, &Block::default());
            State { input: input.into(), tag: tag.into(), gate: out.label() }
        })
        .collect();
    transition(out, &states[0], key, dispatcher);

    for index in (0..function.blocks.len()).rev() {
        let block = &function.blocks[index];
        out.bind(labels[index]);
        emit_body(out, &function.insns[block.body.clone()], options.mba)?;
        if let Some(address) = block.exit_address {
            out.record(address);
        }
        match block.exit {
            Exit::Raw(word) => out.raw(word),
            Exit::Tail(address) => out.jump_to(address),
            Exit::Jump(next) => transition(out, &states[next], key, dispatcher),
            Exit::Call { site, next, bridge } => {
                out.jump_to(site);
                if bridge {
                    out.resume(site + 4);
                    transition(out, &states[next], key, dispatcher);
                }
            }
            Exit::Conditional { word, taken, fallthrough } => {
                let taken_edge = out.label();
                out.branch(word, taken_edge);
                transition(out, &states[fallthrough], key, dispatcher);
                out.bind(taken_edge);
                match taken {
                    Destination::Block(next) => transition(out, &states[next], key, dispatcher),
                    Destination::Address(address) => out.jump_to(address),
                }
            }
        }
    }

    out.bind(dispatcher);
    let mut ordered: Vec<_> = states.iter().collect();
    ordered.sort_unstable_by_key(|s| s.order());
    let invalid = out.label();
    dispatch(out, &ordered, invalid);
    out.bind(invalid);
    dynasm!(out.asm; .arch aarch64; brk 0);

    for (state, &label) in states.iter().zip(labels) {
        out.bind(state.gate);
        dynasm!(out.asm
            ; .arch aarch64
            ; ldp q30, q31, [sp, 16]
            ; ldp x16, x17, [sp], 176
        );
        out.jump(label);
    }
    // decoy gates mirror the real ones so they cant be told apart by shape
    for (offset, state) in states[labels.len()..].iter().enumerate() {
        out.bind(state.gate);
        dynasm!(out.asm
            ; .arch aarch64
            ; ldp q30, q31, [sp, 16]
            ; ldp x16, x17, [sp], 176
        );
        out.jump(labels[offset % labels.len()]);
    }
    Ok(())
}

fn dispatch(out: &mut Emitter, states: &[&State], invalid: Label) {
    let middle = states.len() / 2;
    let split = states.partition_point(|s| s.order() <= states[middle].order());
    if split < states.len() {
        let right = out.label();
        out.vector(31, states[middle].tag);
        dynasm!(out.asm
            ; .arch aarch64
            ; cmhi v31.s4, v30.s4, v31.s4
            ; umov w16, v31.s[3]
            ; tbnz w16, 0, =>right
        );
        dispatch(out, &states[..split], invalid);
        out.bind(right);
        dispatch(out, &states[split..], invalid);
    } else {
        for state in states {
            out.vector(31, state.tag);
            dynasm!(out.asm
                ; .arch aarch64
                ; cmeq v31.b16, v30.b16, v31.b16
                ; uminv b31, v31.b16
                ; umov w16, v31.b[0]
                ; tbnz w16, 0, =>state.gate
            );
        }
        out.jump(invalid);
    }
}

fn transition(out: &mut Emitter, state: &State, key: [u8; 16], dispatcher: Label) {
    dynasm!(out.asm
        ; .arch aarch64
        ; stp x16, x17, [sp, -176]!
        ; stp q30, q31, [sp, 16]
    );
    out.vector(30, state.input);
    out.vector(31, key);
    dynasm!(out.asm
        ; .arch aarch64
        ; aese v30.b16, v31.b16
        ; aesmc v30.b16, v30.b16
        ; b =>dispatcher
    );
}
