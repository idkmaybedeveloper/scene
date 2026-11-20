use anyhow::Result;
use dynasmrt::{DynasmLabelApi, dynasm};

use super::{
    Options,
    cfg::{Destination, Exit, Function},
    emit::{Emitter, Label},
    emit_body,
};

pub fn emit(
    function: &Function<'_>,
    labels: &[Label],
    out: &mut Emitter,
    options: Options,
) -> Result<()> {
    let dispatcher = out.label();
    let gates: Vec<_> = labels.iter().map(|_| out.label()).collect();
    let state = |index: usize| (index as u32).wrapping_mul(0x9E37_79B1).wrapping_add(options.seed);
    let key = options.seed.rotate_left(13) ^ 0xA53C_9E71;
    transition(out, state(0), key, dispatcher);

    for index in (0..function.blocks.len()).rev() {
        let block = &function.blocks[index];
        out.bind(labels[index]);
        emit_body(out, &function.insns[block.body.clone()], options.mba)?;
        match block.exit {
            Exit::Raw(word) => out.raw(word),
            Exit::Tail(address) => out.jump_to(address),
            Exit::Jump(next) => transition(out, state(next), key, dispatcher),
            Exit::Call { site, next, bridge } => {
                out.jump_to(site);
                if bridge {
                    out.resume(site + 4);
                    transition(out, state(next), key, dispatcher);
                }
            }
            Exit::Conditional { word, taken, fallthrough } => {
                let taken_edge = out.label();
                out.branch(word, taken_edge);
                transition(out, state(fallthrough), key, dispatcher);
                out.bind(taken_edge);
                match taken {
                    Destination::Block(next) => transition(out, state(next), key, dispatcher),
                    Destination::Address(address) => out.jump_to(address),
                }
            }
        }
    }

    out.bind(dispatcher);
    dynasm!(out.asm; .arch aarch64; eor v30.b16, v30.b16, v31.b16);
    for (index, &gate) in gates.iter().enumerate() {
        out.constant(16, state(index));
        dynasm!(out.asm
            ; .arch aarch64
            ; dup v31.d2, x16
            ; cmeq v31.d2, v30.d2, v31.d2
            ; umov x16, v31.d[0]
            ; tbnz x16, 0, =>gate
        );
    }
    dynasm!(out.asm; .arch aarch64; brk 0);

    for (index, &gate) in gates.iter().enumerate() {
        out.bind(gate);
        dynasm!(out.asm
            ; .arch aarch64
            ; ldp q30, q31, [sp, 16]
            ; ldp x16, x17, [sp], 176
        );
        out.jump(labels[index]);
    }
    Ok(())
}

// transition............
fn transition(out: &mut Emitter, state: u32, key: u32, dispatcher: Label) {
    dynasm!(out.asm
        ; .arch aarch64
        ; stp x16, x17, [sp, -176]!
        ; stp q30, q31, [sp, 16]
    );
    out.constant(16, state);
    out.constant(17, key);
    dynasm!(out.asm
        ; .arch aarch64
        ; dup v30.d2, x16
        ; dup v31.d2, x17
        ; eor v30.b16, v30.b16, v31.b16
        ; b =>dispatcher
    );
}
