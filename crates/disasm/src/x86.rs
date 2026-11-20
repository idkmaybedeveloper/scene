use std::{fmt, ops::Range};

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

#[derive(Clone, Debug)]
pub enum Insn {
    Decoded(Instruction),
    Raw { address: u64, bytes: Vec<u8> },
}

impl Insn {
    pub fn address(&self) -> u64 {
        match self {
            Insn::Decoded(insn) => insn.ip(),
            Insn::Raw { address, .. } => *address,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Insn::Decoded(insn) => insn.len(),
            Insn::Raw { bytes, .. } => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub fn decode(bitness: u32, code: &[u8], base: u64, data: &[Range<u64>]) -> Vec<Insn> {
    let end = base + code.len() as u64;
    let bytes =
        |range: Range<u64>| &code[(range.start - base) as usize..(range.end - base) as usize];
    let mut data: Vec<_> =
        data.iter().map(|d| d.start.max(base)..d.end.min(end)).filter(|d| !d.is_empty()).collect();
    data.sort_by_key(|d| d.start);

    let mut insns = Vec::new();
    let mut cursor = base;
    for range in data {
        if range.start > cursor {
            decode_code(bitness, bytes(cursor..range.start), cursor, &mut insns);
        }
        let start = range.start.max(cursor);
        if range.end > start {
            insns.push(Insn::Raw { address: start, bytes: bytes(start..range.end).to_vec() });
            cursor = range.end;
        }
    }
    if cursor < end {
        decode_code(bitness, bytes(cursor..end), cursor, &mut insns);
    }
    insns
}

fn decode_code(bitness: u32, code: &[u8], base: u64, insns: &mut Vec<Insn>) {
    let mut decoder = Decoder::with_ip(bitness, code, base, DecoderOptions::NONE);
    while decoder.can_decode() {
        let start = decoder.position();
        let insn = decoder.decode();
        if !insn.is_invalid() {
            insns.push(Insn::Decoded(insn));
            continue;
        }
        let mut end = decoder.position();
        if end <= start {
            end = start + 1;
            decoder.set_position(end).expect("position inside code");
        }
        insns.push(Insn::Raw { address: base + start as u64, bytes: code[start..end].to_vec() });
    }
}

pub(crate) fn fmt_listing(insns: &[Insn], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut formatter = IntelFormatter::new();
    let mut text = String::new();
    for insn in insns {
        match insn {
            Insn::Decoded(insn) => {
                text.clear();
                formatter.format(insn, &mut text);
                writeln!(f, "{:016x}  {text}", insn.ip())?;
            }
            Insn::Raw { address, bytes } => writeln!(f, "{address:016x}  db {bytes:02x?}")?,
        }
    }
    Ok(())
}
