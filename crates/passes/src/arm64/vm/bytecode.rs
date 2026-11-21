use scene_disasm::arm64::Insn;

pub const RECORD_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Move,
    MovePair,
    Keep,
    Jump,
    Condition,
    Zero,
    Bit,
    Return,
    Nop,
    Address,
    Call,
    Load,
    Store,
    LoadPair,
    StorePair,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Opcode {
    pub kind: Kind,
    pub wide: bool,
    pub flags: bool,
}

#[derive(Clone)]
pub struct Record {
    pub opcode: Opcode,
    pub dst: u8,
    pub lhs: u8,
    pub rhs: u8,
    pub aux: u32,
    pub immediate: u64,
    pub target: Option<u64>,
    pub extra: u64,
}

impl std::fmt::Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let width = if self.opcode.wide { 64 } else { 32 };
        let flags = if self.opcode.flags { "+nzcv" } else { "" };
        match self.opcode.kind {
            Kind::Jump => write!(f, "jmp {:#x}", self.immediate),
            Kind::Condition => {
                let condition = [
                    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt",
                    "le", "al", "nv",
                ][self.aux as usize];
                write!(f, "j{condition} nzcv -> {:#x}", self.immediate)
            }
            Kind::Zero => write!(
                f,
                "j{}z.{width} v{} -> {:#x}",
                if self.aux == 0 { "" } else { "n" },
                self.lhs,
                self.immediate
            ),
            Kind::Bit => write!(
                f,
                "tb{}z v{}, #{} -> {:#x}",
                if self.aux & 256 == 0 { "" } else { "n" },
                self.lhs,
                self.aux & 63,
                self.immediate
            ),
            Kind::Return => f.write_str("exit -> ret x30"),
            Kind::Nop => f.write_str("nop"),
            Kind::MovePair => write!(
                f,
                "mov2.{width} v{}, {:#x}; v{}, {:#x}",
                self.dst,
                self.immediate,
                self.aux >> 16,
                self.extra
            ),
            Kind::Address => write!(f, "addr v{}, bytecode_base + {:#x}", self.dst, self.immediate),
            Kind::Call => write!(f, "call native site #{}", self.immediate),
            Kind::Load | Kind::Store => write!(
                f,
                "{:?}.{width} v{}, [v{}, {:+#x}]",
                self.opcode.kind, self.dst, self.lhs, self.immediate as i64
            ),
            Kind::LoadPair | Kind::StorePair => write!(
                f,
                "{:?}.{width} v{}, v{}, [v{}, {:+#x}]",
                self.opcode.kind, self.dst, self.rhs, self.lhs, self.immediate as i64
            ),
            Kind::Move | Kind::Keep => write!(
                f,
                "{:?}.{width} v{}, {:#x}, shift={}",
                self.opcode.kind, self.dst, self.immediate, self.aux
            ),
            kind => {
                write!(f, "{kind:?}.{width}{flags} v{}, v{}, ", self.dst, self.lhs)?;
                if self.rhs == 255 {
                    write!(f, "{:#x}", self.immediate)?;
                } else {
                    write!(f, "v{}", self.rhs)?;
                }
                if self.aux & 255 != 0 {
                    let shift = ["lsl", "lsr", "asr", "ror"][(self.aux & 3) as usize];
                    write!(f, " {shift} #{}", self.aux >> 2 & 63)?;
                }
                if self.aux & 256 != 0 {
                    f.write_str(" inverted")?;
                }
                Ok(())
            }
        }
    }
}

impl Record {
    pub fn new(kind: Kind, wide: bool) -> Self {
        Self {
            opcode: Opcode { kind, wide, flags: false },
            dst: 0,
            lhs: 31,
            rhs: 31,
            aux: 0,
            immediate: 0,
            target: None,
            extra: 0,
        }
    }
}

pub struct Program {
    pub records: Vec<Record>,
    pub sources: Vec<Insn>,
    pub entry_patch: u64,
    pub elided: Vec<u64>,
}
