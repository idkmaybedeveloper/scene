use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand, Register,
};

#[derive(Clone, Copy)]
pub struct Label(usize);

pub struct Emitter {
    insns: Vec<Instruction>,
    labels: Vec<Option<usize>>,
    branches: Vec<(usize, Label)>,
    references: Vec<(usize, Label)>,
    vectors: BTreeMap<[u8; 16], Label>,
    moved: BTreeMap<u64, Label>,
}

pub struct Encoded {
    pub code: Vec<u8>,
    pub moved: BTreeMap<u64, u64>,
    base: u64,
    labels: Vec<usize>,
    offsets: Vec<u32>,
}

impl Encoded {
    pub fn address(&self, label: Label) -> Result<u64> {
        let offset = self.offsets[self.labels[label.0]];
        ensure!(offset != u32::MAX, "label points to an expanded instruction");
        Ok(self.base + offset as u64)
    }
}

impl Emitter {
    pub fn new() -> Self {
        Self {
            insns: Vec::new(),
            labels: Vec::new(),
            branches: Vec::new(),
            references: Vec::new(),
            vectors: BTreeMap::new(),
            moved: BTreeMap::new(),
        }
    }

    pub fn label(&mut self) -> Label {
        let label = Label(self.labels.len());
        self.labels.push(None);
        label
    }

    pub fn bind(&mut self, label: Label) {
        self.labels[label.0] = Some(self.insns.len());
        self.push(Instruction::with(Code::Nopd));
    }

    pub fn push(&mut self, insn: Instruction) {
        self.insns.push(insn);
    }

    pub fn record(&mut self, address: u64) {
        let label = self.label();
        self.bind(label);
        self.moved.insert(address, label);
    }

    pub fn jump(&mut self, label: Label) -> Result<()> {
        self.branch(Instruction::with_branch(Code::Jmp_rel32_64, 0)?, label);
        Ok(())
    }

    pub fn jump_to(&mut self, address: u64) -> Result<()> {
        self.push(Instruction::with_branch(Code::Jmp_rel32_64, address)?);
        Ok(())
    }

    pub fn branch(&mut self, insn: Instruction, label: Label) {
        self.branches.push((self.insns.len(), label));
        self.push(insn);
    }

    pub fn vector(&mut self, register: Register, value: [u8; 16]) -> Result<()> {
        let label = if let Some(&label) = self.vectors.get(&value) {
            label
        } else {
            let label = self.label();
            self.vectors.insert(value, label);
            label
        };
        self.references.push((self.insns.len(), label));
        self.push(Instruction::with2(
            Code::Movdqu_xmm_xmmm128,
            register,
            MemoryOperand::with_base_displ(Register::RIP, 0),
        )?);
        Ok(())
    }

    pub fn finish(mut self, base: u64) -> Result<Encoded> {
        for (value, label) in std::mem::take(&mut self.vectors) {
            self.labels[label.0] = Some(self.insns.len());
            self.push(Instruction::with_declare_byte(&value)?);
        }
        let labels: Vec<_> = self
            .labels
            .into_iter()
            .map(|i| i.context("unbound x86 label"))
            .collect::<Result<_>>()?;
        let address = |index| 0x8000_0000_0000_0000 + index as u64 * 16;
        for (index, insn) in self.insns.iter_mut().enumerate() {
            insn.set_ip(address(index));
        }
        for (index, label) in self.branches {
            self.insns[index].set_near_branch64(address(labels[label.0]));
        }
        for (index, label) in self.references {
            self.insns[index].set_memory_displacement64(address(labels[label.0]));
        }
        let encoded = BlockEncoder::encode(
            64,
            InstructionBlock::new(&self.insns, base),
            BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS
                | BlockEncoderOptions::RETURN_RELOC_INFOS,
        )
        .context("encoding x86 control flow")?;
        ensure!(encoded.reloc_infos.is_empty(), "x86 relocation requires absolute branch pointers");
        let mut result = Encoded {
            code: encoded.code_buffer,
            moved: BTreeMap::new(),
            base,
            labels,
            offsets: encoded.new_instruction_offsets,
        };
        for (address, label) in self.moved {
            result.moved.insert(address, result.address(label)?);
        }
        Ok(result)
    }
}
