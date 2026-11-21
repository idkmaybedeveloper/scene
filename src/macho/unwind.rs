use anyhow::{Context, Result, ensure};
use gimli::{
    Encoding, Format, LittleEndian, X86_64,
    write::{
        Address, CallFrameInstruction as Cfi, CommonInformationEntry, EhFrame, EndianVec,
        Expression, FrameDescriptionEntry, FrameTable,
    },
};
use iced_x86::Register;
use object::{Object, ObjectSection, ObjectSegment};
use scene_passes::x86::unwind::{Cfa, NONVOLATILE, Row, Rule};

pub struct Section {
    pub address: u64,
    pub data: Vec<u8>,
}

pub struct Unwind {
    address: u64,
    offset: u64,
    capacity: usize,
    data: Vec<u8>,
    new_section: bool,
    count: usize,
    reserved: usize,
    reserved_code: usize,
    shared_code_end: Option<u64>,
}

impl Unwind {
    pub fn new(file: &object::File) -> Result<Self> {
        let text = file
            .segments()
            .find(|s| s.name().ok().flatten() == Some("__TEXT"))
            .context("missing text segment")?;
        let (text_offset, text_size) = text.file_range();
        let last = file
            .sections()
            .filter(|s| s.segment_name().ok().flatten() == Some("__TEXT"))
            .filter_map(|s| s.file_range())
            .map(|(o, n)| o + n)
            .max()
            .context("missing text sections")?;
        let (offset, data, new_section) = if let Some(section) = file.section_by_name("__eh_frame")
        {
            let (offset, size) = section.file_range().context("eh_frame has no file data")?;
            ensure!(offset + size == last, "eh_frame is not the last text section");
            let bytes = section.data()?;
            let mut cursor = 0;
            while cursor + 4 <= bytes.len() {
                let size = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into()?);
                if size == 0 {
                    break;
                }
                ensure!(size != u32::MAX, "64-bit dwarf lengths in eh_frame are unsupported");
                cursor =
                    cursor.checked_add(4 + size as usize).context("invalid eh_frame length")?;
                ensure!(cursor <= bytes.len(), "truncated eh_frame entry");
            }
            (offset, bytes[..cursor].to_vec(), false)
        } else {
            ((last + 7) & !7, Vec::new(), true)
        };
        let end = text_offset + text_size.min(text.size());
        ensure!(offset < end, "no text padding for unwind metadata");
        let padding = text
            .data()?
            .get((last - text_offset) as usize..(end - text_offset) as usize)
            .context("invalid text padding")?;
        ensure!(padding.iter().all(|&b| b == 0), "text padding contains unsectioned data");
        Ok(Self {
            address: text.address() + offset - text_offset,
            offset,
            capacity: (end - offset) as usize,
            data,
            new_section,
            count: 0,
            reserved: 0,
            reserved_code: 0,
            shared_code_end: None,
        })
    }

    pub fn header_size(&self) -> usize {
        if self.new_section { 80 } else { 0 }
    }
    pub fn code_limit(&self) -> Option<u64> {
        if self.new_section { None } else { Some(self.offset) }
    }

    pub fn share_code(&mut self, base: u64) {
        self.shared_code_end = Some(base);
    }

    pub fn reserve(&mut self, bytes: usize, code: usize) -> Result<()> {
        ensure!(
            self.data.len() + bytes + 4 <= self.capacity,
            "insufficient text padding for string unwind metadata"
        );
        self.reserved = bytes;
        self.reserved_code = code;
        Ok(())
    }

    pub fn release(&mut self) {
        self.reserved = 0;
        self.reserved_code = 0;
    }

    pub fn add(&mut self, base: u64, size: usize, rows: &[(u64, Row)]) -> Result<()> {
        ensure!(!rows.is_empty() && rows[0].0 == base, "missing unwind row at generated entry");
        let start = self.address + self.data.len() as u64;
        let mut table = FrameTable::default();
        let mut cie = CommonInformationEntry::new(
            Encoding { format: Format::Dwarf32, version: 1, address_size: 8 },
            1,
            -8,
            X86_64::RA,
        );
        cie.fde_address_encoding = gimli::DW_EH_PE_pcrel | gimli::DW_EH_PE_sdata4;
        cie.add_instruction(Cfi::Cfa(X86_64::RSP, 8));
        cie.add_instruction(Cfi::Offset(X86_64::RA, -8));
        let cie = table.add_cie(cie);
        let mut fde = FrameDescriptionEntry::new(
            Address::Constant(base.wrapping_sub(start)),
            size.try_into()?,
        );
        let mut previous = Row::leaf();
        for (address, row) in rows {
            let offset =
                u32::try_from(address.checked_sub(base).context("unwind row below function")?)?;
            if row.cfa != previous.cfa {
                fde.add_instruction(
                    offset,
                    match row.cfa {
                        Cfa::Register(register, amount) => {
                            Cfi::Cfa(dwarf(register)?, amount.try_into()?)
                        }
                        Cfa::Stack(slot) => {
                            let mut expression = stack(slot);
                            expression.op_deref();
                            Cfi::CfaExpression(expression)
                        }
                    },
                );
            }
            for &register in NONVOLATILE.iter().chain([Register::RIP].iter()) {
                if row.registers.get(&register) == previous.registers.get(&register) {
                    continue;
                }
                fde.add_instruction(
                    offset,
                    match row.registers.get(&register) {
                        Some(Rule::Offset(amount)) => {
                            Cfi::Offset(dwarf(register)?, (*amount).try_into()?)
                        }
                        Some(Rule::Stack(slot)) => Cfi::Expression(dwarf(register)?, stack(*slot)),
                        None => Cfi::SameValue(dwarf(register)?),
                    },
                );
            }
            previous = row.clone();
        }
        table.add_fde(cie, fde);
        let mut section = EhFrame(EndianVec::new(LittleEndian));
        table.write_eh_frame(&mut section)?;
        let bytes = section.0.into_vec();
        let code_end = self.shared_code_end.map(|end| end.max(base + size as u64));
        let consumed = code_end
            .map(|end| {
                ((end + self.reserved_code as u64 + 7) & !7).saturating_sub(self.address) as usize
            })
            .unwrap_or(0);
        ensure!(
            self.data.len() + bytes.len() + self.reserved + consumed + 4 <= self.capacity,
            "text padding exhausted by unwind metadata"
        );
        self.data.extend(bytes);
        self.shared_code_end = code_end;
        self.count += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Section {
        let address = self
            .shared_code_end
            .map(|end| ((end + 7) & !7).max(self.address))
            .unwrap_or(self.address);
        let delta = address - self.address;
        if delta != 0 {
            let mut cursor = 0;
            while cursor + 8 <= self.data.len() {
                let size =
                    u32::from_le_bytes(self.data[cursor..cursor + 4].try_into().unwrap()) as usize;
                let id = u32::from_le_bytes(self.data[cursor + 4..cursor + 8].try_into().unwrap());
                if id != 0 {
                    let pointer =
                        i32::from_le_bytes(self.data[cursor + 8..cursor + 12].try_into().unwrap());
                    self.data[cursor + 8..cursor + 12]
                        .copy_from_slice(&pointer.wrapping_sub(delta as i32).to_le_bytes());
                }
                cursor += size + 4;
            }
        }
        self.data.extend([0; 4]);
        log::info!("unwind: {} generated fdes, {} bytes", self.count, self.data.len());
        Section { address, data: self.data }
    }
}

fn stack(slot: i64) -> Expression {
    let mut expression = Expression::new();
    expression.op_breg(X86_64::RSP, slot);
    expression
}

fn dwarf(register: Register) -> Result<gimli::Register> {
    Ok(match register {
        Register::RSP => X86_64::RSP,
        Register::RBP => X86_64::RBP,
        Register::RBX => X86_64::RBX,
        Register::R12 => X86_64::R12,
        Register::R13 => X86_64::R13,
        Register::R14 => X86_64::R14,
        Register::R15 => X86_64::R15,
        Register::RIP => X86_64::RA,
        _ => anyhow::bail!("unsupported unwind register {register:?}"),
    })
}
