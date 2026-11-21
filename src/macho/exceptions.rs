use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use gimli::{
    BaseAddresses, CieOrFde, EhFrame, EndianSlice, LittleEndian, Pointer, Reader, UnwindSection,
};
use macho_unwind_info::raw::CompactUnwindInfoHeader;
use object::{Object, ObjectSection, ObjectSegment};

pub fn landing_pads(file: &object::File) -> Result<BTreeSet<u64>> {
    let base = file
        .segments()
        .find(|s| s.name().ok().flatten() == Some("__TEXT"))
        .context("missing text segment")?
        .address();
    let mut lsdas = BTreeSet::new();
    if let Some(section) = file.section_by_name("__unwind_info") {
        let data = section.data()?;
        let header = CompactUnwindInfoHeader::parse(data)?;
        for pair in header.pages(data)?.windows(2) {
            let start = pair[0].lsda_index_offset() as usize;
            let end = pair[1].lsda_index_offset() as usize;
            let bytes = data.get(start..end).context("invalid compact unwind lsda index")?;
            ensure!(bytes.len().is_multiple_of(8), "unaligned compact unwind lsda index");
            for entry in bytes.as_chunks::<8>().0 {
                let function = base + u32::from_le_bytes(entry[..4].try_into()?) as u64;
                let lsda = base + u32::from_le_bytes(entry[4..].try_into()?) as u64;
                lsdas.insert((function, lsda));
            }
        }
    }
    if let Some(section) = file.section_by_name("__eh_frame") {
        let mut frame = EhFrame::new(section.data()?, LittleEndian);
        frame.set_address_size(8);
        let bases = BaseAddresses::default().set_text(base).set_eh_frame(section.address());
        let mut entries = frame.entries(&bases);
        while let Some(entry) = entries.next()? {
            if let CieOrFde::Fde(fde) = entry {
                let fde = fde.parse(EhFrame::cie_from_offset)?;
                match fde.lsda() {
                    Some(Pointer::Direct(lsda)) => {
                        lsdas.insert((fde.initial_address(), lsda));
                    }
                    Some(Pointer::Indirect(_)) => {
                        anyhow::bail!("indirect lsda pointer is unsupported")
                    }
                    None => {}
                }
            }
        }
    }
    let mut result = BTreeSet::new();
    for (function, address) in lsdas {
        let section = file
            .sections()
            .find(|s| (s.address()..s.address() + s.size()).contains(&address))
            .context("lsda is outside section data")?;
        let bytes = section
            .data()?
            .get((address - section.address()) as usize..)
            .context("lsda has no file data")?;
        let mut reader = EndianSlice::new(bytes, LittleEndian);
        let landing_encoding = reader.read_u8()?;
        let landing_base = if landing_encoding == 0xff {
            function
        } else {
            let location = address + (bytes.len() - reader.len()) as u64;
            let value = encoded(&mut reader, landing_encoding)?;
            match landing_encoding & 0xf0 {
                0 => value,
                0x10 => location.wrapping_add(value),
                _ => anyhow::bail!("unsupported lsda landing base encoding"),
            }
        };
        let types = reader.read_u8()?;
        if types != 0xff {
            reader.read_uleb128()?;
        }
        let encoding = reader.read_u8()?;
        ensure!(encoding & 0xf0 == 0, "unsupported lsda call-site encoding");
        let length = usize::try_from(reader.read_uleb128()?)?;
        let mut sites = reader.split(length)?;
        while !sites.is_empty() {
            encoded(&mut sites, encoding)?;
            encoded(&mut sites, encoding)?;
            let landing = encoded(&mut sites, encoding)?;
            sites.read_uleb128()?;
            if landing != 0 {
                result.insert(landing_base.wrapping_add(landing));
            }
        }
    }
    Ok(result)
}

fn encoded(reader: &mut EndianSlice<'_, LittleEndian>, encoding: u8) -> Result<u64> {
    Ok(match encoding & 15 {
        0 => reader.read_u64()?,
        1 => reader.read_uleb128()?,
        2 => reader.read_u16()? as u64,
        3 => reader.read_u32()? as u64,
        4 => reader.read_u64()?,
        9 => reader.read_sleb128()? as u64,
        10 => reader.read_i16()? as u64,
        11 => reader.read_i32()? as u64,
        12 => reader.read_i64()? as u64,
        _ => anyhow::bail!("unsupported lsda value encoding"),
    })
}
