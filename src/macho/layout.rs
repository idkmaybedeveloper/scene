use std::ops::Range;

use anyhow::{Context, Result, ensure};
use object::{
    Architecture, Endianness, Object, ObjectSection, ObjectSegment,
    build::macho::{Builder, LoadCommand, SectionData},
    macho,
};

use super::{functions, metadata, sections};

const SEGMENT: &[u8] = b"__SCENE";

enum Placement {
    Segment,
    Padding { offset: usize, capacity: usize },
}

pub struct CodeLayout {
    pub base: u64,
    pub data_base: u64,
    text_base: u64,
    placement: Placement,
    merge_sections: bool,
    pub storage_size: u64,
    page_size: u64,
}

impl CodeLayout {
    pub fn new(file: &object::File, data: &[u8], storage_size: usize) -> Result<Self> {
        Self::with_metadata(file, data, storage_size, 0, None)
    }

    pub fn with_metadata(
        file: &object::File,
        data: &[u8],
        storage_size: usize,
        header_space: usize,
        code_limit: Option<u64>,
    ) -> Result<Self> {
        let object::File::MachO64(image) = file else { anyhow::bail!("expected a 64-bit image") };
        ensure!(image.endian() == Endianness::Little, "unsupported byte order");
        let endian = image.endian();
        let header = image.macho_header();
        ensure!(
            [macho::MH_EXECUTE, macho::MH_DYLIB, macho::MH_BUNDLE]
                .contains(&header.filetype.get(endian)),
            "input is not a linked image"
        );
        let subtype = header.cpusubtype.get(endian).0 & 0x00FF_FFFF;
        let (page_size, subtypes): (_, &[_]) = match file.architecture() {
            Architecture::Aarch64 => {
                (0x4000, &[macho::CPU_SUBTYPE_ARM64_ALL.0, macho::CPU_SUBTYPE_ARM64E.0])
            }
            Architecture::X86_64 => {
                (0x1000, &[macho::CPU_SUBTYPE_X86_64_ALL.0, macho::CPU_SUBTYPE_X86_64_H.0])
            }
            other => anyhow::bail!("unsupported Mach-O architecture {other:?}"),
        };
        ensure!(subtypes.contains(&subtype), "unsupported CPU subtype {subtype:#x}");
        ensure!(
            !file.segments().any(|s| s.name().ok().flatten() == Some("__SCENE")),
            "binary already contains scene"
        );
        let linkedit = file
            .segments()
            .find(|s| s.name().ok().flatten() == Some("__LINKEDIT"))
            .context("missing linkedit")?;
        let text = file
            .segments()
            .find(|s| s.name().ok().flatten() == Some("__TEXT"))
            .context("missing __text")?;
        ensure!(linkedit.address().is_multiple_of(page_size), "unaligned linkedit");
        ensure!(
            file.segments().all(|s| s.address() <= linkedit.address()),
            "linkedit must be last"
        );
        let commands_end = 32 + header.sizeofcmds.get(endian) as usize;
        let first_section = file
            .sections()
            .filter_map(|s| s.file_range())
            .filter(|(_, n)| *n > 0)
            .map(|(o, _)| o as usize)
            .min()
            .context("missing section data")?;
        let section_savings = sections::header_savings(file);
        let (metadata_savings, signature_space) = metadata::header_savings(data)?;
        let saved = section_savings + metadata_savings;
        let storage_size = (storage_size as u64 + page_size - 1) & !(page_size - 1);
        let extend_storage = file.segments().any(|s| {
            s.address() + s.size() == linkedit.address()
                && matches!(s.flags(), object::SegmentFlags::MachO { initprot, .. } if initprot & macho::VM_PROT_WRITE != macho::VmProt(0))
        });
        let extra = if storage_size != 0 && !extend_storage { 72 } else { 0 };
        let required_end = commands_end
            .checked_add(152 + extra + signature_space + header_space)
            .context("load command size overflow")?
            .saturating_sub(saved);
        if required_end <= first_section
            && data.get(commands_end..first_section).is_some_and(|b| b.iter().all(|&b| b == 0))
        {
            return Ok(Self {
                base: linkedit.address() + storage_size,
                data_base: linkedit.address(),
                text_base: text.address(),
                placement: Placement::Segment,
                merge_sections: section_savings != 0,
                storage_size,
                page_size,
            });
        }
        ensure!(
            commands_end + extra + signature_space + header_space <= first_section + saved,
            "no space for writable string storage"
        );
        let (text_offset, text_size) = text.file_range();
        let last_section = file
            .sections()
            .filter(|s| s.segment_name().ok().flatten() == Some("__TEXT"))
            .filter_map(|s| s.file_range())
            .map(|(o, n)| o + n)
            .max()
            .context("missing __text sections")?;
        let offset = last_section.checked_add(3).context("padding offset overflow")? & !3;
        let mut end =
            text_offset.checked_add(text_size.min(text.size())).context("text size overflow")?;
        if let Some(limit) = code_limit {
            end = end.min(limit);
        }
        ensure!(offset < end, "no space for generated code");
        let padding =
            data.get(offset as usize..end as usize).context("invalid __text file range")?;
        ensure!(padding.iter().all(|&b| b == 0), "unused __text space contains data");
        log::info!("using {} bytes of executable __text padding", padding.len());
        Ok(Self {
            base: text.address() + offset - text_offset,
            data_base: linkedit.address(),
            text_base: text.address(),
            placement: Placement::Padding { offset: offset as usize, capacity: padding.len() },
            merge_sections: section_savings != 0,
            storage_size,
            page_size,
        })
    }

    pub fn fits(&self, size: usize) -> bool {
        match self.placement {
            Placement::Segment => true,
            Placement::Padding { capacity, .. } => size <= capacity,
        }
    }

    pub fn in_text_padding(&self) -> bool {
        matches!(self.placement, Placement::Padding { .. })
    }

    pub fn finish(
        self,
        data: &[u8],
        code: Vec<u8>,
        entries: &[u64],
        protected: &[Range<u64>],
    ) -> Result<Vec<u8>> {
        self.finish_with_unwind(data, code, entries, None, protected)
    }

    pub fn finish_with_unwind(
        self,
        data: &[u8],
        code: Vec<u8>,
        entries: &[u64],
        unwind: Option<super::unwind::Section>,
        protected: &[Range<u64>],
    ) -> Result<Vec<u8>> {
        let original = object::File::parse(data)?;
        let mut builder = Builder::read(data).context("reading image for rebuild")?;
        if self.merge_sections {
            sections::merge(&mut builder, data)?;
        }
        if self.storage_size != 0 {
            add_storage(&mut builder, self.data_base, self.storage_size)?;
        }
        let had_unwind = unwind.is_some();
        // a segmented eh_frame rides in __SCENE next to the code (address at/after the code base)
        // rather than the __text padding, so it is placed by add_segment, not here
        let scene_eh = matches!(self.placement, Placement::Segment)
            && unwind.as_ref().is_some_and(|u| u.address >= self.base);
        if let Some(unwind) = &unwind
            && !scene_eh
        {
            let text_id = builder
                .segments
                .iter()
                .find(|s| s.segname() == b"__TEXT")
                .context("missing text segment")?
                .id();
            let section_id = if let Some(id) = builder
                .sections
                .iter()
                .find(|s| s.sectname() == b"__eh_frame" && s.segname() == b"__TEXT")
                .map(|s| s.id())
            {
                id
            } else {
                let section = builder.sections.add();
                section.sectname[..10].copy_from_slice(b"__eh_frame");
                section.segname[..6].copy_from_slice(b"__TEXT");
                section.addr = unwind.address;
                section.align = 3;
                let id = section.id();
                builder.segments.get_mut(text_id).sections.push(id);
                id
            };
            let section = builder.sections.get_mut(section_id);
            ensure!(section.addr == unwind.address, "unwind section moved");
            section.data = SectionData::Data(unwind.data.clone().into());
        }
        for command in &builder.commands {
            if let LoadCommand::Other { cmd, .. } = command {
                ensure!(
                    ![macho::LC_ENCRYPTION_INFO, macho::LC_ENCRYPTION_INFO_64].contains(cmd),
                    "kill yourself"
                );
            }
        }
        let code_end = self.base + code.len() as u64;
        let padding = match self.placement {
            Placement::Segment => {
                let eh = if scene_eh { unwind } else { None };
                add_segment(&mut builder, self.base, code, eh, self.page_size)?;
                None
            }
            Placement::Padding { offset, .. } => Some((offset, code)),
        };
        let mut starts = functions::starts(&original)?;
        starts.extend_from_slice(entries);
        metadata::apply(&mut builder, &mut starts, entries, code_end, protected)?;
        starts.sort_unstable();
        starts.dedup();
        let mut encoded = Vec::new();
        let mut previous = self.text_base;
        for start in starts {
            leb128::write::unsigned(
                &mut encoded,
                start.checked_sub(previous).context("invalid function start")?,
            )?;
            previous = start;
        }
        encoded.push(0);
        if let Some(LoadCommand::LinkeditData { data, .. }) = builder.commands.iter_mut().find(
            |command| matches!(command, LoadCommand::LinkeditData { cmd, .. } if *cmd == macho::LC_FUNCTION_STARTS)
        ) {
            *data = encoded.into();
        }
        let mut out = Vec::new();
        builder.write(&mut out).context("rebuildin!")?;
        let rebuilt = object::File::parse(&*out)?;
        for section in original.sections() {
            if let object::SectionFlags::MachO { flags, .. } = section.flags()
                && metadata::is_debug_section(
                    section.segment_name()?.unwrap_or_default().as_bytes(),
                    section.name_bytes()?,
                    flags,
                )
            {
                continue;
            }
            let name = section.name()?;
            let segment = section.segment_name()?;
            let replacement = rebuilt
                .sections()
                .find(|s| {
                    s.segment_name().ok() == Some(segment)
                        && s.address() <= section.address()
                        && s.address() + s.size() >= section.address() + section.size()
                })
                .context("rebuild lost an existing section")?;
            let delta = section.address() - replacement.address();
            if had_unwind && name == "__eh_frame" {
                continue;
            }
            ensure!(
                replacement.file_range().map(|(o, _)| o + delta)
                    == section.file_range().map(|(o, _)| o),
                "rebuild moved existing section {name}"
            );
            let bytes = replacement.data()?;
            let original_bytes = section.data()?;
            ensure!(
                original_bytes.is_empty()
                    || bytes.get(delta as usize..delta as usize + original_bytes.len())
                        == Some(original_bytes),
                "rebuild changed section data {name}"
            );
        }
        if let Some((offset, code)) = padding {
            let text = rebuilt
                .segments()
                .find(|s| s.name().ok().flatten() == Some("__TEXT"))
                .context("rebuild lost __TEXT")?;
            let (file_offset, file_size) = text.file_range();
            ensure!(
                offset as u64 >= file_offset
                    && (offset + code.len()) as u64 <= file_offset + file_size,
                "rebuild lost executable padding"
            );
            out.get_mut(offset..offset + code.len())
                .context("generated code exceeds output")?
                .copy_from_slice(&code);
        }
        Ok(out)
    }
}

fn add_segment(
    builder: &mut Builder<'_>,
    base: u64,
    code: Vec<u8>,
    eh: Option<super::unwind::Section>,
    page_size: u64,
) -> Result<()> {
    let linkedit_id = builder
        .segments
        .iter()
        .find(|s| s.segname() == b"__LINKEDIT")
        .context("missing linkedit")?
        .id();
    ensure!(builder.segments.get(linkedit_id).sections.is_empty(), "linkedit contains sections");
    let linkedit_size = builder.segments.get(linkedit_id).vmsize;
    let code_len = code.len() as u64;
    let section = builder.sections.add();
    section.sectname[..6].copy_from_slice(b"__text");
    section.segname[..SEGMENT.len()].copy_from_slice(SEGMENT);
    section.addr = base;
    section.align = 2;
    section.flags = macho::S_ATTR_PURE_INSTRUCTIONS | macho::S_ATTR_SOME_INSTRUCTIONS;
    section.data = SectionData::Data(code.into());
    let text_id = section.id();
    // the generated eh_frame trails the code in the same segment, 8-byte aligned
    let mut used = code_len;
    let eh_id = if let Some(eh) = eh {
        let eh_addr = (base + code_len + 7) & !7;
        ensure!(eh_addr == eh.address, "segmented eh_frame address mismatch");
        used = eh_addr - base + eh.data.len() as u64;
        let section = builder.sections.add();
        section.sectname[..10].copy_from_slice(b"__eh_frame");
        section.segname[..SEGMENT.len()].copy_from_slice(SEGMENT);
        section.addr = eh_addr;
        section.align = 3;
        section.data = SectionData::Data(eh.data.into());
        Some(section.id())
    } else {
        None
    };
    let mapped_size =
        used.checked_add(page_size - 1).context("code size overflow")? & !(page_size - 1);
    let segment = builder.segments.get_mut(linkedit_id);
    segment.segname = [0; 16];
    segment.segname[..SEGMENT.len()].copy_from_slice(SEGMENT);
    segment.vmsize = mapped_size;
    segment.maxprot = macho::VM_PROT_READ | macho::VM_PROT_EXECUTE;
    segment.initprot = segment.maxprot;
    segment.sections.push(text_id);
    if let Some(eh_id) = eh_id {
        segment.sections.push(eh_id);
    }
    let segment = builder.segments.add();
    segment.segname[..10].copy_from_slice(b"__LINKEDIT");
    segment.vmaddr = base.checked_add(mapped_size).context("segment address overflow")?;
    segment.vmsize = linkedit_size;
    segment.maxprot = macho::VM_PROT_READ;
    segment.initprot = segment.maxprot;
    let new_linkedit_id = segment.id();
    let index = builder
        .commands
        .iter()
        .position(|c| matches!(c, LoadCommand::Segment(id) if *id == linkedit_id))
        .unwrap();
    builder.commands.insert(index + 1, LoadCommand::Segment(new_linkedit_id));
    Ok(())
}

fn add_storage(builder: &mut Builder<'_>, base: u64, size: u64) -> Result<()> {
    let id = builder
        .segments
        .iter()
        .find(|s| s.segname() == b"__LINKEDIT")
        .context("missing linkedit")?
        .id();
    if let Some(writable) = builder
        .segments
        .iter()
        .find(|s| {
            s.vmaddr + s.vmsize == base && s.initprot & macho::VM_PROT_WRITE != macho::VmProt(0)
        })
        .map(|s| s.id())
    {
        builder.segments.get_mut(writable).vmsize += size;
        builder.segments.get_mut(id).vmaddr += size;
        return Ok(());
    }
    let segment = builder.segments.get_mut(id);
    let old_size = segment.vmsize;
    segment.segname = [0; 16];
    segment.segname[..12].copy_from_slice(b"__SCENE_DATA");
    segment.vmsize = size;
    segment.maxprot = macho::VM_PROT_READ | macho::VM_PROT_WRITE;
    segment.initprot = segment.maxprot;
    let segment = builder.segments.add();
    segment.segname[..10].copy_from_slice(b"__LINKEDIT");
    segment.vmaddr = base + size;
    segment.vmsize = old_size;
    segment.maxprot = macho::VM_PROT_READ;
    segment.initprot = segment.maxprot;
    let new_id = segment.id();
    let at = builder
        .commands
        .iter()
        .position(|c| matches!(c, LoadCommand::Segment(s) if *s == id))
        .unwrap();
    builder.commands.insert(at + 1, LoadCommand::Segment(new_id));
    Ok(())
}
