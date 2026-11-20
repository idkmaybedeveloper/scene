use anyhow::{Context, Result, ensure};
use object::{
    Endianness, Object, ObjectSection, ObjectSegment,
    build::macho::{Builder, LoadCommand, SectionData},
    macho,
};

use super::{functions, sections};

const SEGMENT: &[u8] = b"__SCENE";
const PAGE_SIZE: u64 = 0x4000;

enum Placement {
    Segment,
    Padding { offset: usize, capacity: usize },
}

pub struct CodeLayout {
    pub base: u64,
    text_base: u64,
    placement: Placement,
    merge_constants: bool,
}

impl CodeLayout {
    pub fn new(file: &object::File, data: &[u8]) -> Result<Self> {
        let object::File::MachO64(image) = file else { anyhow::bail!("expected a 64-bit image") };
        ensure!(image.endian() == Endianness::Little, "unsupported byte order");
        let endian = image.endian();
        let header = image.macho_header();
        ensure!(
            [macho::MH_EXECUTE, macho::MH_DYLIB, macho::MH_BUNDLE]
                .contains(&header.filetype.get(endian)),
            "input is not a linked image"
        );
        ensure!(
            [macho::CPU_SUBTYPE_ARM64_ALL.0, macho::CPU_SUBTYPE_ARM64E.0]
                .contains(&(header.cpusubtype.get(endian).0 & 0x00FF_FFFF)),
            "unsupported arm64 subtype"
        );
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
        ensure!(linkedit.address().is_multiple_of(PAGE_SIZE), "unaligned linkedit");
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
        let merge_constants = sections::can_merge_constants(file);
        let required_end = commands_end.checked_add(152).context("load command size overflow")?;
        let required_end = required_end - if merge_constants { 80 } else { 0 };
        if required_end <= first_section
            && data.get(commands_end..first_section).is_some_and(|b| b.iter().all(|&b| b == 0))
        {
            return Ok(Self {
                base: linkedit.address(),
                text_base: text.address(),
                placement: Placement::Segment,
                merge_constants,
            });
        }
        let (text_offset, text_size) = text.file_range();
        let last_section = file
            .sections()
            .filter(|s| s.segment_name().ok().flatten() == Some("__TEXT"))
            .filter_map(|s| s.file_range())
            .map(|(o, n)| o + n)
            .max()
            .context("missing __text sections")?;
        let offset = last_section.checked_add(3).context("padding offset overflow")? & !3;
        let end =
            text_offset.checked_add(text_size.min(text.size())).context("text size overflow")?;
        ensure!(offset < end, "no space for generated code");
        let padding =
            data.get(offset as usize..end as usize).context("invalid __text file range")?;
        ensure!(padding.iter().all(|&b| b == 0), "unused __text space contains data");
        eprintln!("using {} bytes of executable __text padding", padding.len());
        Ok(Self {
            base: text.address() + offset - text_offset,
            text_base: text.address(),
            placement: Placement::Padding { offset: offset as usize, capacity: padding.len() },
            merge_constants: false,
        })
    }

    pub fn fits(&self, size: usize) -> bool {
        match self.placement {
            Placement::Segment => true,
            Placement::Padding { capacity, .. } => size <= capacity,
        }
    }

    pub fn finish(self, data: &[u8], code: Vec<u8>, entries: &[u64]) -> Result<Vec<u8>> {
        let original = object::File::parse(data)?;
        let mut builder = Builder::read(data).context("reading image for rebuild")?;
        if self.merge_constants {
            sections::merge_constants(&mut builder, data)?;
        }
        for command in &builder.commands {
            if let LoadCommand::Other { cmd, .. } = command {
                ensure!(
                    ![macho::LC_ENCRYPTION_INFO, macho::LC_ENCRYPTION_INFO_64].contains(cmd),
                    "kill yourself"
                );
            }
        }
        let padding = match self.placement {
            Placement::Segment => {
                add_segment(&mut builder, self.base, code)?;
                None
            }
            Placement::Padding { offset, .. } => Some((offset, code)),
        };
        let mut starts = functions::starts(&original)?;
        starts.extend_from_slice(entries);
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

fn add_segment(builder: &mut Builder<'_>, base: u64, code: Vec<u8>) -> Result<()> {
    let mapped_size =
        (code.len() as u64).checked_add(PAGE_SIZE - 1).context("code size overflow")?
            & !(PAGE_SIZE - 1);
    let linkedit_id = builder
        .segments
        .iter()
        .find(|s| s.segname() == b"__LINKEDIT")
        .context("missing linkedit")?
        .id();
    ensure!(builder.segments.get(linkedit_id).sections.is_empty(), "linkedit contains sections");
    let linkedit_size = builder.segments.get(linkedit_id).vmsize;
    let section = builder.sections.add();
    section.sectname[..6].copy_from_slice(b"__text");
    section.segname[..SEGMENT.len()].copy_from_slice(SEGMENT);
    section.addr = base;
    section.align = 2;
    section.flags = macho::S_ATTR_PURE_INSTRUCTIONS | macho::S_ATTR_SOME_INSTRUCTIONS;
    section.data = SectionData::Data(code.into());
    let section_id = section.id();
    let segment = builder.segments.get_mut(linkedit_id);
    segment.segname = [0; 16];
    segment.segname[..SEGMENT.len()].copy_from_slice(SEGMENT);
    segment.vmsize = mapped_size;
    segment.maxprot = macho::VM_PROT_READ | macho::VM_PROT_EXECUTE;
    segment.initprot = segment.maxprot;
    segment.sections.push(section_id);
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
