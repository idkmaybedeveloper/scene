use anyhow::{Context, Result, ensure};
use object::{
    Object, ObjectSection,
    build::macho::{Builder, SectionData},
};

const GROUPS: &[&[&[u8]]] = &[
    &[b"__text", b"__stubs", b"__auth_stubs", b"__stub_helper"],
    &[b"__const", b"__gcc_except_tab", b"__cstring"],
];

fn groups(file: &object::File) -> Vec<Vec<Vec<u8>>> {
    let mut groups = Vec::new();
    for names in GROUPS {
        let mut run = Vec::new();
        for section in file.sections() {
            let name = section.name_bytes().unwrap_or_default();
            if section.segment_name().ok().flatten() == Some("__TEXT") && names.contains(&name) {
                run.push(name.to_vec());
            } else {
                if run.len() > 1 {
                    groups.push(std::mem::take(&mut run));
                }
                run.clear();
            }
        }
        if run.len() > 1 {
            groups.push(run);
        }
    }
    groups
}

pub fn header_savings(file: &object::File) -> usize {
    groups(file).iter().map(|g| (g.len() - 1) * 80).sum()
}

pub fn merge(builder: &mut Builder<'_>, data: &[u8]) -> Result<()> {
    let image = object::File::parse(data)?;
    for names in groups(&image) {
        let ids: Vec<_> = builder
            .sections
            .iter()
            .filter(|s| s.segname() == b"__TEXT" && names.iter().any(|n| n == s.sectname()))
            .map(|s| s.id())
            .collect();
        ensure!(ids.len() == names.len(), "ambiguous section group");
        let first = ids[0];
        let section =
            image.section_by_name(std::str::from_utf8(&names[0])?).context("missing section")?;
        let (offset, _) = section.file_range().context("section has no file data")?;
        let start = section.address();
        let mut end = start;
        for &id in &ids {
            let section = builder.sections.get(id);
            ensure!(section.relocations.is_empty(), "section contains relocations");
            ensure!(section.addr >= end, "sections overlap or are out of order");
            end = section.addr + section.data.size() as u64;
        }
        let bytes = data
            .get(offset as usize..(offset + end - start) as usize)
            .context("invalid section range")?;
        builder.sections.get_mut(first).data = SectionData::Data(bytes.to_vec().into());
        for &id in &ids[1..] {
            builder.sections.get_mut(id).delete = true;
            for symbol in &mut builder.symbols {
                if symbol.section == Some(id) {
                    symbol.section = Some(first);
                }
            }
            for segment in &mut builder.segments {
                segment.sections.retain(|&section| section != id);
            }
        }
    }
    Ok(())
}
