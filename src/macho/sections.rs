use anyhow::{Context, Result, ensure};
use object::{
    Object, ObjectSection,
    build::macho::{Builder, SectionData},
};

pub fn can_merge_constants(file: &object::File) -> bool {
    let sections: Vec<_> =
        file.sections().filter(|s| s.segment_name().ok().flatten() == Some("__TEXT")).collect();
    sections.windows(2).any(|s| {
        s[0].name().ok() == Some("__const") && s[1].name().ok() == Some("__gcc_except_tab")
    })
}

pub fn merge_constants<'a>(builder: &mut Builder<'a>, data: &'a [u8]) -> Result<()> {
    let image = object::File::parse(data)?;
    let section = image
        .sections()
        .find(|s| {
            s.segment_name().ok().flatten() == Some("__TEXT") && s.name().ok() == Some("__const")
        })
        .context("missing constants")?;
    let (offset, _) = section.file_range().context("constants have no file data")?;
    let ids: Vec<_> = builder
        .sections
        .iter()
        .filter(|s| {
            s.segname() == b"__TEXT"
                && [b"__const".as_slice(), b"__gcc_except_tab"].contains(&s.sectname())
        })
        .map(|s| s.id())
        .collect();
    ensure!(ids.len() == 2, "ambiguous constant sections");
    let first = ids[0];
    let second = ids[1];
    let left = builder.sections.get(first);
    let right = builder.sections.get(second);
    ensure!(
        left.sectname() == b"__const"
            && right.sectname() == b"__gcc_except_tab"
            && left.addr + left.data.size() as u64 <= right.addr,
        "constant sections overlap or are out of order"
    );
    ensure!(
        left.relocations.is_empty() && right.relocations.is_empty(),
        "constant sections contain relocations"
    );
    let size = right.addr + right.data.size() as u64 - left.addr;
    let bytes =
        data.get(offset as usize..(offset + size) as usize).context("invalid constant range")?;
    builder.sections.get_mut(first).data = SectionData::Data(bytes.into());
    builder.sections.get_mut(second).delete = true;
    for symbol in &mut builder.symbols {
        if symbol.section == Some(second) {
            symbol.section = Some(first);
        }
    }
    for segment in &mut builder.segments {
        segment.sections.retain(|&id| id != second);
    }
    Ok(())
}
