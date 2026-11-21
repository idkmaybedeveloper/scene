use std::ops::Range;

use anyhow::{Context, Result};
use object::{Object, ObjectSection, SectionKind};
use scene_passes::strings::EncryptedString;

use super::{StringValue, pointers};

pub(super) struct Constants {
    pub values: Vec<StringValue>,
    pub pages: Vec<Range<u64>>,
    pub kept: usize,
}

impl Constants {
    pub fn collect(file: &object::File) -> Result<Self> {
        let mut result = Self { values: Vec::new(), pages: Vec::new(), kept: 0 };
        let page_size = 0x4000;
        let executable: Vec<_> = file
            .sections()
            .filter(|s| s.kind() == SectionKind::Text)
            .map(|s| {
                (s.address() & !(page_size - 1))
                    ..(s.address() + s.size() + page_size - 1) & !(page_size - 1)
            })
            .collect();
        for section in file.sections().filter(|s| {
            s.name().ok() == Some("__const") && s.segment_name().ok().flatten() == Some("__TEXT")
        }) {
            let data = section.data()?;
            let (offset, _) = section.file_range().context("constants have no file data")?;
            let range = section.address()..section.address() + section.size();
            let pointers = pointers::collect(file, &range)?;
            for candidate in text_ranges(data) {
                let start = section.address() + candidate.start as u64;
                let end = section.address() + candidate.end as u64;
                if executable.iter().any(|r| r.start < end && start < r.end)
                    || pointers.iter().any(|p| p.protected && (start..end).contains(&p.target))
                {
                    result.kept += 1;
                    continue;
                }
                result.values.push(StringValue {
                    range: start..end,
                    offset: offset as usize + candidate.start,
                    encrypted: EncryptedString::new(&data[candidate])?,
                });
                result
                    .pages
                    .push((start & !(page_size - 1))..(end + page_size - 1) & !(page_size - 1));
            }
        }
        result.merge_pages();
        Ok(result)
    }

    pub fn exclude_code_padding(&mut self, base: u64) {
        let page = base & !0x3fff;
        let before = self.values.len();
        self.values.retain(|v| v.range.end <= page);
        self.kept += before - self.values.len();
        self.pages = self
            .values
            .iter()
            .map(|v| (v.range.start & !0x3fff)..(v.range.end + 0x3fff) & !0x3fff)
            .collect();
        self.merge_pages();
    }

    fn merge_pages(&mut self) {
        self.pages.sort_unstable_by_key(|r| r.start);
        let mut pages: Vec<Range<u64>> = Vec::new();
        for range in self.pages.drain(..) {
            if let Some(last) = pages.last_mut()
                && range.start <= last.end
            {
                last.end = last.end.max(range.end);
            } else {
                pages.push(range);
            }
        }
        self.pages = pages;
    }
}

fn text_ranges(data: &[u8]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut cursor = 0;
    while cursor < data.len() {
        let (valid, skip) = match std::str::from_utf8(&data[cursor..]) {
            Ok(text) => (text, 0),
            Err(error) => (
                std::str::from_utf8(&data[cursor..cursor + error.valid_up_to()]).unwrap(),
                error.error_len().unwrap_or(data.len() - cursor - error.valid_up_to()),
            ),
        };
        let mut start = 0;
        for (at, ch) in valid.char_indices() {
            if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
                if at - start >= 4 {
                    ranges.push(cursor + start..cursor + at);
                }
                start = at + ch.len_utf8();
            }
        }
        if valid.len() - start >= 4 {
            ranges.push(cursor + start..cursor + valid.len());
        }
        cursor += valid.len() + skip;
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::text_ranges;

    #[test]
    fn finds_unterminated_utf8_and_strings_with_embedded_nuls() {
        let data = "firstsecond\0строка\0prefix\0suffix".as_bytes();
        let values: Vec<_> = text_ranges(data).into_iter().map(|r| &data[r]).collect();
        assert_eq!(
            values,
            vec!["firstsecond".as_bytes(), "строка".as_bytes(), b"prefix", b"suffix"]
        );
    }

    #[test]
    fn skips_invalid_utf8_without_losing_adjacent_text() {
        let data = b"\xffmessage\xe2\x82\0\x01other\0\xc3";
        let values: Vec<_> = text_ranges(data).into_iter().map(|r| &data[r]).collect();
        assert_eq!(values, vec![b"message".as_slice(), b"other"]);
    }
}
