use std::collections::BTreeMap;

#[derive(Default)]
pub struct Report {
    pub cff: usize,
    pub mba_only: usize,
    pub substitutions: usize,
    pub skipped: usize,
    cff_reasons: BTreeMap<String, usize>,
    skip_reasons: BTreeMap<String, usize>,
}

impl Report {
    pub fn cff_skip(&mut self, error: &anyhow::Error) {
        *self.cff_reasons.entry(reason(error.root_cause().to_string())).or_default() += 1;
    }

    pub fn skip(&mut self, message: impl Into<String>) {
        self.skipped += 1;
        *self.skip_reasons.entry(reason(message.into())).or_default() += 1;
    }

    pub fn print(&self, size: usize) {
        eprintln!(
            "cff: {} functions; mba: {} substitutions ({} functions without cff)",
            self.cff, self.substitutions, self.mba_only
        );
        eprintln!(
            "transformed: {}; skipped: {}; generated: {size} bytes",
            self.cff + self.mba_only,
            self.skipped
        );
        print_reasons("cff skipped", &self.cff_reasons);
        print_reasons("skipped", &self.skip_reasons);
    }
}

fn reason(message: String) -> String {
    if message.contains("unsupported control/system instruction") {
        "unsupported control/system instruction".into()
    } else if message.contains("Impossible relocation") || message.contains("doesn't fit in imm") {
        "branch or literal out of range".into()
    } else if message.contains("pc-relative ref to function interior") {
        "pc-relative reference to function interior".into()
    } else {
        message
    }
}

fn print_reasons(label: &str, reasons: &BTreeMap<String, usize>) {
    let mut reasons: Vec<_> = reasons.iter().collect();
    reasons.sort_unstable_by(|(a, x), (b, y)| y.cmp(x).then_with(|| a.cmp(b)));
    for (reason, count) in reasons.iter().take(6) {
        eprintln!("{label}: {count} x {reason}");
    }
    let remaining: usize = reasons.iter().skip(6).map(|(_, count)| **count).sum();
    if remaining != 0 {
        eprintln!("{label}: {remaining} x other reasons");
    }
}
