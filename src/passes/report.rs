use std::collections::BTreeMap;

#[derive(Default)]
pub struct Report {
    pub vm: usize,
    pub vm_instructions: usize,
    pub vm_bytecode: usize,
    pub vm_runtime: usize,
    pub vm_raw_runtime: usize,
    pub vm_handlers: usize,
    pub vm_substitutions: usize,
    pub cff: usize,
    pub mba_only: usize,
    pub substitutions: usize,
    pub skipped: usize,
    pub untouched: usize,
    cff_reasons: BTreeMap<String, usize>,
    vm_reasons: BTreeMap<String, usize>,
    skip_reasons: BTreeMap<String, usize>,
}

impl Report {
    pub fn vm_skip(&mut self, error: &anyhow::Error) {
        *self.vm_reasons.entry(reason(error.root_cause().to_string())).or_default() += 1;
    }

    pub fn cff_skip(&mut self, error: &anyhow::Error) {
        *self.cff_reasons.entry(reason(error.root_cause().to_string())).or_default() += 1;
    }

    pub fn skip(&mut self, message: impl Into<String>) {
        self.skipped += 1;
        *self.skip_reasons.entry(reason(message.into())).or_default() += 1;
    }

    pub fn print(&self, size: usize) {
        if self.vm != 0 {
            log::info!(
                "vm runtime: {} handlers, {} mba substitutions, {} -> {} bytes",
                self.vm_handlers,
                self.vm_substitutions,
                self.vm_raw_runtime,
                self.vm_runtime
            );
            log::info!(
                "generated {} vm instructions, {} bytecode bytes",
                self.vm_instructions,
                self.vm_bytecode
            );
        }
        log::info!(
            "vm: {} functions; cff: {} functions; mba: {} substitutions ({} functions without cff)",
            self.vm,
            self.cff,
            self.substitutions,
            self.mba_only
        );
        log::info!(
            "transformed: {}; untouched: {}; skipped: {}; generated: {size} bytes",
            self.vm + self.cff + self.mba_only,
            self.untouched,
            self.skipped
        );
        print_reasons("vm skipped", &self.vm_reasons);
        print_reasons("cff skipped", &self.cff_reasons);
        print_reasons("skipped", &self.skip_reasons);
    }
}

fn reason(message: String) -> String {
    if message.starts_with("vm: unsupported instruction") {
        "vm: unsupported instruction".into()
    } else if message.contains("unsupported control/system instruction") {
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
        log::warn!("{label}: {count} x {reason}");
    }
    let remaining: usize = reasons.iter().skip(6).map(|(_, count)| **count).sum();
    if remaining != 0 {
        log::warn!("{label}: {remaining} x other reasons");
    }
}
