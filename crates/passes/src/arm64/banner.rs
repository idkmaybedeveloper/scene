use anyhow::{Result, anyhow, ensure};
use dynasmrt::{DynasmApi, DynasmLabelApi, VecAssembler, aarch64::Aarch64Relocation, dynasm};

pub struct Banner {
    pub code: Vec<u8>,
    pub entries: Vec<u64>,
}

pub fn emit(base: u64, lines: &[Vec<u8>], main: Option<u64>) -> Result<Banner> {
    ensure!(!lines.is_empty(), "empty banner");
    let mut asm = VecAssembler::<Aarch64Relocation>::new(base as usize);
    let sink = asm.new_dynamic_label();
    let gate = asm.new_dynamic_label();
    let labels: Vec<_> = lines.iter().map(|_| asm.new_dynamic_label()).collect();
    if let Some(main) = main {
        dynasm!(asm
            ; .arch aarch64
            ; tbnz x0, #63, =>gate
            ; b extern main as usize
            ; =>gate
        );
    }
    for &label in &labels {
        dynasm!(asm; .arch aarch64; adr x0, =>label; bl =>sink);
    }
    match main {
        Some(main) => dynasm!(asm; .arch aarch64; b extern main as usize),
        None => dynasm!(asm; .arch aarch64; ret),
    }
    dynasm!(asm; .arch aarch64; =>sink; str x0, [x0]; ret);
    for (&label, line) in labels.iter().zip(lines) {
        dynasm!(asm; .arch aarch64; =>label);
        asm.extend(line.iter().copied());
        asm.push(0);
    }
    while asm.offset().0 % 4 != 0 {
        asm.push(0);
    }
    let sink = base + asm.labels().resolve_dynamic(sink).map_err(|e| anyhow!("{e}"))?.0 as u64;
    let code = asm.finalize().map_err(|e| anyhow!("assembling banner: {e:?}"))?;
    Ok(Banner { code, entries: vec![base, sink] })
}
