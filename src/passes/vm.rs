use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use anyhow::{Result, ensure};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind};
use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};
use scene_disasm::arm64::Insn;

use super::report::Report;
use crate::{
    config::Vm,
    macho::{self, functions::Function},
};

pub fn select(
    file: &object::File,
    insns: &[Insn],
    functions: &[Function],
    data_in_code: &[Range<u64>],
    selection: &Vm,
    seed: u32,
    report: &mut Report,
) -> Result<BTreeSet<usize>> {
    if !selection.on() {
        return Ok(BTreeSet::new());
    }
    let names: Vec<_> = functions.iter().map(|f| display_name(&f.name)).collect();
    let mut requested = BTreeSet::new();
    if let Vm::Functions(patterns) = selection {
        for pattern in patterns {
            let matches: Vec<_> = functions
                .iter()
                .zip(&names)
                .enumerate()
                .filter(|(_, (function, name))| {
                    pattern.matches(&function.name)
                        || pattern.as_str() == function.name
                        || pattern.as_str() == name.as_str()
                        || pattern
                            .matches(function.name.strip_prefix('_').unwrap_or(&function.name))
                        || pattern.matches(name)
                })
                .map(|(index, _)| index)
                .collect();
            ensure!(!matches.is_empty(), "vm: no function matches {pattern:?}");
            requested.extend(matches);
        }
    } else {
        requested.extend(0..functions.len());
    }
    let mut targets: BTreeSet<_> = file.symbols().map(|s| s.address()).collect();
    targets.extend(macho::exceptions::landing_pads(file)?);
    let mut references = BTreeMap::<_, Vec<_>>::new();
    for text in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Some((offset, _)) = text.file_range() else { continue };
        for insn in super::decode(text.data()?, text.address(), offset, data_in_code)? {
            if !insn.data
                && let Some(target) = insn.target
            {
                references.entry(target).or_default().push(insn.address);
            }
        }
    }
    let mut eligible = Vec::new();
    for &index in &requested {
        let candidate = &insns[functions[index].range.clone()];
        let checked = (|| -> Result<()> {
            let start = candidate[0].address;
            let end = start + candidate.len() as u64 * 4;
            ensure!(
                targets.range(start + 1..end).next().is_none(),
                "vm: externally visible function interior"
            );
            ensure!(
                !references.range(start + 1..end).any(|(_, sources)| sources
                    .iter()
                    .any(|address| !(start..end).contains(address))),
                "vm: external reference to function interior"
            );
            scene_passes::arm64::vm::validate(candidate)
        })();
        match checked {
            Ok(()) => eligible.push(index),
            Err(error) => {
                report.vm_skip(&error);
                if matches!(selection, Vm::Functions(_)) {
                    log::warn!("{}: vm skipped: {error:#}", names[index]);
                }
            }
        }
    }
    if matches!(selection, Vm::Random) {
        let count = eligible.len().div_ceil(4).min(32);
        log::info!(
            "vm: {} eligible functions, randomly selecting {count}, seed={seed:#x}",
            eligible.len()
        );
        eligible.shuffle(&mut StdRng::seed_from_u64(u64::from(seed)));
        eligible.truncate(count);
    } else {
        ensure!(!eligible.is_empty(), "vm: none of the selected functions can be virtualized");
        log::info!("vm: {} requested functions, {} eligible", requested.len(), eligible.len());
    }
    for &index in &eligible {
        log::info!(
            "vm selected: {} @ {:#x}",
            names[index],
            insns[functions[index].range.start].address
        );
    }
    Ok(eligible.into_iter().collect())
}

pub fn display_name(name: &str) -> String {
    match rustc_demangle::try_demangle(name) {
        Ok(name) => format!("{name:#}"),
        Err(_) => name.strip_prefix('_').unwrap_or(name).to_owned(),
    }
}
