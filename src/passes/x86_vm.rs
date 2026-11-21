use super::{report::Report, vm::display_name};
use crate::{config::Vm, macho};
use anyhow::{Result, ensure};
use iced_x86::OpKind;
use object::{Object, ObjectSymbol};
use rand::{
    SeedableRng,
    rngs::StdRng,
    seq::{IteratorRandom, SliceRandom},
};
use scene_disasm::x86::Insn;
use std::collections::{BTreeMap, BTreeSet};

pub fn select(
    file: &object::File,
    insns: &[Insn],
    starts: &[u64],
    selection: &Vm,
    seed: u32,
    report: &mut Report,
) -> Result<BTreeSet<u64>> {
    if !selection.on() {
        return Ok(BTreeSet::new());
    }
    let names: BTreeMap<_, _> =
        file.symbols().filter_map(|s| Some((s.address(), s.name().ok()?.to_owned()))).collect();
    let visible: BTreeSet<_> =
        file.symbols().map(|s| s.address()).chain(macho::exceptions::landing_pads(file)?).collect();
    let name = |address| {
        names.get(&address).map(|s| display_name(s)).unwrap_or_else(|| format!("{address:#x}"))
    };
    let mut requested = BTreeSet::new();
    if let Vm::Functions(patterns) = selection {
        for pattern in patterns {
            let matches: Vec<_> = starts[..starts.len() - 1]
                .iter()
                .filter(|&&address| {
                    pattern.matches(&name(address))
                        || names
                            .get(&address)
                            .is_some_and(|s| pattern.matches(s) || pattern.as_str() == s)
                })
                .copied()
                .collect();
            ensure!(!matches.is_empty(), "vm: no function matches {:?}", pattern.as_str());
            requested.extend(matches);
        }
    } else {
        requested.extend(&starts[..starts.len() - 1]);
    }
    let mut eligible = Vec::new();
    for pair in starts.windows(2) {
        let (start, end) = (pair[0], pair[1]);
        if !requested.contains(&start) {
            continue;
        }
        let checked = (|| -> Result<()> {
            ensure!(
                visible.range(start + 1..end).next().is_none(),
                "vm: externally visible function interior"
            );
            let mut decoded = Vec::new();
            for insn in insns.iter().filter(|s| (start..end).contains(&s.address())) {
                let Insn::Decoded(insn) = insn else { break };
                decoded.push(*insn);
            }
            for insn in insns.iter().filter(|s| !(start..end).contains(&s.address())) {
                if let Insn::Decoded(insn) = insn {
                    ensure!(
                        !insn.op_kinds().any(|k| k == OpKind::NearBranch64
                            && (start + 1..end).contains(&insn.near_branch_target()))
                            && !(insn.is_ip_rel_memory_operand()
                                && (start + 1..end).contains(&insn.ip_rel_memory_address())),
                        "vm: external reference to function interior"
                    );
                }
            }
            ensure!(end - start >= 5, "vm: insufficient entry space");
            scene_passes::x86::vm::validate(&decoded)
        })();
        match checked {
            Ok(()) => eligible.push(start),
            Err(error) => {
                report.vm_skip(&error);
                if matches!(selection, Vm::Functions(_)) {
                    log::warn!("{}: vm skipped: {error:#}", name(start));
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
    for &address in &eligible {
        log::info!("vm selected: {} @ {address:#x}", name(address));
    }
    Ok(eligible.into_iter().collect())
}

pub fn anchors(insns: &[Insn], seed: u32) -> Vec<u64> {
    insns
        .iter()
        .filter_map(
            |s| if let Insn::Decoded(i) = s { (i.len() >= 4).then_some(i.ip()) } else { None },
        )
        .choose_multiple(&mut StdRng::seed_from_u64(u64::from(seed)), 16)
}
