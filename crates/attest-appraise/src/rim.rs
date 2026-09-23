//! Reference set from a RIM (`tactiq-rim/1`, tactiq-os `RELEASE_INTEGRITY.md` 5.4).
//!
//! A RIM gives, for every selected PCR, its set of reference values; PCR values
//! that depend on the boot slot are given per slot. The envelope carries one
//! composite: SHA-256 over the selected PCR values concatenated in ascending
//! index order, exactly as `tpm2_pcrread <spec> -o` writes them and as the
//! prover hashes them. This module turns the per-PCR sets into the set of
//! composites a device can legitimately present.
//!
//! Per slot, not across slots: a device boots one slot, so a composite mixing
//! the slot-A value of one PCR with the slot-B value of another is never
//! admitted. Within a slot, list-valued PCRs combine freely (the cartesian
//! product), which is what "a set of values per PCR" means.
//!
//! This module does not verify the RIM's signature. A caller that does not
//! check the signature first appraises against values anyone could have written.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::reference::{PcrHash, PcrSelection, ReferenceSet};

const RIM_FORMAT: &str = "tactiq-rim/1";
const TPM_ALG_SHA256: u16 = 0x000B;

enum PcrValues {
    Any(Vec<PcrHash>),
    BySlot(BTreeMap<String, PcrHash>),
}

fn digest(v: &Value, what: &str) -> Result<PcrHash, String> {
    let s = v.as_str().ok_or_else(|| format!("{what}: not a string"))?;
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{what}: {s:?} is not 64 hex digits"));
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| format!("{what}: {e}"))?;
    }
    Ok(out)
}

/// The reference set a RIM describes: its PCR selection in the sha256 bank and
/// every composite a device booted from one of its slots can present.
///
/// Refuses anything it does not fully understand: another format or bank, a
/// selection that differs from the keys of `values`, slot-keyed PCRs that name
/// different slots, malformed digests.
pub fn reference_from_rim(rim_json: &str) -> Result<ReferenceSet, String> {
    let rim: Value = serde_json::from_str(rim_json).map_err(|e| format!("RIM is not JSON: {e}"))?;
    match rim.get("format").and_then(Value::as_str) {
        Some(RIM_FORMAT) => {}
        other => return Err(format!("RIM format {other:?}, expected {RIM_FORMAT:?}")),
    }
    let pcr = rim.get("pcr").ok_or("RIM has no pcr section")?;
    match pcr.get("bank").and_then(Value::as_str) {
        Some("sha256") => {}
        other => return Err(format!("RIM bank {other:?}, expected \"sha256\"")),
    }

    let mut selection: Vec<u8> = Vec::new();
    for v in pcr.get("selection").and_then(Value::as_array).ok_or("RIM pcr.selection is not a list")? {
        let i = v.as_u64().filter(|i| *i <= 23).ok_or("RIM pcr.selection: index not in 0..=23")? as u8;
        selection.push(i);
    }
    selection.sort_unstable();
    selection.dedup();
    if selection.is_empty() {
        return Err("RIM pcr.selection is empty".into());
    }

    let values = pcr.get("values").and_then(Value::as_object).ok_or("RIM pcr.values is not an object")?;
    let keys: Vec<u8> = {
        let mut k = Vec::new();
        for name in values.keys() {
            k.push(name.parse::<u8>().map_err(|_| format!("RIM pcr.values: key {name:?} is not a PCR index"))?);
        }
        k.sort_unstable();
        k
    };
    if keys != selection {
        return Err(format!("RIM pcr.values names PCRs {keys:?}, selection is {selection:?}"));
    }

    let mut per_pcr: Vec<PcrValues> = Vec::new();
    let mut slots: Option<Vec<String>> = None;
    for i in &selection {
        let what = format!("RIM PCR {i}");
        let v = &values[&i.to_string()];
        if let Some(list) = v.as_array() {
            if list.is_empty() {
                return Err(format!("{what}: empty value set"));
            }
            let mut ds = list.iter().map(|x| digest(x, &what)).collect::<Result<Vec<_>, _>>()?;
            ds.sort_unstable();
            ds.dedup();
            per_pcr.push(PcrValues::Any(ds));
        } else if let Some(map) = v.as_object() {
            let mut m = BTreeMap::new();
            for (slot, x) in map {
                m.insert(slot.clone(), digest(x, &format!("{what} slot {slot}"))?);
            }
            let names: Vec<String> = m.keys().cloned().collect();
            if names.is_empty() {
                return Err(format!("{what}: no slots"));
            }
            match &slots {
                None => slots = Some(names),
                Some(s) if *s == names => {}
                Some(s) => return Err(format!("{what}: slots {names:?}, another PCR names {s:?}")),
            }
            per_pcr.push(PcrValues::BySlot(m));
        } else {
            return Err(format!("{what}: neither a list nor a per-slot object"));
        }
    }

    let slot_names: Vec<Option<String>> = match slots {
        Some(s) => s.into_iter().map(Some).collect(),
        None => vec![None],
    };
    let mut composites: Vec<PcrHash> = Vec::new();
    for slot in &slot_names {
        // Per slot: every PCR contributes a list of candidate values.
        let columns: Vec<Vec<PcrHash>> = per_pcr
            .iter()
            .map(|p| match (p, slot) {
                (PcrValues::Any(ds), _) => ds.clone(),
                (PcrValues::BySlot(m), Some(s)) => vec![m[s]],
                (PcrValues::BySlot(_), None) => unreachable!("slot-keyed PCR implies named slots"),
            })
            .collect();
        // The cartesian product of the columns, each combination concatenated
        // in ascending PCR order; its SHA-256 is the composite.
        let mut combos: Vec<Vec<u8>> = vec![Vec::new()];
        for col in &columns {
            combos = combos
                .iter()
                .flat_map(|pre| col.iter().map(move |d| [pre.as_slice(), d.as_slice()].concat()))
                .collect();
        }
        composites.extend(combos.iter().map(|c| -> PcrHash { Sha256::digest(c).into() }));
    }
    composites.sort_unstable();
    composites.dedup();

    let mut mask = [0u8; 3];
    for i in &selection {
        mask[(*i / 8) as usize] |= 1 << (i % 8);
    }
    Ok(ReferenceSet::new(PcrSelection { hash_alg: TPM_ALG_SHA256, pcr_mask: mask }, composites))
}
