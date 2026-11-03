//! A signature as a set of QR codes, the way the ddcard specification lays it out
//! (https://github.com/kaarkz/ddcard, «Визуализация ЭЦП»): the CMS is zipped as `<signId>.cms`
//! (DEFLATE), Base64-encoded, and split across QR codes of version 25, level M, each holding
//! the JSON `{"signId":..,"total":..,"index":..,"data":".."}`.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use qrcodegen::{QrCode, QrCodeEcc, QrSegment, Version};
use serde_json::{Value, json};

use crate::{Error, Result};

/// The version and level the specification recommends.
const VERSION: u8 = 25;
/// The largest signature accepted from QR codes.
const MAX_CMS: u64 = 4 << 20;
const ECC: QrCodeEcc = QrCodeEcc::Medium;

fn encode(text: &str) -> Option<QrCode> {
    let segs = QrSegment::make_segments(text);
    QrCode::encode_segments_advanced(
        &segs,
        ECC,
        Version::new(1),
        Version::new(VERSION),
        None,
        false,
    )
    .ok()
}

/// The longest JSON text that fits one code.
fn capacity() -> usize {
    let (mut lo, mut hi) = (1usize, 4000usize);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if encode(&"x".repeat(mid)).is_some() {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

fn base64(data: &[u8]) -> String {
    crate::base64_encode(data)
}

/// The QR texts for signature `sign_id`.
pub fn payloads(sign_id: u32, cms: &[u8]) -> Result<Vec<String>> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let zerr = |e: zip::result::ZipError| Error::new(format!("could not zip the signature: {e}"));
    zip.start_file(format!("{sign_id}.cms"), opts)
        .map_err(zerr)?;
    zip.write_all(cms).map_err(|e| Error::new(e.to_string()))?;
    let packed = zip.finish().map_err(zerr)?.into_inner();
    let b64 = base64(&packed);
    let estimate = json!({"signId": sign_id, "total": 0, "index": 0, "data": ""}).to_string();
    let room = capacity().saturating_sub(estimate.len() + 10).max(1);
    let parts: Vec<&str> = b64
        .as_bytes()
        .chunks(room)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect();
    let total = parts.len();
    Ok(parts
        .iter()
        .enumerate()
        .map(|(i, d)| {
            json!({"signId": sign_id, "total": total, "index": i + 1, "data": d}).to_string()
        })
        .collect())
}

pub fn code(text: &str) -> Result<QrCode> {
    encode(text).ok_or_else(|| Error::new("a QR code part is too large"))
}

/// The signatures in scanned QR texts: one JSON object per line (other lines are ignored), in
/// any order. Returns each signature's CMS, by signId.
pub fn assemble(text: &str) -> Result<Vec<(u64, Vec<u8>)>> {
    let bad = |m: String| Error::new(format!("QR codes: {m}"));
    let mut sets: BTreeMap<u64, (u64, BTreeMap<u64, String>)> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim().trim_start_matches('\u{feff}');
        let Ok(Value::Object(o)) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let num = |k: &str| o.get(k).and_then(Value::as_u64);
        let (Some(id), Some(total), Some(index), Some(data)) = (
            num("signId"),
            num("total"),
            num("index"),
            o.get("data").and_then(Value::as_str),
        ) else {
            continue;
        };
        if index == 0 || index > total || total > 1000 {
            return Err(bad(format!("signature {id}: a code has a bad part number")));
        }
        let e = sets.entry(id).or_insert((total, BTreeMap::new()));
        if e.0 != total {
            return Err(bad(format!(
                "signature {id}: the codes disagree on how many there are"
            )));
        }
        e.1.insert(index, data.to_string());
    }
    if sets.is_empty() {
        return Err(bad(
            "no signature QR codes found (each is a JSON text with signId, total, index and data)"
                .into(),
        ));
    }
    let mut out = Vec::new();
    for (id, (total, parts)) in sets {
        let missing: Vec<String> = (1..=total)
            .filter(|i| !parts.contains_key(i))
            .map(|i| i.to_string())
            .collect();
        if !missing.is_empty() {
            return Err(bad(format!(
                "signature {id}: missing part(s) {} of {total}",
                missing.join(", ")
            )));
        }
        let b64: String = parts.into_values().collect();
        let packed = crate::base64_decode(&b64)
            .ok_or_else(|| bad(format!("signature {id}: damaged data")))?;
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(packed))
            .map_err(|e| bad(format!("signature {id}: not a ZIP ({e})")))?;
        let mut f = zip
            .by_index(0)
            .map_err(|e| bad(format!("signature {id}: empty ZIP ({e})")))?;
        // a signature is a few KB; a ZIP that unpacks to more is not one (and could be a bomb)
        let mut cms = Vec::new();
        (&mut f)
            .take(MAX_CMS + 1)
            .read_to_end(&mut cms)
            .map_err(|e| bad(format!("signature {id}: damaged ZIP ({e})")))?;
        if cms.len() as u64 > MAX_CMS {
            return Err(bad(format!(
                "signature {id}: unpacks to more than a signature can be"
            )));
        }
        out.push((id, cms));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_in_any_order() {
        let mut x = 2463534242u32;
        let cms: Vec<u8> = (0..6000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let mut p = payloads(3, &cms).unwrap();
        assert!(p.len() >= 5, "{}", p.len());
        for s in &p {
            assert!(code(s).unwrap().version().value() <= VERSION);
        }
        p.reverse();
        let text = format!("noise\n{}\n", p.join("\n"));
        assert_eq!(assemble(&text).unwrap(), vec![(3, cms)]);
        let missing = p[1..].join("\n");
        assert!(assemble(&missing).unwrap_err().0.contains("missing"));
        let v: Value = serde_json::from_str(&p[0]).unwrap();
        assert_eq!(v["signId"], 3);
    }

    #[test]
    fn codes_are_filled() {
        let cms = vec![0x5au8; 1 << 14];
        let mut x = 1u32;
        let cms: Vec<u8> = cms
            .iter()
            .map(|_| {
                x = x.wrapping_mul(1103515245).wrapping_add(12345);
                (x >> 16) as u8
            })
            .collect();
        let p = payloads(1, &cms).unwrap();
        let cap = capacity();
        for s in &p[..p.len() - 1] {
            assert!(s.len() <= cap && s.len() + 16 > cap, "{} of {cap}", s.len());
        }
    }

    fn part(id: u64, total: u64, index: u64, data: &str) -> String {
        json!({"signId": id, "total": total, "index": index, "data": data}).to_string()
    }

    #[test]
    fn bad_part_numbers() {
        let err = |t: &str| assemble(t).unwrap_err().0;
        assert!(err(&part(1, 2, 0, "")).contains("bad part number"));
        assert!(err(&part(1, 2, 3, "")).contains("bad part number"));
        assert!(err(&part(1, 1001, 1, "")).contains("bad part number"));
        assert!(err(&part(1, 1000, 1000, "")).contains("missing part(s) 1, 2"));
        assert!(err(&part(1, 2, 2, "")).contains("missing part(s) 1 of 2"));
        let two = format!("{}\n{}", part(1, 2, 1, ""), part(1, 3, 2, ""));
        assert!(err(&two).contains("disagree"));
        assert!(err("{}\n[1]").contains("no signature QR codes"));
    }

    #[test]
    fn unpacked_size_limit() {
        let fits = vec![0u8; MAX_CMS as usize];
        let p = payloads(5, &fits).unwrap();
        assert_eq!(assemble(&p.join("\n")).unwrap()[0].1.len(), fits.len());
        let over = vec![0u8; MAX_CMS as usize + 1];
        let p = payloads(5, &over).unwrap();
        assert!(
            assemble(&p.join("\n"))
                .unwrap_err()
                .0
                .contains("more than a signature")
        );
    }
}
