//! Signatures inside PDF files (PAdES, ETSI EN 319 142, `ETSI.CAdES.detached`), so the signed
//! document still opens in any PDF viewer. The signature is added as an incremental update:
//! the original bytes, and any earlier signatures, stay exactly as they were.

pub mod card;
pub mod font;
pub mod import;
pub mod layout;
pub mod qr;

use std::collections::HashSet;

use lopdf::{Dictionary, Document, IncrementalDocument, Object, ObjectId, StringFormat};

use crate::cert;
use crate::cms;
use crate::der;
use crate::i18n::{tr, trf};
use crate::p12::Key;
use crate::report::{SignResult, SignerReport, VerifyReport};
use crate::trust::TrustStore;
use crate::{Error, Result, gost, sign, time, verify};

/// Room reserved in the PDF for the signature, in bytes. A CAdES signature with the signer's
/// certificate is 2-4 KB; an NCA timestamp token adds 5-7 KB.
const ROOM: usize = 8 * 1024;
const ROOM_WITH_TIMESTAMP: usize = 24 * 1024;

/// What the byte range holds until the real offsets are known: same width, unique in the file.
const RANGE_PLACEHOLDER: i64 = 9_999_999_999;

pub fn is_pdf(data: &[u8]) -> bool {
    find(&data[..data.len().min(1024)], b"%PDF-").is_some()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn open(data: &[u8]) -> Result<Document> {
    let doc = Document::load_mem(data)
        .map_err(|e| Error::new(trf("This PDF could not be read: {}", &[&e])))?;
    if doc.is_encrypted() || doc.trailer.has(b"Encrypt") {
        return Err(Error::new(tr(
            "This PDF is encrypted (password-protected or with restrictions); kzsigner cannot sign or check it.",
        )));
    }
    Ok(doc)
}

/// Signs a PDF inside the PDF. A PDF that already has signatures gets one more.
pub fn sign(
    input: &[u8],
    key: &Key,
    tsa_url: Option<&str>,
    trust: &TrustStore,
) -> Result<SignResult> {
    let doc = open(input)?;
    if docmdp_level(&doc) == Some(1) {
        return Err(Error::new(tr(
            "This PDF is certified with no changes allowed (DocMDP); adding a signature would break its certification.",
        )));
    }
    let existing = signature_fields(&doc);
    let mut r = SignResult {
        warnings: cert::key_warnings(&key.cert),
        cosigned: !existing.is_empty(),
        ..Default::default()
    };
    let bad = |e: lopdf::Error| Error::new(trf("This PDF could not be read: {}", &[&e]));

    // everything changed or added, worked out on the original before writing
    let mut next = doc.max_id;
    let mut alloc = || {
        next += 1;
        (next, 0u16)
    };
    let (sig_id, widget_id) = (alloc(), alloc());
    let mut out: Vec<(ObjectId, Object)> = Vec::new();

    let names = field_names(&doc);
    let mut k = existing.len() + 1;
    while names.contains(&format!("Signature{k}").into_bytes()) {
        k += 1;
    }
    let first_page = *doc
        .get_pages()
        .values()
        .next()
        .ok_or_else(|| Error::new(tr("This PDF has no pages.")))?;
    let widget = Dictionary::from_iter([
        ("Type", Object::from("Annot")),
        ("Subtype", "Widget".into()),
        ("FT", "Sig".into()),
        ("T", Object::string_literal(format!("Signature{k}"))),
        ("F", 132.into()),
        (
            "Rect",
            Object::Array(vec![0.into(), 0.into(), 0.into(), 0.into()]),
        ),
        ("V", sig_id.into()),
        ("P", first_page.into()),
    ]);
    out.push((widget_id, widget.into()));

    // the widget joins the first page's annotations
    let mut page = doc.get_dictionary(first_page).map_err(bad)?.clone();
    match page.get(b"Annots") {
        Ok(Object::Reference(id)) => {
            let mut a = doc
                .get_object(*id)
                .and_then(Object::as_array)
                .cloned()
                .unwrap_or_default();
            a.push(widget_id.into());
            out.push((*id, Object::Array(a)));
        }
        other => {
            let mut a = other
                .ok()
                .and_then(|o| o.as_array().ok())
                .cloned()
                .unwrap_or_default();
            a.push(widget_id.into());
            page.set("Annots", Object::Array(a));
            out.push((first_page, page.into()));
        }
    }

    // and the catalog's AcroForm
    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(bad)?;
    let mut catalog = doc.catalog().map_err(bad)?.clone();
    let add_field =
        |form: &mut Dictionary, out: &mut Vec<(ObjectId, Object)>| match form.get(b"Fields") {
            Ok(Object::Reference(id)) => {
                let mut a = doc
                    .get_object(*id)
                    .and_then(Object::as_array)
                    .cloned()
                    .unwrap_or_default();
                a.push(widget_id.into());
                out.push((*id, Object::Array(a)));
                form.set("SigFlags", 3);
            }
            other => {
                let mut a = other
                    .ok()
                    .and_then(|o| o.as_array().ok())
                    .cloned()
                    .unwrap_or_default();
                a.push(widget_id.into());
                form.set("Fields", Object::Array(a));
                form.set("SigFlags", 3);
            }
        };
    match catalog.get(b"AcroForm") {
        Ok(Object::Reference(id)) => {
            let id = *id;
            let mut form = doc.get_dictionary(id).cloned().unwrap_or_default();
            add_field(&mut form, &mut out);
            out.push((id, form.into()));
        }
        other => {
            let mut form = other
                .ok()
                .and_then(|o| o.as_dict().ok())
                .cloned()
                .unwrap_or_default();
            add_field(&mut form, &mut out);
            catalog.set("AcroForm", form);
            out.push((root_id, catalog.into()));
        }
    }

    // the signature dictionary, with room for the byte range and the signature
    let room = if tsa_url.is_some() {
        ROOM_WITH_TIMESTAMP
    } else {
        ROOM
    };
    let sig = Dictionary::from_iter([
        ("Type", Object::from("Sig")),
        ("Filter", "Adobe.PPKLite".into()),
        ("SubFilter", "ETSI.CAdES.detached".into()),
        ("M", Object::string_literal(pdf_date(time::now_ms()))),
        ("Name", text_string(&signer_name(&key.cert))),
        (
            "ByteRange",
            Object::Array(vec![
                0.into(),
                RANGE_PLACEHOLDER.into(),
                RANGE_PLACEHOLDER.into(),
                RANGE_PLACEHOLDER.into(),
            ]),
        ),
        (
            "Contents",
            Object::String(vec![0; room], StringFormat::Hexadecimal),
        ),
    ]);
    out.push((sig_id, sig.into()));

    let mut inc = IncrementalDocument::create_from(input.to_vec(), doc);
    for (id, o) in out {
        inc.new_document.objects.insert(id, o);
    }
    inc.new_document.max_id = next;
    let mut data = Vec::new();
    inc.save_to(&mut data)
        .map_err(|e| Error::new(format!("could not write the PDF: {e}")))?;

    // fill in the byte range around the signature value, then sign
    let ph = format!("0 {RANGE_PLACEHOLDER} {RANGE_PLACEHOLDER} {RANGE_PLACEHOLDER}");
    let at = input.len();
    let br = at
        + find(&data[at..], ph.as_bytes()).ok_or_else(|| Error::new("internal: no byte range"))?;
    let zeros = [b"<".as_slice(), &vec![b'0'; 2 * room], b">"].concat();
    let a = at
        + find(&data[at..], &zeros)
            .ok_or_else(|| Error::new("internal: no room for the signature"))?;
    let b = a + zeros.len();
    let ranges = format!("0 {a:010} {b:010} {:010}", data.len() - b);
    data[br..br + ranges.len()].copy_from_slice(ranges.as_bytes());
    let signed = [&data[..a], &data[b..]].concat();
    let mut sd = cms::sign_once_with(
        &signed,
        cms::ID_DATA,
        false,
        &key.private_key,
        &key.cert,
        false,
        &[],
    )
    .map_err(|e| Error::new(trf("Signing failed: {}", &[&e])))?;
    if let Some(url) = tsa_url {
        sign::timestamp(&mut sd, url, key, trust, &mut r)?;
    }
    let der = sd.encode();
    if der.len() > room {
        return Err(Error::new(format!(
            "internal: the signature ({} bytes) is larger than the room for it ({room})",
            der.len()
        )));
    }
    let hex = crate::hex(&der).to_uppercase();
    data[a + 1..a + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    r.cms = data;
    r.signer_count = existing.len() + 1;
    Ok(r)
}

/// The certification signature's permission level (/Perms /DocMDP: 1 = no changes, 2 = forms
/// and signatures, 3 = also annotations), if the PDF is certified.
fn docmdp_level(doc: &Document) -> Option<i64> {
    let perms = deref(doc, doc.catalog().ok()?.get(b"Perms").ok()?)?
        .as_dict()
        .ok()?;
    let sig = deref(doc, perms.get(b"DocMDP").ok()?)?.as_dict().ok()?;
    let refs = deref(doc, sig.get(b"Reference").ok()?)?.as_array().ok()?;
    for r in refs {
        let Some(r) = deref(doc, r).and_then(|r| r.as_dict().ok()) else {
            continue;
        };
        if r.get(b"TransformMethod").and_then(Object::as_name).ok() == Some(b"DocMDP") {
            return Some(
                r.get(b"TransformParams")
                    .ok()
                    .and_then(|p| deref(doc, p))
                    .and_then(|p| p.as_dict().ok())
                    .and_then(|p| p.get(b"P").and_then(Object::as_i64).ok())
                    .unwrap_or(2),
            );
        }
    }
    Some(2)
}

fn signer_name(c: &cert::Cert) -> String {
    let mut sr = SignerReport::default();
    cert::describe(&mut sr, c);
    sr.name()
}

/// A PDF text string: as is when ASCII, else UTF-16BE with a byte order mark.
fn text_string(s: &str) -> Object {
    if s.is_ascii() {
        return Object::string_literal(s);
    }
    let mut b = vec![0xfe, 0xff];
    for u in s.encode_utf16() {
        b.extend(u.to_be_bytes());
    }
    Object::String(b, StringFormat::Hexadecimal)
}

fn text_from(b: &[u8]) -> String {
    if let Some(rest) = b.strip_prefix(&[0xfe, 0xff]) {
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        b.iter().map(|&c| c as char).collect()
    }
}

/// D:YYYYMMDDHHmmSSZ
fn pdf_date(ms: i64) -> String {
    let digits: String = time::iso(ms - ms.rem_euclid(1000))
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    format!("D:{digits}Z")
}

/// A PDF date as milliseconds since 1970.
fn parse_pdf_date(s: &str) -> Option<i64> {
    let s = s.strip_prefix("D:").unwrap_or(s);
    let d: String = s.chars().take_while(char::is_ascii_digit).collect();
    if d.len() < 4 {
        return None;
    }
    let pad = format!("{d:0<14}");
    let num = |r: std::ops::Range<usize>| pad[r].parse::<u32>().ok();
    let t =
        chrono::NaiveDate::from_ymd_opt(num(0..4)? as i32, num(4..6)?.max(1), num(6..8)?.max(1))?
            .and_hms_opt(num(8..10)?, num(10..12)?, num(12..14)?)?;
    let mut ms = t.and_utc().timestamp_millis();
    let rest = &s[d.len()..];
    if let Some(sign @ ('+' | '-')) = rest.chars().next() {
        let z: String = rest[1..].chars().filter(char::is_ascii_digit).collect();
        let zh: i64 = z.get(0..2).and_then(|x| x.parse().ok()).unwrap_or(0);
        let zm: i64 = z.get(2..4).and_then(|x| x.parse().ok()).unwrap_or(0);
        let off = (zh * 60 + zm) * 60_000;
        ms += if sign == '+' { -off } else { off };
    }
    Some(ms)
}

// ------------------------------------------------------------------ verifying

struct SigField {
    name: Vec<u8>,
    v: Dictionary,
}

fn deref<'a>(doc: &'a Document, o: &'a Object) -> Option<&'a Object> {
    doc.dereference(o).ok().map(|(_, o)| o)
}

/// Signed signature fields, from the AcroForm.
fn signature_fields(doc: &Document) -> Vec<SigField> {
    let mut out = Vec::new();
    let Some(fields) = acroform_fields(doc) else {
        return out;
    };
    let mut seen = HashSet::new();
    for f in fields {
        walk_fields(doc, &f, Vec::new(), None, &mut out, &mut seen, 0);
    }
    out
}

fn acroform_fields(doc: &Document) -> Option<Vec<Object>> {
    let form = deref(doc, doc.catalog().ok()?.get(b"AcroForm").ok()?)?
        .as_dict()
        .ok()?;
    Some(
        deref(doc, form.get(b"Fields").ok()?)?
            .as_array()
            .ok()?
            .clone(),
    )
}

fn field_names(doc: &Document) -> Vec<Vec<u8>> {
    acroform_fields(doc)
        .unwrap_or_default()
        .iter()
        .filter_map(|f| {
            Some(
                deref(doc, f)?
                    .as_dict()
                    .ok()?
                    .get(b"T")
                    .ok()?
                    .as_str()
                    .ok()?
                    .to_vec(),
            )
        })
        .collect()
}

fn walk_fields(
    doc: &Document,
    f: &Object,
    prefix: Vec<u8>,
    ft: Option<Vec<u8>>,
    out: &mut Vec<SigField>,
    seen: &mut HashSet<ObjectId>,
    depth: usize,
) {
    if depth > 32 {
        return;
    }
    if let Object::Reference(id) = f
        && !seen.insert(*id)
    {
        return;
    }
    let Some(d) = deref(doc, f).and_then(|o| o.as_dict().ok()) else {
        return;
    };
    let mut name = prefix;
    if let Ok(t) = d.get(b"T").and_then(Object::as_str) {
        if !name.is_empty() {
            name.push(b'.');
        }
        name.extend(t);
    }
    let ft = d
        .get(b"FT")
        .and_then(Object::as_name)
        .ok()
        .map(<[u8]>::to_vec)
        .or(ft);
    if ft.as_deref() == Some(b"Sig")
        && let Some(v) = d
            .get(b"V")
            .ok()
            .and_then(|v| deref(doc, v))
            .and_then(|v| v.as_dict().ok())
    {
        out.push(SigField {
            name: name.clone(),
            v: v.clone(),
        });
    }
    if let Some(kids) = d
        .get(b"Kids")
        .ok()
        .and_then(|k| deref(doc, k))
        .and_then(|k| k.as_array().ok())
    {
        for k in kids {
            walk_fields(doc, k, name.clone(), ft.clone(), out, seen, depth + 1);
        }
    }
}

/// Ends of the file's revisions: just after each `%%EOF` and its end of line. Each
/// incremental update adds one.
fn revisions(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = find(&data[i..], b"%%EOF") {
        let mut e = i + p + 5;
        if data.get(e) == Some(&b'\r') {
            e += 1;
        }
        if data.get(e) == Some(&b'\n') {
            e += 1;
        }
        out.push(e);
        i = e;
    }
    out
}

/// Checks every signature in a PDF's signature fields.
pub fn verify(data: &[u8], trust: &TrustStore, ocsp_url: Option<&str>) -> Result<VerifyReport> {
    let doc = open(data)?;
    let mut rep = VerifyReport {
        has_content: true,
        is_pdf: true,
        content_size: data.len() as u64,
        content_sha256: Some(crate::hex(&gost::sha256(data))),
        ..Default::default()
    };
    for f in signature_fields(&doc) {
        let mut s = check_field(data, &doc, &f, trust, ocsp_url);
        s.kind = Some(trf("PDF signature \"{}\"", &[&text_from(&f.name)]));
        if s.signing_time.is_none() {
            s.signing_time =
                f.v.get(b"M")
                    .and_then(Object::as_str)
                    .ok()
                    .and_then(|m| parse_pdf_date(&text_from(m)));
        }
        rep.signers.push(s);
    }
    for (k, s) in rep.signers.iter_mut().enumerate() {
        s.index = k + 1;
    }
    rep.valid = !rep.signers.is_empty() && rep.signers.iter().all(|s| s.valid);
    if rep.signers.is_empty() {
        rep.warnings.push(tr("This PDF has no signatures.").into());
    }
    Ok(rep)
}

fn failed(m: &str) -> SignerReport {
    SignerReport {
        signature_error: Some(m.to_string()),
        ..Default::default()
    }
}

fn check_field(
    data: &[u8],
    doc: &Document,
    f: &SigField,
    trust: &TrustStore,
    ocsp_url: Option<&str>,
) -> SignerReport {
    let sub =
        f.v.get(b"SubFilter")
            .and_then(Object::as_name)
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .ok();
    if !matches!(
        sub.as_deref(),
        Some("ETSI.CAdES.detached" | "adbe.pkcs7.detached")
    ) {
        return failed(&trf(
            "Unsupported PDF signature type: {}",
            &[&sub.unwrap_or_else(|| "-".into())],
        ));
    }
    let Ok(contents) = f.v.get(b"Contents").and_then(Object::as_str) else {
        return failed(tr("The signature field has no signature value."));
    };
    let br: Vec<i64> =
        f.v.get(b"ByteRange")
            .and_then(Object::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_i64().ok()).collect())
            .unwrap_or_default();
    let ranges = (br.len() == 4 && br.iter().all(|&x| x >= 0))
        .then(|| br.iter().map(|&x| x as usize).collect::<Vec<_>>())
        .filter(|r| {
            r[0] == 0 && r[1] < r[2] && r[2].checked_add(r[3]).is_some_and(|e| e <= data.len())
        });
    let Some(r) = ranges else {
        return failed(tr("The signature's byte range is damaged."));
    };
    // the value is zero-padded after the DER
    let cms = match der::read(contents) {
        Ok((t, _)) => t.raw,
        Err(_) => contents,
    };
    let signed = [&data[..r[1]], &data[r[2]..r[2] + r[3]]].concat();
    let mut s = match verify::verify(cms, Some(&signed), trust, ocsp_url) {
        Ok(rep) if rep.signers.len() == 1 => rep.signers.into_iter().next().unwrap_or_default(),
        Ok(_) => failed(tr("A PDF signature must hold exactly one signer.")),
        Err(e) => failed(&e.0),
    };
    // what the range leaves out must be exactly the signature value, <hex>
    let gap = &data[r[1]..r[2]];
    let gap_ok = gap.len() >= 2
        && gap[0] == b'<'
        && gap[gap.len() - 1] == b'>'
        && gap[1..gap.len() - 1].iter().all(u8::is_ascii_hexdigit);
    if !gap_ok {
        s.valid = false;
        s.signature_ok = false;
        s.signature_error =
            Some(tr("The signature leaves out more of the file than its own value.").into());
    }
    let end = r[2] + r[3];
    if end == data.len() {
        s.notes.push(tr("Covers the whole file.").into());
        return s;
    }
    let later = revisions(&data[end..]).len().max(1);
    let changes = match Document::load_mem(&data[..end]) {
        Ok(old) => changes_after(&old, doc),
        Err(_) => vec![tr("the signed part of the file cannot be read as a PDF").into()],
    };
    if changes.is_empty() {
        s.notes.push(trf(
            "Covers the file as it was when signed; it was updated {} time(s) after that, only to add signatures.",
            &[&later],
        ));
    } else {
        // an incremental update can change what the pages show while the signature over the
        // earlier bytes stays intact: then the signature does not vouch for the document
        s.valid = false;
        s.signature_ok = false;
        s.signature_error = Some(trf(
            "The PDF was changed after this signature, not only by adding signatures, so what it shows now is not what was signed: {}",
            &[&changes.join("; ")],
        ));
    }
    s
}

/// What a later revision changed beyond adding signatures (ETSI EN 319 142 / ISO 32000 allow
/// signature fields and widgets, the AcroForm entries for them, the DSS, and the document
/// information). Empty when nothing else changed.
fn changes_after(old: &Document, new: &Document) -> Vec<String> {
    let mut out = Vec::new();
    let root = |d: &Document| d.trailer.get(b"Root").and_then(Object::as_reference).ok();
    let (Some(old_root), Some(new_root)) = (root(old), root(new)) else {
        return vec![tr("the document catalog is missing").into()];
    };
    if old_root != new_root {
        return vec![tr("the document catalog was replaced").into()];
    }
    let info = old.trailer.get(b"Info").and_then(Object::as_reference).ok();
    let catalog = old.get_dictionary(old_root).ok();
    let reference = |k: &[u8]| {
        catalog
            .and_then(|c| c.get(k).ok())
            .and_then(|o| o.as_reference().ok())
    };
    let (acroform, metadata) = (reference(b"AcroForm"), reference(b"Metadata"));
    for (id, now) in &new.objects {
        let Some(before) = old.objects.get(id) else {
            continue;
        };
        if before == now || Some(*id) == info || Some(*id) == metadata {
            continue;
        }
        let structural = |o: &Object| {
            o.as_stream()
                .is_ok_and(|s| s.dict.has_type(b"XRef") || s.dict.has_type(b"ObjStm"))
        };
        if structural(before) && structural(now) {
            continue;
        }
        let ok = match (before, now) {
            (Object::Dictionary(b), Object::Dictionary(n)) if *id == old_root => {
                dict_change_ok(old, new, b, n, &[b"AcroForm", b"DSS"])
            }
            (Object::Dictionary(b), Object::Dictionary(n)) if Some(*id) == acroform => {
                acroform_ok(old, new, b, n)
            }
            (Object::Dictionary(b), Object::Dictionary(n)) if b.has_type(b"Page") => {
                dict_change_ok(old, new, b, n, &[b"Annots"])
            }
            (Object::Array(b), Object::Array(n)) => only_signatures_added(new, b, n),
            _ => false,
        };
        if !ok {
            let what = match before
                .as_dict()
                .ok()
                .or(before.as_stream().ok().map(|s| &s.dict))
            {
                Some(d) if d.has_type(b"Page") => tr("a page"),
                Some(d) if d.has_type(b"Pages") => tr("the page tree"),
                Some(d) if d.has_type(b"Annot") || d.has(b"Subtype") && d.has(b"Rect") => {
                    tr("an annotation")
                }
                _ if *id == old_root => tr("the document catalog"),
                _ => tr("an object"),
            };
            out.push(trf("{} (object {}) changed", &[&what, &id.0]));
        }
    }
    out
}

fn deref_in<'a>(doc: &'a Document, o: &'a Object) -> &'a Object {
    doc.dereference(o).map(|(_, o)| o).unwrap_or(o)
}

/// Keys whose values differ (or that one side lacks) are all among `allowed`, and each of those
/// only gained signatures.
fn dict_change_ok(
    old: &Document,
    new: &Document,
    b: &Dictionary,
    n: &Dictionary,
    allowed: &[&[u8]],
) -> bool {
    let keys: HashSet<&Vec<u8>> = b.iter().chain(n.iter()).map(|(k, _)| k).collect();
    keys.into_iter().all(|k| {
        let (bv, nv) = (b.get(k).ok(), n.get(k).ok());
        if bv == nv {
            return true;
        }
        if !allowed.contains(&k.as_slice()) {
            return false;
        }
        match k.as_slice() {
            b"AcroForm" => {
                let empty = Dictionary::new();
                let bd = bv.map(|o| deref_in(old, o)).and_then(|o| o.as_dict().ok());
                let nd = nv.map(|o| deref_in(new, o)).and_then(|o| o.as_dict().ok());
                nd.is_some_and(|nd| acroform_ok(old, new, bd.unwrap_or(&empty), nd))
            }
            b"Annots" | b"Fields" => {
                let ba = bv.map(|o| deref_in(old, o)).and_then(|o| o.as_array().ok());
                let na = nv.map(|o| deref_in(new, o)).and_then(|o| o.as_array().ok());
                na.is_some_and(|na| only_signatures_added(new, ba.map_or(&[][..], |v| v), na))
            }
            // the DSS (validation data) and SigFlags are not shown
            _ => true,
        }
    })
}

fn acroform_ok(old: &Document, new: &Document, b: &Dictionary, n: &Dictionary) -> bool {
    dict_change_ok(old, new, b, n, &[b"Fields", b"SigFlags"])
}

/// `n` is `b` with signature fields or widgets added.
fn only_signatures_added(new: &Document, b: &[Object], n: &[Object]) -> bool {
    b.iter().all(|x| n.contains(x))
        && n.iter()
            .filter(|x| !b.contains(x))
            .all(|x| is_signature_item(new, x))
}

fn is_signature_item(doc: &Document, o: &Object) -> bool {
    let Ok(d) = deref_in(doc, o).as_dict() else {
        return false;
    };
    let ft_sig = |d: &Dictionary| {
        d.get(b"FT")
            .and_then(Object::as_name)
            .is_ok_and(|n| n == b"Sig")
    };
    ft_sig(d)
        || d.get(b"Parent")
            .ok()
            .and_then(|p| deref_in(doc, p).as_dict().ok())
            .is_some_and(ft_sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_texts() {
        let ms = parse_pdf_date("D:20261101103000+05'00'").unwrap();
        assert_eq!(time::iso(ms), "2026-11-01T05:30:00Z");
        assert_eq!(pdf_date(ms), "D:20261101053000Z");
        assert_eq!(parse_pdf_date(&pdf_date(ms)), Some(ms));
        let Object::String(s, _) = text_string("Қ1") else {
            unreachable!()
        };
        assert_eq!(text_from(&s), "Қ1");
        assert_eq!(revisions(b"%PDF-1.4\n%%EOF\nx%%EOF\r\n"), vec![15, 23]);
    }
}
