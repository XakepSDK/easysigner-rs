//! Signatures inside PDF files (PAdES, ETSI EN 319 142, `ETSI.CAdES.detached`), so the signed
//! document still opens in any PDF viewer. The signature is added as an incremental update:
//! the original bytes, and any earlier signatures, stay exactly as they were.

pub mod card;
pub mod font;
pub mod import;
pub mod layout;
pub mod qr;
pub mod stamp;

use std::collections::HashSet;

use lopdf::{Dictionary, Document, IncrementalDocument, Object, ObjectId, Stream, StringFormat};

use crate::cert::{self, Cert};
use crate::cms::{self, SignedData};
use crate::der;
use crate::i18n::{tr, trf};
use crate::ltv::{self, Kept};
use crate::p12::Key;
use crate::report::{ArchiveStamp, SignResult, SignerReport, VerifyReport};
use crate::trust::TrustStore;
use crate::tsp;
use crate::{Error, Result, gost, sign, time, verify};

/// Room reserved in the PDF for the signature, in bytes. A CAdES signature with the signer's
/// certificate is 2-4 KB; an NCA timestamp token adds 5-7 KB.
const ROOM: usize = 8 * 1024;
const ROOM_WITH_TIMESTAMP: usize = 24 * 1024;
/// Room for a document timestamp: an NCA timestamp token is 5-7 KB.
const ROOM_DOC_TIMESTAMP: usize = 16 * 1024;

/// What the byte range holds until the real offsets are known: same width, unique in the file.
const RANGE_PLACEHOLDER: i64 = 9_999_999_999;

pub fn is_pdf(data: &[u8]) -> bool {
    // a .cms holding a PDF has "%PDF-" near its start too
    if data.first() == Some(&0x30) && cms::SignedData::try_parse(data).is_some() {
        return false;
    }
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
    stamp: Option<&stamp::Stamp>,
) -> Result<SignResult> {
    let doc = open(input)?;
    if docmdp_level(&doc) == Some(1) {
        return Err(Error::new(tr(
            "This PDF is certified with no changes allowed (DocMDP); adding a signature would break its certification.",
        )));
    }
    let existing = signature_fields(&doc).len();
    let mut r = SignResult {
        warnings: cert::key_warnings(&key.cert),
        cosigned: existing > 0,
        ..Default::default()
    };
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
        ("Name", text_string(&cert::holder_name(&key.cert))),
    ]);
    let visible = stamp.map(|s| (s, &key.cert));
    let data = add_field(input, doc, "Signature", sig, room, visible, |signed| {
        let mut sd = cms::sign_once_with(
            signed,
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
        Ok(sd.encode())
    })?;
    r.cms = data;
    r.signer_count = existing + 1;
    Ok(r)
}

/// Adds a signature field named `prefix`N to the PDF in an incremental update, with the
/// signature dictionary `sig` and `room` bytes for its value, which `fill` makes from the bytes
/// the value's byte range covers.
fn add_field(
    input: &[u8],
    doc: Document,
    prefix: &str,
    mut sig: Dictionary,
    room: usize,
    visible: Option<(&stamp::Stamp, &Cert)>,
    fill: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    let existing = signature_fields(&doc);
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
    while names.contains(&format!("{prefix}{k}").into_bytes()) {
        k += 1;
    }
    let first_page = *doc
        .get_pages()
        .values()
        .next()
        .ok_or_else(|| Error::new(tr("This PDF has no pages.")))?;
    // an invisible signature's widget sits on the first page; a visible one where its stamp is
    let (first_page, rect, appearance) = match visible {
        Some((st, c)) => {
            let d = stamp::draw(&doc, st, c, &mut alloc)?;
            out.extend(d.objects);
            (d.page, d.rect, Some(d.appearance))
        }
        None => (first_page, [0.0; 4], None),
    };
    let mut widget = Dictionary::from_iter([
        ("Type", Object::from("Annot")),
        ("Subtype", "Widget".into()),
        ("FT", "Sig".into()),
        ("T", Object::string_literal(format!("{prefix}{k}"))),
        ("F", 132.into()),
        (
            "Rect",
            Object::Array(rect.iter().map(|&v| Object::Real(v as f32)).collect()),
        ),
        ("V", sig_id.into()),
        ("P", first_page.into()),
    ]);
    if let Some(ap) = appearance {
        widget.set("AP", Dictionary::from_iter([("N", Object::Reference(ap))]));
    }
    out.push((widget_id, widget.into()));

    // the widget joins its page's annotations
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
    sig.extend(&Dictionary::from_iter([
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
    ]));
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
    let der = fill(&signed)?;
    if der.len() > room {
        return Err(Error::new(format!(
            "internal: the signature ({} bytes) is larger than the room for it ({room})",
            der.len()
        )));
    }
    let hex = crate::hex(&der).to_uppercase();
    data[a + 1..a + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    Ok(data)
}

/// Makes a PDF's signatures long-term (PAdES B-LT): the certificates and revocation answers
/// needed to check them later go into the PDF's document security store (DSS), in an
/// incremental update. With `archive` (B-LTA), a document timestamp then covers everything;
/// adding one again later renews it.
pub fn extend(
    input: &[u8],
    archive: bool,
    tsa_url: &str,
    ocsp_url: &str,
    trust: &TrustStore,
) -> Result<SignResult> {
    let doc = open(input)?;
    let mut r = SignResult::default();
    let mut targets: Vec<(Cert, bool)> = Vec::new();
    let mut key_alg = None;
    for f in signature_fields(&doc) {
        let Some(value) = field_value(&f) else {
            continue;
        };
        if subfilter(&f).as_deref() == Some("ETSI.RFC3161") {
            if let Some(c) = tsp::token_cert(value) {
                targets.push((c, false));
            }
            continue;
        }
        let Some(sd) = SignedData::try_parse(value) else {
            continue;
        };
        for si in &sd.signers {
            let Some(c) = sd.signer_cert(si) else {
                continue;
            };
            r.signer_count += 1;
            key_alg.get_or_insert_with(|| c.key_alg());
            let tsas = ltv::tsa_certs(si);
            if tsas.is_empty() {
                r.warnings.push(trf(
                    "The signature of {} has no timestamp: a long-term signature needs one, so it stays checkable only while the certificate is valid.",
                    &[&cert::holder_name(&c)],
                ));
            }
            targets.push((c, true));
            targets.extend(tsas.into_iter().map(|t| (t, false)));
        }
    }
    if r.signer_count == 0 {
        return Err(Error::new(tr("This PDF has no signatures.")));
    }
    let g = ltv::gather(&targets, ocsp_url, trust, time::now_ms());
    r.warnings.extend(g.warnings);
    r.warnings.extend(g.refused);
    let mut out = add_dss(input, &g.kept)?;
    if archive {
        let doc = open(&out)?;
        let sig = Dictionary::from_iter([
            ("Type", Object::from("DocTimeStamp")),
            ("Filter", "Adobe.PPKLite".into()),
            ("SubFilter", "ETSI.RFC3161".into()),
        ]);
        let (alg, policy) = tsp::hash_and_policy_for(key_alg.as_deref().unwrap_or_default());
        out = add_field(
            &out,
            doc,
            "Timestamp",
            sig,
            ROOM_DOC_TIMESTAMP,
            None,
            |signed| tsp::request(tsa_url, alg, &gost::hash(alg, signed)?, policy),
        )?;
        r.timestamped = true;
    }
    r.cms = out;
    Ok(r)
}

/// The validation data in a PDF's document security store.
pub fn dss(doc: &Document) -> Kept {
    let mut k = Kept::default();
    let Some(d) = doc
        .catalog()
        .ok()
        .and_then(|c| c.get(b"DSS").ok())
        .and_then(|o| deref(doc, o))
        .and_then(|o| o.as_dict().ok())
    else {
        return k;
    };
    for (key, list) in [
        (&b"Certs"[..], &mut k.certs),
        (b"OCSPs", &mut k.ocsps),
        (b"CRLs", &mut k.crls),
    ] {
        let Some(a) = d
            .get(key)
            .ok()
            .and_then(|o| deref(doc, o))
            .and_then(|o| o.as_array().ok())
        else {
            continue;
        };
        for o in a {
            if let Some(Ok(st)) = deref(doc, o).map(Object::as_stream) {
                let data = if st.dict.has(b"Filter") {
                    st.decompressed_content().ok()
                } else {
                    Some(st.content.clone())
                };
                if let Some(data) = data
                    && !list.contains(&data)
                {
                    list.push(data);
                }
            }
        }
    }
    k
}

/// Adds the validation data in `kept` that the PDF's DSS lacks, in an incremental update (the
/// PDF as it was when nothing is new).
fn add_dss(input: &[u8], kept: &Kept) -> Result<Vec<u8>> {
    let doc = open(input)?;
    let have = dss(&doc);
    let bad = |e: lopdf::Error| Error::new(trf("This PDF could not be read: {}", &[&e]));
    let mut next = doc.max_id;
    let mut alloc = || {
        next += 1;
        (next, 0u16)
    };
    let root_id = doc
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(bad)?;
    let mut catalog = doc.catalog().map_err(bad)?.clone();
    let old = catalog
        .get(b"DSS")
        .ok()
        .and_then(|o| deref(&doc, o))
        .and_then(|o| o.as_dict().ok())
        .cloned()
        .unwrap_or_default();
    let mut dss = old.clone();
    let mut out: Vec<(ObjectId, Object)> = Vec::new();
    for (key, items, had) in [
        ("Certs", &kept.certs, &have.certs),
        ("OCSPs", &kept.ocsps, &have.ocsps),
        ("CRLs", &kept.crls, &have.crls),
    ] {
        let mut arr: Vec<Object> = old
            .get(key.as_bytes())
            .ok()
            .and_then(|o| deref(&doc, o))
            .and_then(|o| o.as_array().ok())
            .cloned()
            .unwrap_or_default();
        let before = arr.len();
        for it in items.iter().filter(|it| !had.contains(it)) {
            let id = alloc();
            out.push((id, Stream::new(Dictionary::new(), it.clone()).into()));
            arr.push(id.into());
        }
        if arr.len() != before {
            dss.set(key, Object::Array(arr));
        }
    }
    if out.is_empty() {
        return Ok(input.to_vec());
    }
    let dss_id = alloc();
    dss.set("Type", "DSS");
    out.push((dss_id, dss.into()));
    catalog.set("DSS", dss_id);
    out.push((root_id, catalog.into()));
    let mut inc = IncrementalDocument::create_from(input.to_vec(), doc);
    for (id, o) in out {
        inc.new_document.objects.insert(id, o);
    }
    inc.new_document.max_id = next;
    let mut data = Vec::new();
    inc.save_to(&mut data)
        .map_err(|e| Error::new(format!("could not write the PDF: {e}")))?;
    Ok(data)
}

fn subfilter(f: &SigField) -> Option<String> {
    f.v.get(b"SubFilter")
        .and_then(Object::as_name)
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .ok()
}

/// A signature field's value (CMS or timestamp token), without the zero padding after it.
fn field_value(f: &SigField) -> Option<&[u8]> {
    let contents = f.v.get(b"Contents").and_then(Object::as_str).ok()?;
    Some(match der::read(contents) {
        Ok((t, _)) => t.raw,
        Err(_) => contents,
    })
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

/// Checks every signature in a PDF's signature fields, and its document timestamps.
pub fn verify(data: &[u8], trust: &TrustStore, ocsp_url: Option<&str>) -> Result<VerifyReport> {
    let doc = open(data)?;
    let mut rep = VerifyReport {
        has_content: true,
        is_pdf: true,
        content_size: data.len() as u64,
        content_sha256: Some(crate::hex(&gost::sha256(data))),
        ..Default::default()
    };
    let kept = dss(&doc);
    let mut signers: Vec<(SignerReport, usize)> = Vec::new();
    let mut stamps: Vec<(ArchiveStamp, usize)> = Vec::new();
    for f in signature_fields(&doc) {
        if subfilter(&f).as_deref() == Some("ETSI.RFC3161") {
            stamps.push(check_doc_timestamp(data, &doc, &f, trust));
            continue;
        }
        let (mut s, end) = check_field(data, &doc, &f, trust, ocsp_url, &kept);
        s.kind = Some(trf("PDF signature \"{}\"", &[&text_from(&f.name)]));
        if s.signing_time.is_none() {
            s.signing_time =
                f.v.get(b"M")
                    .and_then(Object::as_str)
                    .ok()
                    .and_then(|m| parse_pdf_date(&text_from(m)));
        }
        signers.push((s, end));
    }
    stamps.sort_by_key(|(_, end)| *end);
    // a document timestamp added after a signature covers it (PAdES B-LTA)
    for (s, end) in &mut signers {
        let covering: Vec<ArchiveStamp> = stamps
            .iter()
            .filter(|(_, e)| e > end)
            .map(|(a, _)| a.clone())
            .collect();
        if s.level == Some("B-LT") && covering.iter().any(|a| a.valid) {
            s.level = Some("B-LTA");
        }
        s.archive_timestamps.extend(covering);
    }
    rep.signers = signers.into_iter().map(|(s, _)| s).collect();
    rep.document_timestamps = stamps.into_iter().map(|(a, _)| a).collect();
    for (k, s) in rep.signers.iter_mut().enumerate() {
        s.index = k + 1;
    }
    for a in &rep.document_timestamps {
        if !a.valid {
            rep.warnings.push(trf(
                "A document timestamp is not valid: {}",
                &[&a.error.clone().unwrap_or_default()],
            ));
        } else if !a.trusted {
            rep.warnings.push(trf(
                "The document timestamp authority '{}' is not a trusted NCA RK TSA.",
                &[&a.tsa.clone().unwrap_or_default()],
            ));
        }
    }
    rep.valid = !rep.signers.is_empty()
        && rep.signers.iter().all(|s| s.valid)
        && rep.document_timestamps.iter().all(|a| a.valid);
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

/// What a signature field's byte range covers.
struct Covered<'a> {
    /// The field's value: a CMS, or a timestamp token.
    value: &'a [u8],
    /// The bytes the range covers.
    signed: Vec<u8>,
    /// Where the range ends.
    end: usize,
    /// What the range leaves out is more than the field's own value.
    gap_bad: bool,
    /// For people: what the range covers, when it holds.
    note: Option<String>,
    /// What was changed after the range, beyond adding signatures.
    changes: Vec<String>,
}

fn covered<'a>(
    data: &[u8],
    doc: &Document,
    f: &'a SigField,
) -> std::result::Result<Covered<'a>, String> {
    let value = field_value(f).ok_or_else(|| tr("The signature field has no signature value."))?;
    let br: Vec<i64> =
        f.v.get(b"ByteRange")
            .and_then(Object::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_i64().ok()).collect())
            .unwrap_or_default();
    let r = (br.len() == 4 && br.iter().all(|&x| x >= 0))
        .then(|| br.iter().map(|&x| x as usize).collect::<Vec<_>>())
        .filter(|r| {
            r[0] == 0 && r[1] < r[2] && r[2].checked_add(r[3]).is_some_and(|e| e <= data.len())
        })
        .ok_or_else(|| tr("The signature's byte range is damaged."))?;
    let signed = [&data[..r[1]], &data[r[2]..r[2] + r[3]]].concat();
    // what the range leaves out must be exactly the signature value, <hex>
    let gap = &data[r[1]..r[2]];
    let gap_bad = !(gap.len() >= 2
        && gap[0] == b'<'
        && gap[gap.len() - 1] == b'>'
        && gap[1..gap.len() - 1].iter().all(u8::is_ascii_hexdigit));
    let end = r[2] + r[3];
    let mut c = Covered {
        value,
        signed,
        end,
        gap_bad,
        note: None,
        changes: vec![],
    };
    if end == data.len() {
        c.note = Some(tr("Covers the whole file.").into());
        return Ok(c);
    }
    let later = revisions(&data[end..]).len().max(1);
    c.changes = match Document::load_mem(&data[..end]) {
        Ok(old) => changes_after(&old, doc),
        Err(_) => vec![tr("the signed part of the file cannot be read as a PDF").into()],
    };
    if c.changes.is_empty() {
        c.note = Some(trf(
            "Covers the file as it was when signed; it was updated {} time(s) after that, only to add signatures, timestamps or validation data.",
            &[&later],
        ));
    }
    Ok(c)
}

/// Checks a signature field; returns the report and where its byte range ends.
fn check_field(
    data: &[u8],
    doc: &Document,
    f: &SigField,
    trust: &TrustStore,
    ocsp_url: Option<&str>,
    kept: &Kept,
) -> (SignerReport, usize) {
    let sub = subfilter(f);
    if !matches!(
        sub.as_deref(),
        Some("ETSI.CAdES.detached" | "adbe.pkcs7.detached")
    ) {
        let s = failed(&trf(
            "Unsupported PDF signature type: {}",
            &[&sub.unwrap_or_else(|| "-".into())],
        ));
        return (s, 0);
    }
    let c = match covered(data, doc, f) {
        Ok(c) => c,
        Err(e) => return (failed(&e), 0),
    };
    let mut s = match verify::verify_kept(c.value, Some(&c.signed), trust, ocsp_url, kept) {
        Ok(rep) if rep.signers.len() == 1 => rep.signers.into_iter().next().unwrap_or_default(),
        Ok(_) => failed(tr("A PDF signature must hold exactly one signer.")),
        Err(e) => failed(&e.0),
    };
    if c.gap_bad {
        s.valid = false;
        s.signature_ok = false;
        s.signature_error =
            Some(tr("The signature leaves out more of the file than its own value.").into());
    }
    if !c.changes.is_empty() {
        // an incremental update can change what the pages show while the signature over the
        // earlier bytes stays intact: then the signature does not vouch for the document
        s.valid = false;
        s.signature_ok = false;
        s.signature_error = Some(trf(
            "The PDF was changed after this signature, not only by adding signatures, so what it shows now is not what was signed: {}",
            &[&c.changes.join("; ")],
        ));
    }
    s.notes.extend(c.note);
    (s, c.end)
}

/// Checks a document timestamp (ETSI.RFC3161); returns it and where its byte range ends.
fn check_doc_timestamp(
    data: &[u8],
    doc: &Document,
    f: &SigField,
    trust: &TrustStore,
) -> (ArchiveStamp, usize) {
    let bad = |e: String| ArchiveStamp {
        checked: true,
        error: Some(e),
        ..Default::default()
    };
    let c = match covered(data, doc, f) {
        Ok(c) => c,
        Err(e) => return (bad(e), 0),
    };
    let mut r = SignerReport::default();
    if let Err(e) = tsp::check_token(&mut r, &c.signed, c.value, trust) {
        return (bad(trf("unreadable timestamp: {}", &[&e.0])), c.end);
    }
    let mut a = ArchiveStamp {
        checked: true,
        valid: r.timestamp_ok == Some(true),
        trusted: r.timestamp_trusted == Some(true),
        time: r.timestamp_time,
        tsa: r.timestamp_info,
        error: None,
    };
    if !a.valid {
        a.error = Some(
            tr("the timestamp does not match the document (it or the document was changed)").into(),
        );
    } else if c.gap_bad {
        a.valid = false;
        a.error = Some(tr("The signature leaves out more of the file than its own value.").into());
    } else if !c.changes.is_empty() {
        a.valid = false;
        a.error = Some(trf(
            "the PDF was changed after it, not only by adding signatures: {}",
            &[&c.changes.join("; ")],
        ));
    }
    (a, c.end)
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
    // the document security store holds validation data, which later updates add to
    let dss = reference(b"DSS");
    for (id, now) in &new.objects {
        let Some(before) = old.objects.get(id) else {
            continue;
        };
        if before == now || Some(*id) == info || Some(*id) == metadata || Some(*id) == dss {
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
