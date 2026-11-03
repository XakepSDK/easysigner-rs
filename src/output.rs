//! Verification reports for the command line: plain text and JSON.

use std::fmt::Write as _;

use crate::report::{ArchiveStamp, SignerReport, VerifyReport};
use crate::time::{fmt, iso};

/// Plain-text verification report. `data`: the original file given for a detached .cms.
pub fn text(r: &VerifyReport, data: Option<&str>) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{}",
        if r.valid {
            format!(
                "RESULT: VALID - all {} signature(s) check out",
                r.signers.len()
            )
        } else {
            "RESULT: NOT VALID (see details below)".into()
        }
    );
    if let Some(name) = &r.card_document {
        let _ = writeln!(
            o,
            "Document: {name} (inside the document card), {} bytes, SHA-256 {}",
            r.content_size,
            r.content_sha256.as_deref().unwrap_or("")
        );
    } else if r.is_pdf {
        let _ = writeln!(
            o,
            "Document: PDF, {} bytes, SHA-256 {}",
            r.content_size,
            r.content_sha256.as_deref().unwrap_or("")
        );
    } else if r.has_content {
        let _ = writeln!(
            o,
            "Document: embedded, {} bytes, SHA-256 {}",
            r.content_size,
            r.content_sha256.as_deref().unwrap_or("")
        );
    } else if r.detached_provided {
        let _ = writeln!(
            o,
            "Document: detached, checked against {}",
            data.unwrap_or("the original")
        );
    }
    for w in &r.warnings {
        let _ = writeln!(o, "Note: {w}");
    }
    for a in &r.document_timestamps {
        let _ = writeln!(o, "Document timestamp: {}", stamp(a));
    }
    for s in &r.signers {
        let _ = writeln!(o);
        let _ = writeln!(
            o,
            "Signature #{}: {}",
            s.index,
            if s.valid { "VALID" } else { "NOT VALID" }
        );
        let line = |o: &mut String, k: &str, v: &str| {
            let _ = writeln!(o, "  {:<14} {v}", format!("{k}:"));
        };
        if let Some(k) = &s.kind {
            line(&mut o, "Type", k);
        }
        for n in &s.notes {
            line(&mut o, "Covers", n);
        }
        let given = s.get("G").map(|g| format!(" {g}")).unwrap_or_default();
        line(
            &mut o,
            "Signer",
            &format!("{}{given}", s.get("CN").unwrap_or("?")),
        );
        if let Some(v) = s.get("IIN") {
            line(&mut o, "IIN", v);
        }
        if let Some(org) = s.get("O") {
            let bin = s
                .get("BIN")
                .map(|b| format!(" (BIN {b})"))
                .unwrap_or_default();
            line(&mut o, "Organization", &format!("{org}{bin}"));
        }
        if let Some(v) = s.get("E") {
            line(&mut o, "Email", v);
        }
        line(&mut o, "Signed at", &signed_at(s));
        if let Some(l) = s.level {
            line(&mut o, "Level", &format!("{l} ({})", level_words(l)));
        }
        // a PDF's document timestamps are listed once, above
        if !r.is_pdf {
            for a in &s.archive_timestamps {
                line(&mut o, "Archived", &stamp(a));
            }
        }
        line(
            &mut o,
            "Algorithm",
            s.algorithm.as_deref().unwrap_or("null"),
        );
        line(
            &mut o,
            "Signature",
            if s.signature_ok {
                "matches the document"
            } else {
                s.signature_error.as_deref().unwrap_or("null")
            },
        );
        let types = if s.cert_types.is_empty() {
            String::new()
        } else {
            format!(", type {}", s.cert_types.join("/"))
        };
        line(
            &mut o,
            "Certificate",
            &format!(
                "serial {}, valid {} .. {}{types}",
                s.serial_hex.as_deref().unwrap_or("null"),
                fmt(s.not_before),
                fmt(s.not_after)
            ),
        );
        line(&mut o, "Issuer", s.issuer_cn.as_deref().unwrap_or("null"));
        line(&mut o, "Trust", s.chain_status.as_deref().unwrap_or("-"));
        if let Some(e) = &s.usage_error {
            line(&mut o, "Usage", e);
        }
        line(
            &mut o,
            "Revocation",
            s.ocsp_status
                .as_deref()
                .unwrap_or("not checked (use --ocsp, needs internet)"),
        );
        for w in &s.warnings {
            line(&mut o, "Warning", w);
        }
    }
    o
}

fn level_words(l: &str) -> &'static str {
    match l {
        "B-B" => "no timestamp",
        "B-T" => "timestamped",
        "B-LT" => "long-term: revocation data kept",
        "B-LTA" => "long-term with archive timestamp",
        _ => "",
    }
}

fn stamp(a: &ArchiveStamp) -> String {
    let state = if !a.checked {
        a.error.clone().unwrap_or_default()
    } else if !a.valid {
        format!("INVALID: {}", a.error.as_deref().unwrap_or(""))
    } else if a.trusted {
        "verified, trusted TSA".into()
    } else {
        "signature ok but TSA not trusted".into()
    };
    format!(
        "{} (by {}, {state})",
        fmt(a.time),
        a.tsa.as_deref().unwrap_or("unknown TSA")
    )
}

fn signed_at(s: &SignerReport) -> String {
    let Some(ts) = s.timestamp_time else {
        return format!("{} (signer's clock)", fmt(s.signing_time));
    };
    let state = if s.timestamp_ok != Some(true) {
        "INVALID"
    } else if s.timestamp_trusted == Some(true) {
        "verified, trusted TSA"
    } else {
        "signature ok but TSA not trusted"
    };
    format!(
        "{} (timestamp by {}, {state})",
        fmt(Some(ts)),
        s.timestamp_info.as_deref().unwrap_or("null")
    )
}

// ------------------------------------------------------------------ JSON

enum J {
    Null,
    Bool(bool),
    Num(i64),
    Str(String),
    List(Vec<J>),
    Obj(Vec<(String, J)>),
}

fn s(v: &Option<String>) -> J {
    v.as_ref().map(|x| J::Str(x.clone())).unwrap_or(J::Null)
}
fn b(v: Option<bool>) -> J {
    v.map(J::Bool).unwrap_or(J::Null)
}
fn t(v: Option<i64>) -> J {
    v.map(|x| J::Str(iso(x))).unwrap_or(J::Null)
}
fn strs(v: &[String]) -> J {
    J::List(v.iter().map(|x| J::Str(x.clone())).collect())
}
fn obj(fields: Vec<(&str, J)>) -> J {
    J::Obj(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

/// JSON for `verify --json`. Every field is always present (null when unknown); dates are
/// ISO-8601 UTC; the certificate is base64 DER. Field order is fixed.
pub fn json(r: &VerifyReport) -> String {
    let o = obj(vec![
        ("valid", J::Bool(r.valid)),
        ("hasContent", J::Bool(r.has_content)),
        ("detachedProvided", J::Bool(r.detached_provided)),
        ("contentSize", J::Num(r.content_size as i64)),
        ("contentSha256", s(&r.content_sha256)),
        ("warnings", strs(&r.warnings)),
        ("signers", J::List(r.signers.iter().map(signer).collect())),
        ("isPdf", J::Bool(r.is_pdf)),
        ("cardDocument", s(&r.card_document)),
        (
            "documentTimestamps",
            J::List(r.document_timestamps.iter().map(archive).collect()),
        ),
    ]);
    let mut out = String::new();
    write(&mut out, &o, "");
    out
}

fn archive(a: &ArchiveStamp) -> J {
    obj(vec![
        ("time", t(a.time)),
        ("authority", s(&a.tsa)),
        ("checked", J::Bool(a.checked)),
        ("valid", J::Bool(a.valid)),
        ("trusted", J::Bool(a.trusted)),
        ("error", s(&a.error)),
    ])
}

fn signer(x: &SignerReport) -> J {
    obj(vec![
        ("index", J::Num(x.index as i64)),
        ("valid", J::Bool(x.valid)),
        ("signatureOk", J::Bool(x.signature_ok)),
        ("signatureError", s(&x.signature_error)),
        (
            "subject",
            J::Obj(
                x.subject
                    .iter()
                    .map(|(k, v)| (k.clone(), J::Str(v.clone())))
                    .collect(),
            ),
        ),
        ("subjectDn", s(&x.subject_dn)),
        ("issuerDn", s(&x.issuer_dn)),
        ("issuerCn", s(&x.issuer_cn)),
        ("serial", s(&x.serial_hex)),
        ("notBefore", t(x.not_before)),
        ("notAfter", t(x.not_after)),
        ("signingTime", t(x.signing_time)),
        ("timestampTime", t(x.timestamp_time)),
        ("timestampOk", b(x.timestamp_ok)),
        ("timestampAuthority", s(&x.timestamp_info)),
        ("timestampTrusted", b(x.timestamp_trusted)),
        ("algorithm", s(&x.algorithm)),
        ("certTypes", strs(&x.cert_types)),
        ("chainOk", J::Bool(x.chain_ok)),
        ("chainStatus", s(&x.chain_status)),
        ("chain", strs(&x.chain)),
        ("usageError", s(&x.usage_error)),
        // at the trusted timestamp's time, or at checkedAt (the moment of checking) without one
        ("certValidAtSigning", b(x.cert_valid_at_signing)),
        ("checkedAt", t(x.checked_at)),
        ("ocspStatus", s(&x.ocsp_status)),
        // "ocsp", "crl", "kept-ocsp" or "kept-crl" (an answer kept in the signature), or null
        // when there is no revocation answer
        (
            "revocationSource",
            x.revocation_source
                .map(|v| J::Str(v.into()))
                .unwrap_or(J::Null),
        ),
        // "B-B", "B-T", "B-LT" or "B-LTA" (ETSI baseline levels)
        (
            "level",
            x.level.map(|v| J::Str(v.into())).unwrap_or(J::Null),
        ),
        (
            "archiveTimestamps",
            J::List(x.archive_timestamps.iter().map(archive).collect()),
        ),
        ("warnings", strs(&x.warnings)),
        ("kind", s(&x.kind)),
        ("notes", strs(&x.notes)),
        (
            "certificate",
            x.cert_der
                .as_ref()
                .map(|d| J::Str(crate::base64_encode(d)))
                .unwrap_or(J::Null),
        ),
    ])
}

/// JSON string escaping as org.json's JSONObject.quote does it (`</` as `<\/`).
fn quote(out: &mut String, v: &str) {
    out.push('"');
    let mut prev = '\0';
    for c in v.chars() {
        match c {
            '\\' | '"' => {
                out.push('\\');
                out.push(c);
            }
            '/' => {
                if prev == '<' {
                    out.push('\\');
                }
                out.push(c);
            }
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c < ' '
                || ('\u{80}'..'\u{a0}').contains(&c)
                || ('\u{2000}'..'\u{2100}').contains(&c) =>
            {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
        prev = c;
    }
    out.push('"');
}

fn write(out: &mut String, v: &J, indent: &str) {
    let inner = format!("{indent}  ");
    match v {
        J::Null => out.push_str("null"),
        J::Bool(x) => out.push_str(if *x { "true" } else { "false" }),
        J::Num(n) => {
            let _ = write!(out, "{n}");
        }
        J::Str(x) => quote(out, x),
        J::List(l) if l.is_empty() => out.push_str("[]"),
        J::Obj(f) if f.is_empty() => out.push_str("{}"),
        J::List(l) => {
            out.push_str("[\n");
            for (i, x) in l.iter().enumerate() {
                out.push_str(&inner);
                write(out, x, &inner);
                out.push_str(if i + 1 < l.len() { ",\n" } else { "\n" });
            }
            out.push_str(indent);
            out.push(']');
        }
        J::Obj(f) => {
            out.push_str("{\n");
            for (i, (k, x)) in f.iter().enumerate() {
                out.push_str(&inner);
                quote(out, k);
                out.push_str(": ");
                write(out, x, &inner);
                out.push_str(if i + 1 < f.len() { ",\n" } else { "\n" });
            }
            out.push_str(indent);
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn quoting() {
        let mut o = String::new();
        super::quote(&mut o, "a\"b</c\nд");
        assert_eq!(o, r#""a\"b<\/c\nд""#);
    }
}
