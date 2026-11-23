//! Checking a signed file for the app (screens 5 and 6): one verdict, each signer with one
//! reason when theirs fails, and the details a specialist asks for.

use std::sync::Arc;

use kzsigner::cert::{Cert, get, rdns};
use kzsigner::i18n::Lang;
use kzsigner::report::{SignerReport, VerifyReport};

use crate::sign::{DocKind, Nca, inner_name, kind_of};

/// What the check found, for the whole file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Verdict {
    /// Every signature is valid.
    Valid,
    /// A signature is not valid: see the signer's [`Reason`].
    Invalid,
    /// Nothing is wrong that the phone could see, but NCA did not confirm a key: no answer.
    Unknown,
    /// The file has no signature.
    NotSigned,
    /// A .cms with only the signatures: checking needs the document it signs.
    NeedsDocument,
}

/// Why one signature is not valid: one reason, the first that applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Reason {
    /// The document was changed after it was signed.
    Changed,
    /// NCA says the signer's key was revoked before the signature was made.
    Revoked,
    /// The key was no longer (or not yet) valid at NCA's signing time.
    Expired,
    /// No NCA time, and the key is no longer valid: it can't be checked anymore.
    ExpiredSince,
    /// Not a key from NCA or another CA recognized in Kazakhstan, or not one for signing.
    NotRecognized,
    /// The signature itself is broken (cut or damaged file, a bad timestamp).
    Damaged,
    /// NCA did not answer whether the key was valid (the verdict is then Unknown).
    NotConfirmed,
}

/// How the file carries its signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Format {
    /// PAdES: inside the PDF.
    Pdf,
    /// XAdES: inside the XML document.
    Xml,
    /// CAdES: a .cms with the document inside.
    Cms,
    /// CAdES: a .cms beside the document (detached).
    DetachedCms,
    /// A document card (a PDF that carries the original and its .cms signatures).
    Card,
}

/// One signature.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignerCheck {
    pub valid: bool,
    pub reason: Option<Reason>,
    pub name: String,
    pub iin: Option<String>,
    pub company: Option<String>,
    pub bin: Option<String>,
    /// When it was signed: NCA's time when `nca_time`, else what the signer's computer said.
    pub signed_ms: Option<i64>,
    pub nca_time: bool,
    /// The key's certificate validity.
    pub valid_from_ms: Option<i64>,
    pub expires_ms: Option<i64>,
    /// For the details screen, in the language given to [`check_file`].
    pub algorithm: Option<String>,
    pub serial: Option<String>,
    pub issuer: Option<String>,
    pub revocation: Option<String>,
    /// "B-B", "B-T", "B-LT", "B-LTA".
    pub level: Option<String>,
    /// What the core found, in that language: for "Copy details".
    pub problems: Vec<String>,
}

/// A checked file.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Checked {
    pub verdict: Verdict,
    pub format: Option<Format>,
    pub signers: Vec<SignerCheck>,
    /// The signed document's name: the file's, or for a .cms the one inside it.
    pub document_name: String,
    /// The signed document itself, to open: the file, or what is inside a .cms.
    pub document: Option<Vec<u8>>,
    /// SHA-256 of the signed document, hex.
    pub fingerprint: Option<String>,
}

/// Checks the signatures in `bytes`, a file named `name` (`original`: the document a
/// detached .cms signs), asking NCA whether each key was valid. `lang`: the app's language,
/// for the texts in the details. Blocks: call it off the main thread.
#[uniffi::export]
pub fn check_file(
    nca: Arc<Nca>,
    name: String,
    bytes: Vec<u8>,
    original: Option<Vec<u8>>,
    lang: String,
) -> Checked {
    kzsigner::i18n::set(Lang::parse(&lang).unwrap_or(Lang::En));
    let e = &nca.engine;
    let kind = kind_of(e, &bytes);
    let mut out = Checked {
        verdict: Verdict::NotSigned,
        format: None,
        signers: vec![],
        document_name: name.clone(),
        document: None,
        fingerprint: None,
    };
    if kind == DocKind::Other {
        out.document = Some(bytes);
        return out;
    }
    let content = if kind == DocKind::Cms {
        out.document_name = inner_name(&name);
        e.extract(&bytes).ok()
    } else {
        None
    };
    out.format = Some(match kind {
        DocKind::Pdf if e.card_original(&bytes).is_some() => Format::Card,
        DocKind::Pdf => Format::Pdf,
        DocKind::Xml => Format::Xml,
        _ if content.is_some() => Format::Cms,
        _ => Format::DetachedCms,
    });
    if out.format == Some(Format::DetachedCms) && original.is_none() {
        out.verdict = Verdict::NeedsDocument;
        out.signers = crate::sign::signers(e, &bytes)
            .into_iter()
            .map(|s| SignerCheck {
                valid: false,
                reason: None,
                name: s.name,
                iin: None,
                company: s.company,
                bin: None,
                signed_ms: s.signed_ms,
                nca_time: false,
                valid_from_ms: None,
                expires_ms: None,
                algorithm: None,
                serial: None,
                issuer: None,
                revocation: None,
                level: None,
                problems: vec![],
            })
            .collect();
        return out;
    }
    let doc = match out.format {
        Some(Format::Card) => e.card_original(&bytes).map(|(n, d)| {
            out.document_name = n;
            d
        }),
        Some(Format::Cms) => content,
        Some(Format::DetachedCms) => original.clone(),
        _ => Some(bytes.clone()),
    };
    out.fingerprint = doc
        .as_deref()
        .map(|d| kzsigner::hex(&kzsigner::gost::sha256(d)));
    out.document = doc;
    let rep = match e.verify(&bytes, original.as_deref(), Some(&nca.ocsp)) {
        Ok(r) => r,
        Err(err) => {
            // a PDF or XML document without signatures reads as one; anything else is broken
            if kind == DocKind::Cms {
                out.verdict = Verdict::Invalid;
                out.signers = vec![broken(err.0)];
            }
            return out;
        }
    };
    out.signers = rep.signers.iter().map(signer).collect();
    out.signers.sort_by_key(|s| s.signed_ms.unwrap_or(i64::MAX));
    out.verdict = verdict(&rep, &out.signers);
    out
}

fn verdict(rep: &VerifyReport, signers: &[SignerCheck]) -> Verdict {
    if signers.is_empty() {
        Verdict::NotSigned
    } else if rep.valid {
        Verdict::Valid
    } else if signers
        .iter()
        .all(|s| s.valid || s.reason == Some(Reason::NotConfirmed))
        && !rep
            .document_timestamps
            .iter()
            .any(|a| a.checked && !a.valid)
    {
        Verdict::Unknown
    } else {
        Verdict::Invalid
    }
}

/// A .cms that can't be read at all.
fn broken(why: String) -> SignerCheck {
    SignerCheck {
        valid: false,
        reason: Some(Reason::Damaged),
        name: String::new(),
        iin: None,
        company: None,
        bin: None,
        signed_ms: None,
        nca_time: false,
        valid_from_ms: None,
        expires_ms: None,
        algorithm: None,
        serial: None,
        issuer: None,
        revocation: None,
        level: None,
        problems: vec![why],
    }
}

fn signer(s: &SignerReport) -> SignerCheck {
    let company = s
        .cert_der
        .as_deref()
        .and_then(|d| Cert::parse(d).ok())
        .and_then(|c| get(&rdns(&c.subject), "O").map(str::to_string));
    let nca = s.trusted_time();
    let mut problems: Vec<String> = s.signature_error.iter().cloned().collect();
    problems.extend(s.warnings.iter().cloned());
    SignerCheck {
        valid: s.valid,
        reason: s.reason().map(Reason::from),
        name: s.name(),
        iin: s.get("IIN").map(str::to_string),
        company,
        bin: s.get("BIN").map(str::to_string),
        signed_ms: nca.or(s.timestamp_time).or(s.signing_time),
        nca_time: nca.is_some(),
        valid_from_ms: s.not_before,
        expires_ms: s.not_after,
        algorithm: s.algorithm.clone(),
        serial: s.serial_hex.clone(),
        issuer: s.issuer_cn.clone(),
        revocation: s.ocsp_status.clone(),
        level: s.level.map(str::to_string),
        problems,
    }
}

impl From<kzsigner::report::Reason> for Reason {
    fn from(r: kzsigner::report::Reason) -> Self {
        use kzsigner::report::Reason as R;
        match r {
            R::Changed => Reason::Changed,
            R::Revoked => Reason::Revoked,
            R::Expired => Reason::Expired,
            R::ExpiredSince => Reason::ExpiredSince,
            R::NotRecognized => Reason::NotRecognized,
            R::Damaged => Reason::Damaged,
            R::NotConfirmed => Reason::NotConfirmed,
        }
    }
}
