//! Signing for the app: what a file is and what signing it makes ([`inspect`]), and
//! [`Vault::sign`]. Output by input, with no options: a PDF gets its signature inside (with a
//! stamp on its last page), an XML document too, a received .cms gets the signature added,
//! anything else becomes a .cms with the document inside.

use std::path::Path;
use std::sync::Arc;

use kzsigner::cert::{self, Cert, get, rdns};
use kzsigner::i18n::Lang;
use kzsigner::pdf::whosigned::WhoSigned;
use kzsigner::report::{SignResult, SignerReport};
use kzsigner::vault::VaultError;
use kzsigner::{Engine, ltv};
use zeroize::Zeroizing;

use crate::{CantSign, ChipPrompt, Vault, cant_sign, now};

/// NCA's servers, and the CAs signing trusts (NCA RK's).
#[derive(uniffi::Object)]
pub struct Nca {
    pub(crate) tsa: String,
    pub(crate) ocsp: String,
    pub(crate) engine: Engine,
}

#[uniffi::export]
impl Nca {
    /// The real ones: tsp.pki.gov.kz and ocsp.pki.gov.kz.
    #[uniffi::constructor]
    pub fn kazakhstan() -> Arc<Nca> {
        Arc::new(Nca::with(
            kzsigner::DEFAULT_TSA_URL,
            kzsigner::DEFAULT_OCSP_URL,
            vec![],
        ))
    }

    /// Fake servers at `tsa` and `ocsp`, with the CA certificates in `cas` trusted too: for
    /// the emulator tests only (the app's test build). Certificates that don't parse are left
    /// out.
    #[uniffi::constructor]
    pub fn for_tests(tsa: String, ocsp: String, cas: Vec<Vec<u8>>) -> Arc<Nca> {
        let cas = cas.iter().filter_map(|c| Cert::parse_any(c).ok()).collect();
        Arc::new(Nca::with(&tsa, &ocsp, cas))
    }
}

impl Nca {
    /// NotRecognized when `c` is not from NCA or another CA recognized in Kazakhstan, or not a
    /// key for signing documents; checked offline.
    pub(crate) fn unrecognized(&self, c: &Cert) -> Option<CantSign> {
        let env = self.engine.env();
        let chain = env.trust.check(c, env.now_ms());
        (!chain.ok || cert::usage_problem(c, chain.issuer.as_ref()).is_some())
            .then_some(CantSign::NotRecognized)
    }

    /// Other servers and extra trusted CAs: the tests' fake ones.
    pub(crate) fn with(tsa: &str, ocsp: &str, extra_trust: Vec<Cert>) -> Nca {
        Nca {
            tsa: tsa.into(),
            ocsp: ocsp.into(),
            engine: Engine::new(extra_trust),
        }
    }
}

/// What a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DocKind {
    Pdf,
    Xml,
    /// A signed .cms (CAdES).
    Cms,
    /// A signature key file (.p12): it goes to Add key.
    Key,
    Other,
}

/// What signing a file makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Output {
    /// The signature goes inside the PDF, with a stamp on its last page.
    InsidePdf,
    /// The signature goes inside the XML document.
    InsideXml,
    /// A .cms with the document and the signature inside.
    NewCms,
    /// The signature joins the others in the same .cms.
    JoinCms,
    /// It can't be signed here: a .cms without the document in it (a detached signature), or
    /// an XML document whose signatures another one would break.
    Cannot,
}

/// Someone who already signed the file.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignedBy {
    pub name: String,
    pub company: Option<String>,
    /// When: NCA's time when the signature has one, else the time the signer's computer
    /// gave (milliseconds since 1970, UTC).
    pub signed_ms: Option<i64>,
}

/// A file about to be signed.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Doc {
    pub kind: DocKind,
    /// For a .cms: the name of the document inside (the file's name without ".cms").
    pub inner_name: Option<String>,
    /// For a .cms: what the document inside is (PDF, XML or other).
    pub inner_kind: Option<DocKind>,
    /// Who signed it already, oldest first. Whether those signatures are valid is checked by
    /// Check, not here.
    pub signers: Vec<SignedBy>,
    pub output: Output,
    /// A PDF with the Who signed page at its end (its last page): a signature adds a box there.
    pub who_signed_page: bool,
    /// The signed file's name.
    pub output_name: String,
}

/// A signed file.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Signed {
    pub bytes: Vec<u8>,
    pub name: String,
    /// NCA's time for the new signature (milliseconds since 1970, UTC).
    pub nca_time_ms: Option<i64>,
    /// The signature joined others in the same file.
    pub joined: bool,
}

/// Why nothing was signed.
#[derive(Debug, uniffi::Error)]
pub enum SignError {
    /// NCA did not answer: no internet, or NCA is down (the app can tell which).
    NoAnswer,
    /// The key can't sign; nothing was asked or signed.
    KeyCantSign {
        reason: CantSign,
        valid_from_ms: i64,
        expires_ms: i64,
    },
    /// The key's password is wrong (a key kept under its password).
    WrongPassword,
    /// Too many wrong passwords: try again after this many seconds.
    Wait {
        seconds: u64,
    },
    /// The owner closed the fingerprint/PIN prompt.
    Cancelled,
    /// The phone reset the key's protection: the key file has to be added again.
    KeyReset,
    NoSuchKey,
    /// See [`Output::Cannot`].
    Cannot,
    Failed {
        detail: String,
    },
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// What `bytes`, a file named `name`, is, who signed it, and what signing it will make.
/// Offline and quick: it does not check the signatures.
#[uniffi::export]
pub fn inspect(name: String, bytes: Vec<u8>) -> Doc {
    let e = Engine::new(vec![]);
    let kind = kind(&e, &bytes);
    let mut doc = Doc {
        kind,
        inner_name: None,
        inner_kind: None,
        signers: vec![],
        output: Output::NewCms,
        who_signed_page: false,
        output_name: format!("{name}.cms"),
    };
    match kind {
        DocKind::Pdf => {
            doc.signers = signers(&e, &bytes);
            doc.output = Output::InsidePdf;
            doc.who_signed_page = kzsigner::pdf::whosigned::ends_with_page(&bytes);
            doc.output_name = signed_name(&name, "pdf");
        }
        DocKind::Xml => {
            doc.signers = signers(&e, &bytes);
            doc.output = if doc.signers.is_empty() || e.xml_has_room(&bytes) {
                Output::InsideXml
            } else {
                Output::Cannot
            };
            doc.output_name = signed_name(&name, "xml");
        }
        DocKind::Cms => {
            doc.signers = signers(&e, &bytes);
            doc.inner_name = Some(inner_name(&name));
            match e.extract(&bytes) {
                Ok(inner) => {
                    doc.inner_kind = Some(match kind_of(&e, &inner) {
                        k @ (DocKind::Pdf | DocKind::Xml) => k,
                        _ => DocKind::Other,
                    });
                    doc.output = Output::JoinCms;
                }
                Err(_) => doc.output = Output::Cannot,
            }
            doc.output_name = name;
        }
        DocKind::Key => {
            doc.output = Output::Cannot;
            doc.output_name = name;
        }
        DocKind::Other => {}
    }
    doc
}

/// The document inside a .cms, to read it; None for a detached signature.
#[uniffi::export]
pub fn cms_content(bytes: Vec<u8>) -> Option<Vec<u8>> {
    Engine::new(vec![]).extract(&bytes).ok()
}

fn kind(e: &Engine, bytes: &[u8]) -> DocKind {
    match kind_of(e, bytes) {
        DocKind::Other if is_key(bytes) => DocKind::Key,
        k => k,
    }
}

pub(crate) fn kind_of(e: &Engine, bytes: &[u8]) -> DocKind {
    if e.is_pdf(bytes) {
        DocKind::Pdf
    } else if e.is_xml(bytes) {
        DocKind::Xml
    } else if e.is_signed_cms(bytes) {
        DocKind::Cms
    } else {
        DocKind::Other
    }
}

/// A .p12 file: it reads as one, only the password is missing.
fn is_key(bytes: &[u8]) -> bool {
    kzsigner::p12::open(bytes, "", None).is_ok()
        || kzsigner::p12::problem(bytes, "") == Some(kzsigner::p12::Problem::WrongPassword)
}

/// "Dogovor.pdf.cms" holds "Dogovor.pdf".
pub(crate) fn inner_name(name: &str) -> String {
    let lower = name.to_lowercase();
    for ext in [".cms", ".p7s", ".p7m", ".sig"] {
        if lower.ends_with(ext) && name.len() > ext.len() {
            return name[..name.len() - ext.len()].to_string();
        }
    }
    name.to_string()
}

/// "Dogovor.pdf" signed is "Dogovor-signed.pdf".
fn signed_name(name: &str, ext: &str) -> String {
    kzsigner::signed_name(Path::new(name), ext)
        .to_string_lossy()
        .into_owned()
}

/// Who signed `bytes`, oldest first, from the file alone.
pub(crate) fn signers(e: &Engine, bytes: &[u8]) -> Vec<SignedBy> {
    let Ok(r) = e.verify(bytes, None, None) else {
        return vec![];
    };
    let mut v: Vec<SignedBy> = r.signers.iter().map(signed_by).collect();
    v.sort_by_key(|s| s.signed_ms.unwrap_or(i64::MAX));
    v
}

fn signed_by(s: &SignerReport) -> SignedBy {
    let company = s
        .cert_der
        .as_deref()
        .and_then(|d| Cert::parse(d).ok())
        .and_then(|c| get(&rdns(&c.subject), "O").map(str::to_string));
    SignedBy {
        name: s.name(),
        company,
        signed_ms: s.timestamp_time.or(s.signing_time),
    }
}

/// Why `c` can't sign today, asking NCA: before any prompt, so a key that can't sign asks
/// nothing. `Ok` when NCA says it is good.
fn check(nca: &Nca, c: &Cert) -> Result<(), SignError> {
    let refuse = |reason| SignError::KeyCantSign {
        reason,
        valid_from_ms: c.not_before,
        expires_ms: c.not_after,
    };
    if let Some(r) = cant_sign(c, now()) {
        return Err(refuse(r));
    }
    let env = nca.engine.env();
    let chain = env.trust.check(c, env.now_ms());
    if !chain.ok || cert::usage_problem(c, chain.issuer.as_ref()).is_some() {
        return Err(refuse(CantSign::NotRecognized));
    }
    let (_, _, answer, _) =
        kzsigner::verify::revocation(c, chain.issuer.as_ref(), &nca.ocsp, env, None);
    match answer {
        "good" => Ok(()),
        "revoked" => Err(refuse(CantSign::Revoked)),
        "" => Err(SignError::NoAnswer),
        _ => Err(refuse(CantSign::NotRecognized)),
    }
}

#[uniffi::export]
impl Vault {
    /// Signs `bytes`, a file named `name`, with key `key_id`: checks the key with NCA first
    /// (no prompt for a key that can't sign, or without internet), then opens it (one
    /// prompt, or `password` for a key kept under its password) and signs with NCA's time.
    /// `lang`: the app's language, for the core's messages. Blocks: call it off the main thread.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &self,
        nca: Arc<Nca>,
        key_id: String,
        name: String,
        bytes: Vec<u8>,
        password: Option<String>,
        prompt: ChipPrompt,
        lang: String,
    ) -> Result<Signed, SignError> {
        kzsigner::i18n::set(Lang::parse(&lang).unwrap_or(Lang::En));
        let doc = inspect(name.clone(), bytes.clone());
        if doc.output == Output::Cannot {
            return Err(SignError::Cannot);
        }
        let cert = {
            let s = self.store();
            let e = s
                .keys()
                .iter()
                .find(|e| e.id == key_id)
                .ok_or(SignError::NoSuchKey)?;
            e.cert().clone()
        };
        check(&nca, &cert)?;
        let password = password.map(Zeroizing::new);
        let key = self
            .store()
            .key(
                &key_id,
                password.as_deref().map(String::as_str),
                &prompt.into(),
            )
            .map_err(|e| match e {
                VaultError::Cancelled => SignError::Cancelled,
                VaultError::KeyReset => SignError::KeyReset,
                VaultError::WrongPassword => SignError::WrongPassword,
                VaultError::Wait(seconds) => SignError::Wait { seconds },
                VaultError::NoSuchKey => SignError::NoSuchKey,
                e => SignError::Failed {
                    detail: e.to_string(),
                },
            })?;
        let e = &nca.engine;
        let tsa = Some(nca.tsa.as_str());
        // revocation was checked above: not twice
        let r = match doc.output {
            Output::InsidePdf => {
                let page = WhoSigned {
                    document: name.clone(),
                };
                e.sign_pdf_page(&bytes, &key, tsa, None, &page)
            }
            Output::InsideXml => e.sign_xml(&bytes, &key, tsa, None),
            _ => e.sign(&bytes, &key, false, tsa, None, true, None),
        }
        .map_err(|x| {
            // NCA's timestamp server not answering; anything else is a failure to show
            if x.server() == Some(kzsigner::Server::Timestamp) {
                SignError::NoAnswer
            } else {
                SignError::Failed {
                    detail: x.to_string(),
                }
            }
        })?;
        // long-term, as the desktop app does by default: when that fails, the signature
        // made stands
        let r = e.extend_new(r, None, ltv::Level::Lta, &nca.tsa, &nca.ocsp);
        Ok(Signed {
            nca_time_ms: nca_time(e, &r),
            joined: r.cosigned,
            bytes: r.cms,
            name: doc.output_name,
        })
    }
}

/// NCA's time on the newest signature in `r`.
fn nca_time(e: &Engine, r: &SignResult) -> Option<i64> {
    let rep = e.verify(&r.cms, None, None).ok()?;
    rep.signers.iter().filter_map(|s| s.timestamp_time).max()
}
