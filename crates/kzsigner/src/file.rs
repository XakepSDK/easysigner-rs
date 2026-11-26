//! Signing a whole file, the one way every kzsigner front end does it: the command line, the
//! desktop window and the phone app all call [`Engine::sign_file`]. With
//! [`FileOptions::default`] (what each does unless told otherwise) the same file, key, time
//! and NCA answers give the same bytes, whichever one signed it.
//!
//! By default the file decides what signing makes ([`plan`]): a PDF is signed inside, with the
//! signer's box on the Who signed page; an XML document inside (an enveloped XAdES
//! signature); a .cms that holds its document gets the signature added; anything else goes
//! into a new .cms with the document inside. Each signature gets NCA's timestamp and is made
//! long-term (B-LTA); when that last step fails, the signature made stands, with a warning.

use std::path::Path;

use crate::ltv::Level;
use crate::p12::Key;
use crate::pdf::stamp::Stamp;
use crate::pdf::whosigned::WhoSigned;
use crate::report::SignResult;
use crate::{Cms, Engine, Error, Result, SignRequest, i18n};

/// What a file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Pdf,
    Xml,
    /// A signed .cms (CAdES).
    Cms,
    /// A signature key file (.p12).
    Key,
    Other,
}

/// What signing a file makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    /// The signature goes inside the PDF.
    InsidePdf,
    /// The signature goes inside the XML document.
    InsideXml,
    /// A .cms with the document and the signature inside.
    NewCms,
    /// The signature joins the others in the same .cms.
    JoinCms,
    /// It can't be signed as it is: a .cms without the document in it (a detached
    /// signature), an XML document whose signatures another one would break, or a key file.
    Cannot,
}

/// What signing a file named `name` makes by default, and the signed file's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub kind: Kind,
    pub output: Output,
    /// For a .cms: the name of the document inside (the file's name without ".cms").
    pub inner_name: Option<String>,
    /// The signed file's name: "X-signed.pdf", "X-signed.xml", "X.cms", or a joined .cms's
    /// own name.
    pub output_name: String,
}

/// What `bytes` is.
pub fn kind(e: &Engine, bytes: &[u8]) -> Kind {
    if e.is_pdf(bytes) {
        Kind::Pdf
    } else if e.is_xml(bytes) {
        Kind::Xml
    } else if e.is_signed_cms(bytes) {
        Kind::Cms
    } else if is_key(bytes) {
        Kind::Key
    } else {
        Kind::Other
    }
}

/// A .p12 file: it reads as one, only the password is missing.
fn is_key(bytes: &[u8]) -> bool {
    crate::p12::open(bytes, "", None).is_ok()
        || crate::p12::problem(bytes, "") == Some(crate::p12::Problem::WrongPassword)
}

/// What signing `bytes`, a file named `name`, makes by default. Offline and quick: it does
/// not check the signatures already there.
pub fn plan(e: &Engine, name: &str, bytes: &[u8]) -> Plan {
    let kind = kind(e, bytes);
    let (output, output_name, inner_name) = match kind {
        Kind::Pdf => (Output::InsidePdf, signed_name(name, "pdf"), None),
        Kind::Xml => {
            let room = e
                .verify(bytes, None, None)
                .map_or(true, |r| r.signers.is_empty())
                || e.xml_has_room(bytes);
            let output = if room {
                Output::InsideXml
            } else {
                Output::Cannot
            };
            (output, signed_name(name, "xml"), None)
        }
        Kind::Cms => {
            let output = if e.extract(bytes).is_ok() {
                Output::JoinCms
            } else {
                Output::Cannot
            };
            (output, name.to_string(), Some(inner_name(name)))
        }
        Kind::Key => (Output::Cannot, name.to_string(), None),
        Kind::Other => (Output::NewCms, format!("{name}.cms"), None),
    };
    Plan {
        kind,
        output,
        inner_name,
        output_name,
    }
}

/// "Dogovor.pdf" signed is "Dogovor-signed.pdf".
fn signed_name(name: &str, ext: &str) -> String {
    crate::signed_name(Path::new(name), ext)
        .to_string_lossy()
        .into_owned()
}

/// "Dogovor.pdf.cms" holds "Dogovor.pdf".
pub fn inner_name(name: &str) -> String {
    let lower = name.to_lowercase();
    for ext in [".cms", ".p7s", ".p7m", ".sig"] {
        if lower.ends_with(ext) && name.len() > ext.len() {
            return name[..name.len() - ext.len()].to_string();
        }
    }
    name.to_string()
}

/// What to make, when not what the file decides.
#[derive(Clone, Copy, Debug, Default)]
pub enum Make<'a> {
    /// What the file decides ([`plan`]).
    #[default]
    ByFile,
    /// A .cms around the document (or, `detached`, beside it); a .cms given as the input gets
    /// the signature added. `original`: a detached .cms's document, to co-sign it.
    Cms {
        detached: bool,
        original: Option<&'a [u8]>,
    },
    /// Inside the PDF: on the Who signed page, or with this stamp on a page instead.
    Pdf(Option<&'a Stamp>),
    /// Inside the XML document.
    Xml,
}

/// How to sign a file. The default is what every front end does unless told otherwise.
#[derive(Clone, Copy, Debug)]
pub struct FileOptions<'a> {
    pub make: Make<'a>,
    /// The timestamp server; None signs without NCA's time (and so not long-term).
    pub tsa_url: Option<&'a str>,
    /// The OCSP server: for the key's revocation check, and for the long-term data.
    pub ocsp_url: &'a str,
    /// Check that the key is not revoked before signing (a front end that checked already
    /// turns it off).
    pub check_revocation: bool,
    /// Long-term, after signing (with a timestamp only); None leaves the signature as made.
    pub level: Option<Level>,
}

impl Default for FileOptions<'_> {
    fn default() -> Self {
        FileOptions {
            make: Make::ByFile,
            tsa_url: Some(crate::DEFAULT_TSA_URL),
            ocsp_url: crate::DEFAULT_OCSP_URL,
            check_revocation: true,
            level: Some(Level::Lta),
        }
    }
}

/// A signed file.
#[derive(Debug)]
pub struct SignedFile {
    pub result: SignResult,
    pub output: Output,
    /// The signed file's name, as [`Plan::output_name`] gives it.
    pub name: String,
    /// How long-term the new signature was made; None when not (or when that failed).
    pub level: Option<Level>,
}

impl Engine {
    /// Signs `bytes`, a file named `name`, as `o` says; see the [module](crate::file).
    pub fn sign_file(
        &self,
        name: &str,
        bytes: &[u8],
        key: &Key,
        o: &FileOptions,
    ) -> Result<SignedFile> {
        let plan = plan(self, name, bytes);
        let page = WhoSigned {
            document: name.to_string(),
        };
        let cms = |detached, original| {
            SignRequest::cms(
                bytes,
                key,
                Cms {
                    detached,
                    cosign: true,
                    original,
                },
            )
        };
        let (req, output, out_name, original) = match o.make {
            Make::ByFile => match plan.output {
                Output::InsidePdf => (
                    SignRequest::pdf_page(bytes, key, &page),
                    plan.output,
                    plan.output_name,
                    None,
                ),
                Output::InsideXml => (
                    SignRequest::xml(bytes, key),
                    plan.output,
                    plan.output_name,
                    None,
                ),
                Output::NewCms | Output::JoinCms => {
                    (cms(false, None), plan.output, plan.output_name, None)
                }
                Output::Cannot => return Err(cannot(plan.kind)),
            },
            Make::Cms { detached, original } => {
                let (output, out_name) = if plan.kind == Kind::Cms {
                    (Output::JoinCms, name.to_string())
                } else {
                    (Output::NewCms, format!("{name}.cms"))
                };
                // a detached .cms's document: the original it co-signs, or the input itself
                let doc = original.or(detached.then_some(bytes));
                (cms(detached, original), output, out_name, doc)
            }
            Make::Pdf(stamp) => {
                if plan.kind != Kind::Pdf {
                    return Err(Error::new(i18n::tr("This file is not a PDF.")));
                }
                let req = match stamp {
                    Some(s) => SignRequest::pdf(bytes, key).stamp(Some(s)),
                    None => SignRequest::pdf_page(bytes, key, &page),
                };
                (req, Output::InsidePdf, signed_name(name, "pdf"), None)
            }
            Make::Xml => {
                if plan.kind != Kind::Xml {
                    return Err(Error::new(i18n::tr("This file is not an XML document.")));
                }
                (
                    SignRequest::xml(bytes, key),
                    Output::InsideXml,
                    signed_name(name, "xml"),
                    None,
                )
            }
        };
        let req = req
            .tsa(o.tsa_url)
            .ocsp(o.check_revocation.then_some(o.ocsp_url));
        let r = self.sign(req)?;
        let (result, level) = match (o.level, o.tsa_url) {
            (Some(level), Some(tsa)) => {
                match self.try_extend_new(&r, original, level, tsa, o.ocsp_url) {
                    Ok(x) => (x, Some(level)),
                    // the signature made stands
                    Err(e) => {
                        let mut r = r;
                        r.warnings.push(i18n::trf(
                            "The signature was made, but not as a long-term one: {}",
                            &[&e],
                        ));
                        (r, None)
                    }
                }
            }
            _ => (r, None),
        };
        Ok(SignedFile {
            result,
            output,
            name: out_name,
            level,
        })
    }
}

/// Why a file the plan can't sign is refused.
fn cannot(kind: Kind) -> Error {
    Error::new(i18n::tr(match kind {
        Kind::Xml => {
            "This XML document is already signed, and its signature covers everything in it, so another signature inside it would break that one. Add yours as a .cms file instead."
        }
        Kind::Key => "This is a key file, not a document to sign.",
        _ => {
            "This .cms does not hold the document it signs: give the document too to add a signature."
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans() {
        let e = Engine::new(vec![]);
        let fx = |p: &str| {
            std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../testdata")
                    .join(p),
            )
            .unwrap()
        };
        let p = plan(&e, "Dogovor.pdf", &fx("pdf/plain.pdf"));
        assert_eq!(
            (p.kind, p.output, p.output_name.as_str()),
            (Kind::Pdf, Output::InsidePdf, "Dogovor-signed.pdf")
        );
        let p = plan(&e, "act.xml", &fx("app/act.xml"));
        assert_eq!(
            (p.output, p.output_name.as_str()),
            (Output::InsideXml, "act-signed.xml")
        );
        let p = plan(&e, "note.txt", b"hello");
        assert_eq!(
            (p.output, p.output_name.as_str()),
            (Output::NewCms, "note.txt.cms")
        );
        let p = plan(&e, "doc.txt.cms", &fx("kalkan/detached_gost2015.cms"));
        assert_eq!(
            (p.kind, p.output, p.inner_name.as_deref()),
            (Kind::Cms, Output::Cannot, Some("doc.txt"))
        );
        let p = plan(&e, "key.p12", &fx("keys/alice_rsa.p12"));
        assert_eq!((p.kind, p.output), (Kind::Key, Output::Cannot));
        assert_eq!(inner_name("A.PDF.CMS"), "A.PDF");
    }
}
