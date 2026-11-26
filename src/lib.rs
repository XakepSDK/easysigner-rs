//! kzsigner: sign and verify .cms files with Kazakhstan NCA RK keys, locally, without NCALayer.

pub mod asn1;
pub mod cert;
pub mod cms;
pub mod crl;
pub mod env;
pub mod gost;
pub(crate) mod http;
pub mod i18n;
pub(crate) mod keys;
pub mod ltv;
pub mod ocsp;
pub mod output;
pub mod p12;
pub mod pdf;
pub mod report;
pub mod request;
pub(crate) mod sign;
pub mod text;
pub mod time;
pub mod trust;
pub mod tsp;
pub mod vault;
pub mod verify;
pub(crate) mod xml;

/// The cryptography, for callers that use it directly.
pub use kzcrypto;

use cert::Cert;
use p12::Key;
use report::{SignResult, SignerReport, VerifyReport};
pub use request::{Cms, Form, SignRequest};
use trust::TrustStore;

pub const DEFAULT_TSA_URL: &str = tsp::DEFAULT_TSA_URL;
pub const DEFAULT_OCSP_URL: &str = ocsp::DEFAULT_URL;

/// kzsigner's own version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn crypto_version() -> &'static str {
    "kzcrypto (KZ GOST in Rust; hashes, ciphers and RSA from RustCrypto)"
}

/// What the command line and the window use: open a key, sign, verify, extract.
pub struct Engine {
    env: env::Env,
}

impl Engine {
    /// `extra_trust`: CA certificates to trust on top of the bundled NCA RK ones.
    pub fn new(extra_trust: Vec<Cert>) -> Engine {
        Engine {
            env: env::Env::new(TrustStore::new(extra_trust)),
        }
    }

    /// An engine over `env`: its trusted CAs, network and clock (tests use fakes).
    pub fn with_env(env: env::Env) -> Engine {
        Engine { env }
    }

    pub fn env(&self) -> &env::Env {
        &self.env
    }

    pub fn open_key(&self, p12: &[u8], password: &str, alias: Option<&str>) -> Result<Key> {
        Ok(p12::open(p12, password, alias)?)
    }

    pub fn key_warnings(&self, c: &Cert) -> Vec<String> {
        cert::key_warnings(c, self.env.now_ms())
    }

    /// Checks the signer's own key before signing (Order 500/НҚ p.4): issued by a trusted CA,
    /// valid now, allowed to sign, and, with `ocsp_url`, not revoked. Returns the warnings
    /// (e.g. a revocation check that got no answer).
    pub fn check_key(&self, c: &Cert, ocsp_url: Option<&str>) -> Result<Vec<String>> {
        sign::check_key(c, ocsp_url, &self.env)
    }

    /// Signs as `req` asks. The key is checked first ([`Engine::check_key`]; for revocation
    /// too with an OCSP server); its warnings come first in the result's.
    pub fn sign(&self, req: SignRequest) -> Result<SignResult> {
        let SignRequest {
            input,
            key,
            form,
            tsa_url,
            ocsp_url,
        } = req;
        if let Form::Hash = form {
            sign::check_hash_length(input, key)?;
        }
        let mut warnings = self.check_key(&key.cert, ocsp_url)?;
        let env = &self.env;
        let mut r = match form {
            Form::Cms(c) => sign::sign(input, key, c.detached, tsa_url, c.cosign, c.original, env)?,
            Form::Hash => sign::sign_hash(input, key, tsa_url, env)?,
            Form::Pdf(stamp) => pdf::sign(input, key, tsa_url, env, stamp)?,
            Form::PdfPage(page) => {
                pdf::sign_with(input, key, tsa_url, env, pdf::Look::WhoSigned(page))?
            }
            Form::Xml => xml::sign(input, key, tsa_url, env)?,
        };
        warnings.append(&mut r.warnings);
        r.warnings = warnings;
        Ok(r)
    }

    /// Whether another signature can go inside the signed XML document `data` without breaking
    /// the ones there.
    pub fn xml_has_room(&self, data: &[u8]) -> bool {
        xml::has_room(data)
    }

    /// Whether `data` is an XML document.
    pub fn is_xml(&self, data: &[u8]) -> bool {
        xml::is_xml(data)
    }

    /// Signs `input` into a document card (ddcard), checking the key and the signature
    /// first; see
    /// [`pdf::card`]. If `input` is already a card, the signature is added to it and the card
    /// is made again. A card needs a timestamp, and asks for an OCSP answer kept in the
    /// signature (a missing one only warns). `lang` and `qr`: None to keep what the card had
    /// (Russian, without QR codes, for a new card).
    #[allow(clippy::too_many_arguments)]
    pub fn sign_card(
        &self,
        input: &[u8],
        file_name: &str,
        key: &Key,
        tsa_url: &str,
        ocsp_url: &str,
        lang: Option<pdf::card::CardLang>,
        qr: Option<bool>,
    ) -> Result<SignResult> {
        let mut r = SignResult {
            // revocation is checked when the card's OCSP answer is fetched
            warnings: self.check_key(&key.cert, None)?,
            ..Default::default()
        };
        let (name, doc, mut signatures, made_with) = match pdf::card::read(input) {
            Some(c) => {
                r.cosigned = true;
                (c.original.0, c.original.1, c.signatures, c.made_with)
            }
            None => (file_name.to_string(), input.to_vec(), vec![], None),
        };
        let lang = lang
            .or(made_with.map(|m| m.0))
            .unwrap_or(pdf::card::CardLang::Ru);
        let qr = qr.or(made_with.map(|m| m.1)).unwrap_or(false);
        let cms = pdf::card::sign_for_card(&doc, &name, key, tsa_url, ocsp_url, &self.env, &mut r)?;
        let mut n = signatures.len() + 1;
        while signatures
            .iter()
            .any(|(s, _)| *s == pdf::card::signature_file_name(&name, n))
        {
            n += 1;
        }
        signatures.push((pdf::card::signature_file_name(&name, n), cms));
        let input = pdf::card::CardInput {
            doc: &doc,
            file_name: &name,
            signatures,
            lang,
            qr,
        };
        r.cms = pdf::card::build(&input, &self.env)?;
        r.signer_count = input.signatures.len();
        Ok(r)
    }

    /// Makes the signatures in a .cms, a PDF or an XML document long-term (B-LT, or B-LTA with an archive
    /// timestamp); see [`pdf::extend`]. `original`: a detached .cms's
    /// document.
    pub fn extend(
        &self,
        input: &[u8],
        original: Option<&[u8]>,
        level: ltv::Level,
        tsa_url: &str,
        ocsp_url: &str,
    ) -> Result<SignResult> {
        let archive = level == ltv::Level::Lta;
        if pdf::card::read(input).is_some() {
            return Err(Error::new(i18n::tr(
                "A document card's signatures already keep their revocation answers; a card cannot be extended.",
            )));
        }
        if pdf::is_pdf(input) {
            return pdf::extend(input, archive, tsa_url, ocsp_url, &self.env);
        }
        if xml::is_xml(input) {
            if original.is_some() {
                return Err(Error::new(i18n::tr(
                    "An XML document's signatures are inside it: extend the signed XML file alone, without --data.",
                )));
            }
            return xml::ltv::extend(input, archive, tsa_url, ocsp_url, &self.env, None);
        }
        sign::extend(input, original, archive, tsa_url, ocsp_url, &self.env, None)
    }

    /// [`Engine::extend`] after signing: in a .cms, only the new signature (`r.signature`);
    /// in a PDF, every signature (they share its validation data). The result keeps `r`'s
    /// warnings first. When that fails, the signature made stands as it is, with a warning.
    pub fn extend_new(
        &self,
        mut r: SignResult,
        original: Option<&[u8]>,
        level: ltv::Level,
        tsa_url: &str,
        ocsp_url: &str,
    ) -> SignResult {
        let x = if pdf::is_pdf(&r.cms) {
            self.extend(&r.cms, original, level, tsa_url, ocsp_url)
        } else if xml::is_xml(&r.cms) {
            xml::ltv::extend(
                &r.cms,
                level == ltv::Level::Lta,
                tsa_url,
                ocsp_url,
                &self.env,
                Some(&r.signature),
            )
        } else {
            sign::extend(
                &r.cms,
                original,
                level == ltv::Level::Lta,
                tsa_url,
                ocsp_url,
                &self.env,
                Some(&r.signature),
            )
        };
        let mut x = match x {
            Ok(x) => x,
            Err(e) => {
                r.warnings.push(i18n::trf(
                    "The signature was made, but not as a long-term one: {}",
                    &[&e],
                ));
                return r;
            }
        };
        let mut warnings = r.warnings;
        warnings.append(&mut x.warnings);
        SignResult {
            warnings,
            timestamped: r.timestamped,
            cosigned: r.cosigned,
            signer_count: r.signer_count,
            signature: r.signature,
            cms: x.cms,
        }
    }

    /// The original document inside a document card: (file name, bytes). None if `data` is
    /// not a card.
    pub fn card_original(&self, data: &[u8]) -> Option<(String, Vec<u8>)> {
        pdf::card::read(data).map(|c| c.original)
    }

    /// Checks the signatures carried by scanned QR codes (one scanned text per line) against
    /// the original document.
    pub fn verify_qr(
        &self,
        scans: &str,
        original: &[u8],
        ocsp_url: Option<&str>,
    ) -> Result<VerifyReport> {
        let sigs = pdf::qr::assemble(scans)?;
        let card = pdf::card::Card {
            original: (String::new(), original.to_vec()),
            signatures: sigs
                .into_iter()
                .map(|(id, c)| (format!("{id}.cms"), c))
                .collect(),
            made_with: None,
        };
        let mut rep = pdf::card::verify(&card, &self.env, ocsp_url);
        rep.card_document = None;
        rep.has_content = false;
        rep.detached_provided = true;
        for s in &mut rep.signers {
            s.kind = None;
        }
        Ok(rep)
    }

    /// Checks a .cms, or the signatures inside a PDF. `ocsp_url`: None to skip the revocation
    /// check.
    pub fn verify(
        &self,
        cms: &[u8],
        detached_original: Option<&[u8]>,
        ocsp_url: Option<&str>,
    ) -> Result<VerifyReport> {
        if let Some(card) = pdf::card::read(cms) {
            return Ok(pdf::card::verify(&card, &self.env, ocsp_url));
        }
        if pdf::is_pdf(cms) {
            return pdf::verify(cms, &self.env, ocsp_url);
        }
        if xml::is_xml(cms) {
            if detached_original.is_some() {
                return Err(Error::new(i18n::tr(
                    "An XML signature is inside the document it signs: check the signed XML file alone.",
                )));
            }
            return xml::verify(cms, &self.env, ocsp_url);
        }
        verify::verify(cms, detached_original, &self.env, ocsp_url)
    }

    /// Whether `data` is a PDF.
    pub fn is_pdf(&self, data: &[u8]) -> bool {
        pdf::is_pdf(data)
    }

    pub fn extract(&self, cms: &[u8]) -> Result<Vec<u8>> {
        cms::SignedData::parse(cms)?.content.ok_or_else(|| {
            Error::new(i18n::tr("This .cms has no embedded document: it is a detached signature, the original was never inside it."))
        })
    }

    /// Whether `data` is a CMS SignedData with at least one signature.
    pub fn is_signed_cms(&self, data: &[u8]) -> bool {
        cms::SignedData::try_parse(data).is_some()
    }

    /// Certificate details and trust status, without any signature.
    pub fn describe(&self, c: &Cert) -> SignerReport {
        let mut sr = SignerReport::default();
        cert::describe(&mut sr, c);
        let chain = self.env.trust.check(c, self.env.now_ms());
        sr.chain_ok = chain.ok;
        sr.chain_status = Some(i18n::text(&chain.status));
        sr.chain = chain.path;
        sr.usage_error = cert::usage_problem(c, chain.issuer.as_ref());
        sr.algorithm = Some(cert::key_alg_name(c));
        sr
    }
}

/// What went wrong. Callers branch on the variant; [`Display`](std::fmt::Display) words it in
/// the language set in [`i18n`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// From the cryptography (parsing, keys, signatures), kept as kzcrypto's value.
    Crypto(kzcrypto::Error),
    /// A server could not be reached, or answered with something other than an answer.
    Network {
        server: Server,
        url: String,
        problem: NetProblem,
    },
    /// Anything else, already worded for people.
    Message(String),
}

/// Which of NCA's servers (or another one) a network error is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Server {
    Timestamp,
    Ocsp,
    RevocationList,
}

/// How talking to a server failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetProblem {
    /// Only http:// addresses are supported.
    NotHttp,
    /// No connection, a timeout, a broken answer: the transport's own words.
    Unreachable(String),
    /// An HTTP status other than 200.
    Status(u16),
    /// The answer was larger than this many bytes.
    TooLarge(u64),
}

impl Error {
    /// An error worded for people.
    pub fn new(m: impl Into<String>) -> Error {
        Error::Message(m.into())
    }

    /// The server a network error is about.
    pub fn server(&self) -> Option<Server> {
        match self {
            Error::Network { server, .. } => Some(*server),
            _ => None,
        }
    }
}

impl Server {
    /// "timestamp server", in the reader's language.
    pub fn name(self) -> &'static str {
        match self {
            Server::Timestamp => i18n::tr("timestamp server"),
            Server::Ocsp => i18n::tr("OCSP server"),
            Server::RevocationList => i18n::tr("revocation list server"),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use i18n::{tr, trf};
        match self {
            Error::Crypto(e) => f.write_str(&i18n::text(e)),
            Error::Message(m) => f.write_str(m),
            Error::Network {
                server,
                url,
                problem,
            } => {
                let name = server.name();
                f.write_str(&match problem {
                    NetProblem::NotHttp => trf(
                        "Could not reach the {} at {}: {}",
                        &[
                            &name,
                            url,
                            &tr("only http:// is supported (NCA's timestamp, OCSP and CRL servers use http)"),
                        ],
                    ),
                    NetProblem::Unreachable(why) => {
                        trf("Could not reach the {} at {}: {}", &[&name, url, why])
                    }
                    NetProblem::Status(code) => {
                        trf("The {} answered HTTP {} ({})", &[&name, code, url])
                    }
                    NetProblem::TooLarge(n) => trf(
                        "The {} at {} sent an answer larger than {} bytes",
                        &[&name, url, n],
                    ),
                })
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

impl From<kzcrypto::Error> for Error {
    fn from(e: kzcrypto::Error) -> Error {
        Error::Crypto(e)
    }
}

impl From<::der::oid::Error> for Error {
    fn from(e: ::der::oid::Error) -> Error {
        Error::Crypto(kzcrypto::Error::Asn1(format!("bad object identifier: {e}")))
    }
}

impl From<::der::Error> for Error {
    fn from(e: ::der::Error) -> Error {
        Error::Crypto(kzcrypto::Error::Asn1(format!("{e}")))
    }
}

/// Random bytes from the operating system.
pub fn random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::new(format!("no random numbers from the system: {e}")))
}

/// The operating system's random generator, for [`kzcrypto`].
pub struct OsRng;

impl kzcrypto::Rng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> kzcrypto::Result<()> {
        getrandom::fill(buf).map_err(|e| kzcrypto::Error::Random(e.to_string()))
    }
}

/// The name for a document signed inside it: document.pdf -> document-signed.pdf.
pub fn signed_name(file: &std::path::Path, ext: &str) -> std::path::PathBuf {
    let stem = file
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    file.with_file_name(format!("{stem}-signed.{ext}"))
}

pub use kzcrypto::{base64_decode, base64_encode, hex};
