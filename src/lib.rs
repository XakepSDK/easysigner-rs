//! kzsigner: sign and verify .cms files with Kazakhstan NCA RK keys, locally, without NCALayer.

#[cfg(all(target_os = "android", feature = "gui"))]
pub mod android;
pub mod cert;
pub mod cms;
pub mod crl;
pub mod der;
pub mod gost;
#[cfg(feature = "gui")]
pub mod gui;
pub mod http;
pub mod i18n;
#[cfg(feature = "gui")]
pub mod icons;
pub mod keys;
pub mod ocsp;
pub mod output;
pub mod p12;
pub mod pdf;
pub mod report;
pub mod sign;
pub mod time;
pub mod trust;
pub mod tsp;
pub mod verify;

use cert::Cert;
use p12::Key;
use report::{SignResult, SignerReport, VerifyReport};
use trust::TrustStore;

pub const DEFAULT_TSA_URL: &str = tsp::DEFAULT_TSA_URL;
pub const DEFAULT_OCSP_URL: &str = ocsp::DEFAULT_URL;

/// kzsigner's own version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn crypto_version() -> &'static str {
    "built in (KZ GOST in Rust; hashes, ciphers and RSA from RustCrypto)"
}

/// What the command line and the window use: open a key, sign, verify, extract.
pub struct Engine {
    trust: TrustStore,
}

impl Engine {
    /// `extra_trust`: CA certificates to trust on top of the bundled NCA RK ones.
    pub fn new(extra_trust: Vec<Cert>) -> Engine {
        Engine {
            trust: TrustStore::new(extra_trust),
        }
    }

    pub fn open_key(&self, p12: &[u8], password: &str, alias: Option<&str>) -> Result<Key> {
        p12::open(p12, password, alias)
    }

    pub fn key_warnings(&self, c: &Cert) -> Vec<String> {
        cert::key_warnings(c)
    }

    /// See [`sign::sign`].
    pub fn sign(
        &self,
        input: &[u8],
        key: &Key,
        detached: bool,
        tsa_url: Option<&str>,
        cosign_if_cms: bool,
        detached_original: Option<&[u8]>,
    ) -> Result<SignResult> {
        sign::sign(
            input,
            key,
            detached,
            tsa_url,
            cosign_if_cms,
            detached_original,
            &self.trust,
        )
    }

    /// Signs a PDF inside the PDF (PAdES); see [`pdf::sign`].
    pub fn sign_pdf(&self, input: &[u8], key: &Key, tsa_url: Option<&str>) -> Result<SignResult> {
        pdf::sign(input, key, tsa_url, &self.trust)
    }

    /// Signs `input` into a document card (ddcard), checking the signature first; see
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
        let mut r = SignResult::default();
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
        let cms =
            pdf::card::sign_for_card(&doc, &name, key, tsa_url, ocsp_url, &self.trust, &mut r)?;
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
        r.cms = pdf::card::build(&input, &self.trust)?;
        r.signer_count = input.signatures.len();
        Ok(r)
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
        let mut rep = pdf::card::verify(&card, &self.trust, ocsp_url);
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
            return Ok(pdf::card::verify(&card, &self.trust, ocsp_url));
        }
        if pdf::is_pdf(cms) {
            return pdf::verify(cms, &self.trust, ocsp_url);
        }
        verify::verify(cms, detached_original, &self.trust, ocsp_url)
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
        let chain = self.trust.check(c, time::now_ms());
        sr.chain_ok = chain.ok;
        sr.chain_status = Some(chain.status);
        sr.chain = chain.path;
        sr.usage_error = cert::usage_problem(c, chain.issuer.as_ref());
        sr.algorithm = Some(cert::key_alg_name(c));
        sr
    }
}

/// An error meant to be shown to the user as-is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub String);

impl Error {
    pub fn new(m: impl Into<String>) -> Error {
        Error(m.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Random bytes from the operating system.
pub fn random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::new(format!("no random numbers from the system: {e}")))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Standard Base64 without whitespace; padding optional. None if it is not Base64.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s.trim_end_matches('='))
        .ok()
}
