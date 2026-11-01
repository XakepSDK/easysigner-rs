//! What signing and verifying found: the data the command line and the window show.

/// Everything checked and found about one signature (or, for `describe`, one certificate).
#[derive(Clone, Debug, Default)]
pub struct SignerReport {
    pub index: usize,
    pub valid: bool,
    pub signature_ok: bool,
    pub signature_error: Option<String>,
    /// Subject name attributes by short label (CN, G, O, IIN, BIN, ...), in order.
    pub subject: Vec<(String, String)>,
    pub subject_dn: Option<String>,
    pub issuer_dn: Option<String>,
    pub issuer_cn: Option<String>,
    pub serial_hex: Option<String>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub signing_time: Option<i64>,
    pub timestamp_time: Option<i64>,
    pub timestamp_info: Option<String>,
    pub timestamp_ok: Option<bool>,
    pub timestamp_trusted: Option<bool>,
    pub algorithm: Option<String>,
    pub cert_types: Vec<String>,
    pub chain_status: Option<String>,
    pub chain_ok: bool,
    /// Certificate path, signer first, as common names.
    pub chain: Vec<String>,
    pub cert_valid_at_signing: Option<bool>,
    /// None when not checked.
    pub ocsp_status: Option<String>,
    pub warnings: Vec<String>,
    pub cert_der: Option<Vec<u8>>,
    /// What kind of signature this is, when not a plain .cms signer (e.g. a PDF signature).
    pub kind: Option<String>,
    /// Facts about the signature that are not problems (e.g. what part of a PDF it covers).
    pub notes: Vec<String>,
}

impl SignerReport {
    pub fn get(&self, k: &str) -> Option<&str> {
        crate::cert::get(&self.subject, k)
    }

    /// Display name: CN plus given name.
    pub fn name(&self) -> String {
        let cn = self.get("CN").unwrap_or("Unknown");
        match self.get("G") {
            Some(g) => format!("{cn} {g}"),
            None => cn.to_string(),
        }
    }
}

/// Result of verifying a .cms: the document and every signature in it.
#[derive(Clone, Debug, Default)]
pub struct VerifyReport {
    pub valid: bool,
    /// The file was a PDF with signatures inside it (the content fields describe the PDF).
    pub is_pdf: bool,
    /// The file was a document card (ddcard); the name of the original document inside it.
    pub card_document: Option<String>,
    pub has_content: bool,
    pub content_size: u64,
    pub content_sha256: Option<String>,
    pub detached_provided: bool,
    pub signers: Vec<SignerReport>,
    pub warnings: Vec<String>,
}

/// Outcome of signing: the new .cms bytes and what happened.
#[derive(Clone, Debug, Default)]
pub struct SignResult {
    /// The signed output: a .cms, or the PDF with the signature inside it.
    pub cms: Vec<u8>,
    pub cosigned: bool,
    pub signer_count: usize,
    pub timestamped: bool,
    pub warnings: Vec<String>,
}
