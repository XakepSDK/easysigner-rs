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
    /// Why the certificate may not sign documents under its CA's policy (key usage, purpose,
    /// certificate policy; Order 500/НҚ p.16.4), when its CA was found.
    pub usage_error: Option<String>,
    /// Whether the signer's certificate was valid at the reference time: the trusted timestamp's
    /// time, or the moment of checking when there is none (Order 500/НҚ p.13-14).
    pub cert_valid_at_signing: Option<bool>,
    /// That reference time (ms).
    pub checked_at: Option<i64>,
    /// None when not checked.
    pub ocsp_status: Option<String>,
    /// The OCSP answer when checked: "good", "revoked", "unknown", or "" when none came (no
    /// network, a broken or untrusted response).
    pub ocsp_answer: Option<&'static str>,
    /// Where the revocation answer came from: "ocsp", "crl" (OCSP gave none and a current
    /// revocation list decided), or None when there is no answer.
    pub revocation_source: Option<&'static str>,
    pub warnings: Vec<String>,
    pub cert_der: Option<Vec<u8>>,
    /// The ETSI baseline level the signature reaches: "B-B", "B-T" (signature timestamp),
    /// "B-LT" (with the revocation data to check it later), "B-LTA" (and archive timestamps).
    pub level: Option<&'static str>,
    /// The signature's archive timestamps (CAdES archive-time-stamp-v3, or PDF document
    /// timestamps that cover it).
    pub archive_timestamps: Vec<ArchiveStamp>,
    /// What kind of signature this is, when not a plain .cms signer (e.g. a PDF signature).
    pub kind: Option<String>,
    /// Facts about the signature that are not problems (e.g. what part of a PDF it covers).
    pub notes: Vec<String>,
}

impl SignerReport {
    /// The time a valid timestamp from a trusted TSA proves; None when there is none.
    pub fn trusted_time(&self) -> Option<i64> {
        (self.timestamp_ok == Some(true) && self.timestamp_trusted == Some(true))
            .then_some(self.timestamp_time)
            .flatten()
    }

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

/// An archive timestamp (CAdES archive-time-stamp-v3, or a PDF document timestamp).
#[derive(Clone, Debug, Default)]
pub struct ArchiveStamp {
    /// Whether it could be checked (a detached signature's needs the document).
    pub checked: bool,
    /// Its signature and message imprint hold.
    pub valid: bool,
    /// From a trusted TSA.
    pub trusted: bool,
    pub time: Option<i64>,
    pub tsa: Option<String>,
    /// Why it is not valid, or why it was not checked.
    pub error: Option<String>,
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
    /// A PDF's document timestamps (ETSI.RFC3161), oldest first.
    pub document_timestamps: Vec<ArchiveStamp>,
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
    /// The new signature's value, which tells it apart from the others in a .cms.
    pub signature: Vec<u8>,
    pub warnings: Vec<String>,
}
