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
    /// The CA's revocation answer, when one was looked for (online, or kept in the signature).
    pub revocation: Option<Answer>,
    /// Where the revocation answer came from; None when there is no answer.
    pub revocation_source: Option<Source>,
    pub warnings: Vec<String>,
    pub cert_der: Option<Vec<u8>>,
    /// The ETSI baseline level the signature reaches.
    pub level: Option<Baseline>,
    /// The signature's archive timestamps (CAdES archive-time-stamp-v3, or PDF document
    /// timestamps that cover it).
    pub archive_timestamps: Vec<ArchiveStamp>,
    /// What kind of signature this is, when not a plain .cms signer (e.g. a PDF signature).
    pub kind: Option<String>,
    /// Facts about the signature that are not problems (e.g. what part of a PDF it covers).
    pub notes: Vec<String>,
}

pub use kzcrypto::ocsp::CertStatus;

/// A revocation answer looked for: what the CA said, or that nothing usable came (no network, a
/// broken or untrusted response, no current list).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Answer {
    Said(CertStatus),
    NoAnswer,
}

impl Answer {
    pub fn status(self) -> Option<CertStatus> {
        match self {
            Answer::Said(s) => Some(s),
            Answer::NoAnswer => None,
        }
    }

    /// "good", "revoked", "unknown", or "" for no answer.
    pub fn code(self) -> &'static str {
        self.status().map_or("", CertStatus::code)
    }
}

impl From<Option<CertStatus>> for Answer {
    fn from(s: Option<CertStatus>) -> Answer {
        s.map_or(Answer::NoAnswer, Answer::Said)
    }
}

/// Where a revocation answer came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// NCA's OCSP server, asked now.
    Ocsp,
    /// A current revocation list, fetched now because OCSP gave no answer.
    Crl,
    /// An OCSP answer kept in the signature (B-LT).
    KeptOcsp,
    /// A revocation list kept in the signature.
    KeptCrl,
}

impl Source {
    /// "ocsp", "crl", "kept-ocsp" or "kept-crl".
    pub fn code(self) -> &'static str {
        match self {
            Source::Ocsp => "ocsp",
            Source::Crl => "crl",
            Source::KeptOcsp => "kept-ocsp",
            Source::KeptCrl => "kept-crl",
        }
    }

    /// Kept in the signature, not asked now.
    pub fn kept(self) -> bool {
        matches!(self, Source::KeptOcsp | Source::KeptCrl)
    }

    /// The same source, kept in the signature.
    pub fn as_kept(self) -> Source {
        match self {
            Source::Ocsp | Source::KeptOcsp => Source::KeptOcsp,
            Source::Crl | Source::KeptCrl => Source::KeptCrl,
        }
    }
}

/// The ETSI baseline level a signature reaches (EN 319 122-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Baseline {
    /// B-B: signed, no timestamp.
    B,
    /// B-T: with a signature timestamp.
    T,
    /// B-LT: and the revocation data to check it later.
    Lt,
    /// B-LTA: and archive timestamps.
    Lta,
}

impl Baseline {
    /// "B-B", "B-T", "B-LT" or "B-LTA".
    pub fn code(self) -> &'static str {
        match self {
            Baseline::B => "B-B",
            Baseline::T => "B-T",
            Baseline::Lt => "B-LT",
            Baseline::Lta => "B-LTA",
        }
    }
}

impl std::fmt::Display for Baseline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// Why one signature is not valid, as a code a screen can turn into words: the first that
/// applies, the most serious first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The document was changed after it was signed.
    Changed,
    /// The CA says the signer's key was revoked.
    Revoked,
    /// The key was no longer (or not yet) valid at the trusted signing time.
    Expired,
    /// No trusted signing time, and the key is no longer valid: it can't be checked anymore.
    ExpiredSince,
    /// Not a key from a recognized CA, or not one for signing.
    NotRecognized,
    /// The signature itself is broken (cut or damaged file, a bad timestamp).
    Damaged,
    /// The CA did not answer whether the key was valid.
    NotConfirmed,
}

impl SignerReport {
    /// Why this signature is not valid; None when it is.
    pub fn reason(&self) -> Option<Reason> {
        if self.valid {
            return None;
        }
        Some(if self.cert_der.is_none() {
            // the signature could not even be read
            Reason::Damaged
        } else if !self.signature_ok {
            // read, but the document doesn't match it
            Reason::Changed
        } else if self.status() == Some(CertStatus::Revoked) {
            Reason::Revoked
        } else if !self.chain_ok
            || self.usage_error.is_some()
            || self.status() == Some(CertStatus::Unknown)
        {
            Reason::NotRecognized
        } else if self.timestamp_ok == Some(false) {
            Reason::Damaged
        } else if self.cert_valid_at_signing == Some(false) {
            if self.trusted_time().is_some() {
                Reason::Expired
            } else {
                Reason::ExpiredSince
            }
        } else if self.status().is_none() || self.revocation_source.is_some_and(Source::kept) {
            // no answer now, and none kept in the signature that settles it
            Reason::NotConfirmed
        } else {
            // the CA said good: what failed is an archive timestamp
            Reason::Damaged
        })
    }

    /// What the CA said about the signer's certificate; None when it was not asked or said
    /// nothing usable.
    pub fn status(&self) -> Option<CertStatus> {
        self.revocation.and_then(Answer::status)
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Each reason, the most serious first: a report that fails in one way only, then in two.
    #[test]
    fn reasons() {
        let good = SignerReport {
            cert_der: Some(vec![1]),
            signature_ok: true,
            chain_ok: true,
            cert_valid_at_signing: Some(true),
            revocation: Some(Answer::Said(CertStatus::Good)),
            revocation_source: Some(Source::Ocsp),
            ..Default::default()
        };
        let r = |f: &dyn Fn(&mut SignerReport)| {
            let mut s = good.clone();
            f(&mut s);
            s.reason()
        };
        assert_eq!(r(&|s| s.valid = true), None);
        // only an archive timestamp can have failed
        assert_eq!(r(&|_| {}), Some(Reason::Damaged));
        assert_eq!(r(&|s| s.cert_der = None), Some(Reason::Damaged));
        assert_eq!(r(&|s| s.signature_ok = false), Some(Reason::Changed));
        let revoked = Some(Answer::Said(CertStatus::Revoked));
        assert_eq!(r(&|s| s.revocation = revoked), Some(Reason::Revoked));
        assert_eq!(r(&|s| s.chain_ok = false), Some(Reason::NotRecognized));
        assert_eq!(
            r(&|s| s.usage_error = Some("x".into())),
            Some(Reason::NotRecognized)
        );
        let unknown = Some(Answer::Said(CertStatus::Unknown));
        assert_eq!(r(&|s| s.revocation = unknown), Some(Reason::NotRecognized));
        assert_eq!(r(&|s| s.timestamp_ok = Some(false)), Some(Reason::Damaged));
        assert_eq!(r(&|s| s.timestamp_ok = Some(true)), Some(Reason::Damaged));
        assert_eq!(
            r(&|s| s.cert_valid_at_signing = Some(false)),
            Some(Reason::ExpiredSince)
        );
        assert_eq!(
            r(&|s| {
                s.cert_valid_at_signing = Some(false);
                s.timestamp_ok = Some(true);
                s.timestamp_trusted = Some(true);
                s.timestamp_time = Some(1);
            }),
            Some(Reason::Expired)
        );
        assert_eq!(
            r(&|s| s.revocation = Some(Answer::NoAnswer)),
            Some(Reason::NotConfirmed)
        );
        assert_eq!(r(&|s| s.revocation = None), Some(Reason::NotConfirmed));
        assert_eq!(
            r(&|s| s.revocation_source = Some(Source::KeptOcsp)),
            Some(Reason::NotConfirmed)
        );
        assert_eq!(
            r(&|s| s.revocation_source = Some(Source::Crl)),
            Some(Reason::Damaged)
        );
        // the more serious first
        assert_eq!(
            r(&|s| {
                s.signature_ok = false;
                s.revocation = revoked;
            }),
            Some(Reason::Changed)
        );
        assert_eq!(
            r(&|s| {
                s.revocation = revoked;
                s.chain_ok = false;
            }),
            Some(Reason::Revoked)
        );
        assert_eq!(
            r(&|s| {
                s.chain_ok = false;
                s.timestamp_ok = Some(false);
            }),
            Some(Reason::NotRecognized)
        );
        assert_eq!(
            r(&|s| {
                s.timestamp_ok = Some(false);
                s.cert_valid_at_signing = Some(false);
            }),
            Some(Reason::Damaged)
        );
        assert_eq!(
            r(&|s| {
                s.cert_valid_at_signing = Some(false);
                s.revocation = None;
            }),
            Some(Reason::ExpiredSince)
        );
    }

    #[test]
    fn codes() {
        let all = [Source::Ocsp, Source::Crl, Source::KeptOcsp, Source::KeptCrl];
        let codes: Vec<_> = all.iter().map(|s| s.code()).collect();
        assert_eq!(codes, ["ocsp", "crl", "kept-ocsp", "kept-crl"]);
        let kept: Vec<_> = all.iter().map(|s| s.kept()).collect();
        assert_eq!(kept, [false, false, true, true]);
        let as_kept: Vec<_> = all.iter().map(|s| s.as_kept()).collect();
        assert_eq!(
            as_kept,
            [
                Source::KeptOcsp,
                Source::KeptCrl,
                Source::KeptOcsp,
                Source::KeptCrl
            ]
        );

        let levels = [Baseline::B, Baseline::T, Baseline::Lt, Baseline::Lta];
        let names: Vec<_> = levels.iter().map(|l| l.to_string()).collect();
        assert_eq!(names, ["B-B", "B-T", "B-LT", "B-LTA"]);

        assert_eq!(Answer::from(None), Answer::NoAnswer);
        assert_eq!(Answer::NoAnswer.code(), "");
        let said = Answer::from(Some(CertStatus::Revoked));
        assert_eq!(
            (said, said.code()),
            (Answer::Said(CertStatus::Revoked), "revoked")
        );
        assert_eq!(Answer::Said(CertStatus::Good).code(), "good");
        assert_eq!(Answer::Said(CertStatus::Unknown).code(), "unknown");

        let mut s = SignerReport::default();
        assert_eq!(s.status(), None);
        s.revocation = Some(Answer::NoAnswer);
        assert_eq!(s.status(), None);
        s.revocation = Some(said);
        assert_eq!(s.status(), Some(CertStatus::Revoked));
    }
}
