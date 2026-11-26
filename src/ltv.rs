//! Long-term signatures (ETSI EN 319 122-1 B-LT and B-LTA; Order 500/НҚ p.5-8): the
//! certificates and revocation answers needed to check a signature years later, kept inside
//! it, and archive timestamps over all of it.

use crate::asn1::ber;
use crate::cert::Cert;
use crate::cms::{SignedData, SignerInfo};
use ::der::asn1::{Any, ObjectIdentifier, OctetString};
use ::der::{Decode, Encode, Sequence, Tag, TagNumber, Tagged};

use crate::env::Env;
use crate::i18n::{tr, trf};
use crate::report::{ArchiveStamp, CertStatus, SignerReport, Source};
use crate::tsp::{self, TstInfo};
use crate::{Error, Result, crl, gost, ocsp};

/// id-aa-ets-revocationValues (CAdES, RFC 5126).
pub const ATTR_REVOCATION_VALUES: &str = "1.2.840.113549.1.9.16.2.24";
/// id-aa-ets-certValues (CAdES, RFC 5126).
pub const ATTR_CERT_VALUES: &str = "1.2.840.113549.1.9.16.2.23";
/// id-aa-ets-archiveTimestampV3 (ETSI EN 319 122-1).
pub const ATTR_ARCHIVE_TIMESTAMP_V3: &str = "0.4.0.1733.2.4";
/// id-aa-ATSHashIndex-v3 (ETSI EN 319 122-1), inside an archive timestamp.
pub const ATTR_ATS_HASH_INDEX_V3: &str = "0.4.0.19122.1.5";
/// id-ri-ocsp-response (RFC 5940): an OCSP answer in SignedData's `crls`.
pub const RI_OCSP: &str = "1.3.6.1.5.5.7.16.2";

const MINUTE: i64 = 60 * 1000;

/// How long-term a signature is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// B-LT: the validation data is kept in it.
    Lt,
    /// B-LTA: and an archive timestamp covers everything.
    Lta,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        match s.to_ascii_uppercase().trim_start_matches("B-") {
            "LT" => Some(Level::Lt),
            "LTA" => Some(Level::Lta),
            _ => None,
        }
    }
}

/// Validation data: certificates, OCSP answers (whole OCSPResponses) and CRLs, each as
/// encoded, each once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Kept {
    pub certs: Vec<Vec<u8>>,
    pub ocsps: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
}

fn add(list: &mut Vec<Vec<u8>>, item: &[u8]) {
    if !item.is_empty() && !list.iter().any(|x| x == item) {
        list.push(item.to_vec());
    }
}

impl Kept {
    pub fn is_empty(&self) -> bool {
        self.certs.is_empty() && self.ocsps.is_empty() && self.crls.is_empty()
    }

    pub fn extend(&mut self, o: &Kept) {
        for c in &o.certs {
            add(&mut self.certs, c);
        }
        for c in &o.ocsps {
            add(&mut self.ocsps, c);
        }
        for c in &o.crls {
            add(&mut self.crls, c);
        }
    }

    /// The data a CMS keeps: its certificates and `crls` (CRLs, and OCSP answers in the RFC
    /// 5940 form), and, for `si`, its certValues and revocationValues attributes and what its
    /// archive timestamps carry.
    pub fn from_cms(sd: &SignedData, si: Option<&SignerInfo>) -> Kept {
        let mut k = Kept::default();
        k.add_signed_data(sd);
        let Some(si) = si else {
            return k;
        };
        for (oid, values) in si.unsigned() {
            for v in values {
                match oid.as_str() {
                    ATTR_REVOCATION_VALUES => k.add_revocation_values(&v),
                    ATTR_CERT_VALUES => {
                        for c in items(&v) {
                            add(&mut k.certs, &c);
                        }
                    }
                    ATTR_ARCHIVE_TIMESTAMP_V3 => {
                        if let Ok(t) = SignedData::parse_inner(&v) {
                            k.add_signed_data(&t);
                        }
                    }
                    _ => {}
                }
            }
        }
        k
    }

    fn add_signed_data(&mut self, sd: &SignedData) {
        for c in &sd.certs {
            add(&mut self.certs, c);
        }
        for item in sd.crl_items() {
            let Ok(t) = Any::from_der(&item) else {
                continue;
            };
            if t.tag() == Tag::Sequence {
                add(&mut self.crls, &item);
            } else if t.tag() == OTHER_REVOCATION_INFO
                && let Ok(o) = OtherRevocationInfo::from_der(&as_sequence(&item))
                && o.format.to_string() == RI_OCSP
                && let Ok(raw) = o.info.to_der()
            {
                add(&mut self.ocsps, &raw);
            }
        }
    }

    /// RevocationValues: crlVals [0] SEQUENCE OF CertificateList, ocspVals [1] SEQUENCE OF
    /// BasicOCSPResponse.
    fn add_revocation_values(&mut self, v: &[u8]) {
        let Ok(rv) = ber::<RevocationValues>(v) else {
            return;
        };
        for c in rv.crl_vals.iter().flatten() {
            if let Ok(c) = c.to_der() {
                add(&mut self.crls, &c);
            }
        }
        for b in rv.ocsp_vals.iter().flatten() {
            if let Ok(o) = b
                .to_der()
                .map_err(Error::from)
                .and_then(|b| Ok(ocsp::wrap_basic(&b)?))
            {
                add(&mut self.ocsps, &o);
            }
        }
    }

    /// What `self` holds that `other` does not.
    pub fn without(&self, other: &Kept) -> Kept {
        let minus = |a: &[Vec<u8>], b: &[Vec<u8>]| -> Vec<Vec<u8>> {
            a.iter().filter(|x| !b.contains(x)).cloned().collect()
        };
        Kept {
            certs: minus(&self.certs, &other.certs),
            ocsps: minus(&self.ocsps, &other.ocsps),
            crls: minus(&self.crls, &other.crls),
        }
    }

    /// The certificates that parse.
    pub fn certificates(&self) -> Vec<Cert> {
        self.certs
            .iter()
            .filter_map(|c| Cert::parse(c).ok())
            .collect()
    }

    /// What this data says about `c` (issued by `issuer`) at `at`, the time the signature is
    /// checked at: a kept OCSP answer made no earlier than `at` (Order 500/НҚ p.19.6), or a kept
    /// CRL current at `at`. An older OCSP answer is returned, marked not fresh, only when
    /// nothing better is kept.
    pub fn status(&self, c: &Cert, issuer: &Cert, env: &Env, at: i64) -> Option<KeptStatus> {
        let trust = &env.trust;
        let mut stale = None;
        for raw in &self.ocsps {
            let Ok(a) = ocsp::read_embedded(raw, c, issuer, trust) else {
                continue;
            };
            let Some(cert_status) = a.cert_status else {
                continue;
            };
            let fresh = a.this_update.is_some_and(|u| u + 5 * MINUTE >= at);
            let (answer, status) = good_if_later(
                cert_status,
                crate::i18n::text(&a.status),
                a.revoked_at.zip(a.untrusted_from),
                at,
            );
            let s = KeptStatus {
                answer,
                status,
                source: Source::Ocsp,
                fresh,
                this_update: a.this_update,
                responder: a.responder,
            };
            if fresh || s.answer == CertStatus::Revoked {
                return Some(s);
            }
            stale.get_or_insert(s);
        }
        let lists: Vec<crl::Crl> = self
            .crls
            .iter()
            .filter_map(|d| crl::Crl::parse(d).ok())
            .filter(|l| crate::cert::names_equal(&l.issuer, &c.issuer))
            .collect();
        for base in lists.iter().filter(|l| !l.is_delta) {
            let delta = lists
                .iter()
                .filter(|l| l.is_delta && l.unusable(c, issuer, at, &trust.policy).is_none())
                .max_by_key(|l| l.this_update);
            let (_, status, answer) =
                crl::evaluate(base, delta, false, c, issuer, at, &trust.policy);
            if let Some(answer) = answer {
                let (answer, status) =
                    good_if_later(answer, status, crl_revocation(base, delta, c), at);
                return Some(KeptStatus {
                    answer,
                    status,
                    source: Source::Crl,
                    fresh: true,
                    this_update: Some(delta.map_or(base.this_update, |d| d.this_update)),
                    responder: None,
                });
            }
        }
        stale
    }
}

/// A "revoked" answer for a certificate revoked only after `at`, the time the signature is
/// checked at, is good there (Order 500/НҚ p.14), unless its key was compromised before.
/// `revoked`: (revocation date, untrusted from), as [`ocsp::Answer`] and [`crl::Crl`] give them.
pub(crate) fn good_if_later(
    answer: CertStatus,
    status: String,
    revoked: Option<(i64, i64)>,
    at: i64,
) -> (CertStatus, String) {
    match revoked {
        Some((when, from)) if answer == CertStatus::Revoked && from > at => (
            CertStatus::Good,
            trf(
                "GOOD at the signing time (revoked later, on {})",
                &[&crate::time::fmt(Some(when))],
            ),
        ),
        _ => (answer, status),
    }
}

/// `c`'s (revocation date, untrusted from) in a full list and its delta list.
pub(crate) fn crl_revocation(
    base: &crl::Crl,
    delta: Option<&crl::Crl>,
    c: &Cert,
) -> Option<(i64, i64)> {
    let of = |l: &crl::Crl| l.revocation_of(c).zip(l.untrusted_from(c));
    delta.and_then(of).or_else(|| of(base))
}

/// A revocation answer found in kept validation data.
pub struct KeptStatus {
    pub answer: CertStatus,
    /// For people.
    pub status: String,
    /// [`Source::Ocsp`] or [`Source::Crl`].
    pub source: Source,
    /// Made no earlier than the time the signature is checked at (always true for a CRL that
    /// was current then).
    pub fresh: bool,
    pub this_update: Option<i64>,
    /// The OCSP responder's certificate.
    pub responder: Option<Cert>,
}

/// Validation data fetched for new signatures, and what could not be fetched.
#[derive(Default)]
pub struct Gathered {
    pub kept: Kept,
    pub warnings: Vec<String>,
    /// Certificates found revoked, or unknown to their CA's OCSP server: why, for people.
    pub refused: Vec<String>,
}

/// Fetches the validation data for `targets` (signers' certificates and their TSAs'; with
/// `true` for those whose untrusted path is worth a warning, since a TSA's is reported with
/// its timestamp):
/// their CA paths up to the root, an OCSP answer for each target (or else its CA's CRL), and
/// each CA certificate's CRL from the CA above it. A revoked or unknown certificate goes in
/// `refused`; data that cannot be fetched is a warning.
pub fn gather(targets: &[(Cert, bool)], ocsp_url: &str, env: &Env, now: i64) -> Gathered {
    let trust = &env.trust;
    let mut g = Gathered::default();
    let mut done: Vec<Cert> = Vec::new();
    // (certificate, an end certificate (asked about by OCSP), warn when untrusted)
    let mut queue: std::collections::VecDeque<(Cert, bool, bool)> =
        targets.iter().map(|(c, w)| (c.clone(), true, *w)).collect();
    while let Some((c, leaf, warn)) = queue.pop_front() {
        if done.contains(&c) {
            continue;
        }
        done.push(c.clone());
        add(&mut g.kept.certs, &c.der);
        if c.self_issued() {
            continue;
        }
        let chain = trust.check(&c, now);
        let issuer = match (&chain.issuer, chain.ok) {
            (Some(i), true) => i.clone(),
            _ => {
                if warn {
                    g.warnings.push(trf(
                        "No validation data could be kept for '{}': {}",
                        &[&c.cn(), &crate::i18n::text(&chain.status)],
                    ));
                }
                continue;
            }
        };
        for i in &chain.issuers {
            add(&mut g.kept.certs, &i.der);
        }
        revocation(&mut g, &c, &issuer, leaf.then_some(ocsp_url), env, now);
        queue.push_back((issuer, false, false));
    }
    g
}

fn revocation(
    g: &mut Gathered,
    c: &Cert,
    issuer: &Cert,
    ocsp_url: Option<&str>,
    env: &Env,
    now: i64,
) {
    let refuse = |g: &mut Gathered, status: &str| {
        g.refused.push(trf(
            "The certificate '{}' is not usable: {}",
            &[&c.cn(), &status],
        ))
    };
    let mut why = Vec::new();
    if let Some(url) = ocsp_url {
        match ocsp::fetch(c, issuer, url, env) {
            Ok(a) if a.cert_status == Some(CertStatus::Good) => {
                add(&mut g.kept.ocsps, &a.raw);
                if let Some(r) = &a.responder {
                    add(&mut g.kept.certs, &r.der);
                }
                return;
            }
            // revoked, or unknown to its CA: negative either way (Order 500/НҚ p.19)
            Ok(a) if a.cert_status.is_some() => {
                return refuse(g, &crate::i18n::text(&a.status));
            }
            Ok(a) => why.push(crate::i18n::text(&a.status)),
            Err(e) => why.push(trf("ERROR: could not check OCSP ({})", &[&e])),
        }
    }
    match crl::lists(c, now, env) {
        Ok((base, delta, due)) => {
            let (_, status, answer) = crl::evaluate(
                &base,
                delta.as_deref(),
                due,
                c,
                issuer,
                now,
                &env.trust.policy,
            );
            match answer {
                Some(CertStatus::Good) => {
                    add(&mut g.kept.crls, &base.raw);
                    if let Some(d) = &delta {
                        add(&mut g.kept.crls, &d.raw);
                    }
                    return;
                }
                Some(CertStatus::Revoked) => return refuse(g, &status),
                _ => why.push(status),
            }
        }
        Err(e) => why.push(trf(
            "ERROR: could not check the revocation list ({})",
            &[&e],
        )),
    }
    g.warnings.push(trf(
        "No revocation data could be kept for '{}': {}",
        &[&c.cn(), &why.join("; ")],
    ));
}

/// An OCSP answer as an item of SignedData's `crls` (RFC 5940 other revocation info).
fn ocsp_item(raw: &[u8]) -> Result<Vec<u8>> {
    let mut seq = OtherRevocationInfo {
        format: ObjectIdentifier::new(RI_OCSP)?,
        info: Any::from_der(raw)?,
    }
    .to_der()?;
    // [1] IMPLICIT
    seq[0] = 0xa1;
    Ok(seq)
}

/// OtherRevocationInfoFormat (RFC 5652 10.2.1), read and written as a SEQUENCE (the `crls`
/// field tags it `[1] IMPLICIT`).
#[derive(Sequence)]
struct OtherRevocationInfo {
    format: ObjectIdentifier,
    info: Any,
}

const OTHER_REVOCATION_INFO: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber(1),
};

/// `[n] IMPLICIT SEQUENCE` (one whole element) with its SEQUENCE tag back.
fn as_sequence(item: &[u8]) -> Vec<u8> {
    let mut v = item.to_vec();
    if let Some(t) = v.first_mut() {
        *t = 0x30;
    }
    v
}

/// RevocationValues (EN 319 122-1 A.1.4): CRLs and BasicOCSPResponses, each as encoded.
#[derive(Sequence)]
struct RevocationValues {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    crl_vals: Option<Vec<Any>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    ocsp_vals: Option<Vec<Any>>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    other_rev_vals: Option<Any>,
}

/// ATSHashIndexV3 (EN 319 122-1 5.5.2), with the hash algorithm written out.
#[derive(Sequence)]
struct AtsHashIndex {
    hash_ind_algorithm: spki::AlgorithmIdentifierOwned,
    certificates_hash_index: Vec<OctetString>,
    crls_hash_index: Vec<OctetString>,
    unsigned_attrs_hash_index: Vec<OctetString>,
}

/// The elements of a SEQUENCE OF, each as encoded (none when `v` is not one).
fn items(v: &[u8]) -> Vec<Vec<u8>> {
    ber::<Vec<Any>>(v)
        .map(|l| l.iter().filter_map(|a| a.to_der().ok()).collect())
        .unwrap_or_default()
}

/// The DER of the OID `s`.
fn oid_der(s: &str) -> Result<Vec<u8>> {
    Ok(ObjectIdentifier::new(s)?.to_der()?)
}

/// Puts `kept` into `sd`: its certificates and `crls`, as ETSI B-LT keeps them, and, for the
/// signer `idx` when it has none yet and no archive timestamp, the certValues and
/// revocationValues attributes Order 500/НҚ p.8 names.
pub fn embed(sd: &mut SignedData, idx: usize, kept: &Kept) -> Result<()> {
    sd.add_certs(&kept.certs);
    let mut items = kept.crls.clone();
    for o in &kept.ocsps {
        items.push(ocsp_item(o)?);
    }
    sd.add_crl_items(&items)?;
    let si = &mut sd.signers[idx];
    let has: Vec<String> = si.unsigned().into_iter().map(|(o, _)| o).collect();
    if has.iter().any(|o| o == ATTR_ARCHIVE_TIMESTAMP_V3) {
        return Ok(());
    }
    if !has.iter().any(|o| o == ATTR_REVOCATION_VALUES) {
        let basics: Vec<Vec<u8>> = kept
            .ocsps
            .iter()
            .filter_map(|o| ocsp::basic_of(o))
            .collect();
        let list = |v: &[Vec<u8>]| -> Result<Option<Vec<Any>>> {
            if v.is_empty() {
                return Ok(None);
            }
            Ok(Some(
                v.iter()
                    .map(|x| Any::from_der(x))
                    .collect::<::der::Result<_>>()?,
            ))
        };
        let rv = RevocationValues {
            crl_vals: list(&kept.crls)?,
            ocsp_vals: list(&basics)?,
            other_rev_vals: None,
        };
        if rv.crl_vals.is_some() || rv.ocsp_vals.is_some() {
            si.add_unsigned(ATTR_REVOCATION_VALUES, &rv.to_der()?)?;
        }
    }
    if !has.iter().any(|o| o == ATTR_CERT_VALUES) && !kept.certs.is_empty() {
        let certs = kept
            .certs
            .iter()
            .map(|c| Any::from_der(c))
            .collect::<::der::Result<Vec<_>>>()?;
        si.add_unsigned(ATTR_CERT_VALUES, &certs.to_der()?)?;
    }
    Ok(())
}

/// The certificates of the TSAs whose timestamps `si` carries (signature and archive
/// timestamps).
pub fn tsa_certs(si: &SignerInfo) -> Vec<Cert> {
    si.unsigned()
        .into_iter()
        .filter(|(o, _)| o == crate::cms::ATTR_TIMESTAMP_TOKEN || o == ATTR_ARCHIVE_TIMESTAMP_V3)
        .flat_map(|(_, v)| v)
        .filter_map(|t| tsp::token_cert(&t))
        .collect()
}

// ------------------------------------------------------------------ archive timestamps

/// ATSHashIndexV3 (EN 319 122-1 5.5.2) for signer `si` of `sd`, with hash `alg`: a hash of
/// each certificate, each `crls` item and each unsigned attribute value (with its type).
fn hash_index(sd: &SignedData, si: &SignerInfo, alg: &str) -> Result<Vec<u8>> {
    let h = |b: &[u8]| -> Result<OctetString> { Ok(OctetString::new(gost::hash(alg, b)?)?) };
    let certs = sd.certs.iter().map(|c| h(c)).collect::<Result<Vec<_>>>()?;
    let crls = sd
        .crl_items()
        .iter()
        .map(|c| h(c))
        .collect::<Result<Vec<_>>>()?;
    let attrs = si
        .unsigned_values()
        .iter()
        .map(|(t, v)| h(&[t.as_slice(), v].concat()))
        .collect::<Result<Vec<_>>>()?;
    Ok(AtsHashIndex {
        hash_ind_algorithm: spki::AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new(alg)?,
            parameters: None,
        },
        certificates_hash_index: certs,
        crls_hash_index: crls,
        unsigned_attrs_hash_index: attrs,
    }
    .to_der()?)
}

/// What an archive-time-stamp-v3's message imprint is the hash of (EN 319 122-1 5.5.3): the
/// content type, the hash of the signed content, the signer's signed fields, and the hash
/// index.
fn imprint_input(
    sd: &SignedData,
    si: &SignerInfo,
    content: &[u8],
    alg: &str,
    index: &[u8],
) -> Result<Vec<u8>> {
    Ok([
        oid_der(&sd.content_type)?,
        gost::hash(alg, content)?,
        si.archive_fields()?,
        index.to_vec(),
    ]
    .concat())
}

/// Adds an archive timestamp (ETSI B-LTA) from the TSA at `url` to signer `idx` of `sd`, over
/// `content` (the signed document) and everything the signature holds now. `extra`:
/// validation data for earlier timestamps, kept in the new timestamp token (EN 319 122-1
/// 5.5.3: once an archive timestamp exists, the SignedData fields stay as they are).
pub fn archive(
    sd: &mut SignedData,
    idx: usize,
    content: &[u8],
    url: &str,
    extra: &Kept,
    env: &Env,
) -> Result<()> {
    let si = &sd.signers[idx];
    let key_alg = sd.signer_cert(si).map(|c| c.key_alg()).unwrap_or_default();
    let (alg, policy) = tsp::hash_and_policy_for(&key_alg);
    let index = hash_index(sd, si, alg)?;
    let input = imprint_input(sd, si, content, alg, &index)?;
    let token = tsp::request(url, alg, &gost::hash(alg, &input)?, policy, env)?;
    let mut t = SignedData::parse_inner(&token)?;
    if t.signers.len() != 1 {
        return Err(Error::new("time-stamp token signed by multiple signers."));
    }
    t.signers[0].add_unsigned(ATTR_ATS_HASH_INDEX_V3, &index)?;
    t.add_certs(&extra.certs);
    let mut items = extra.crls.clone();
    for o in &extra.ocsps {
        items.push(ocsp_item(o)?);
    }
    t.add_crl_items(&items)?;
    sd.signers[idx].add_unsigned(ATTR_ARCHIVE_TIMESTAMP_V3, &t.encode()?)?;
    Ok(())
}

/// Checks every archive timestamp of `si`. `content`: the signed document (None when it is not
/// at hand: the timestamps are then not checked).
pub fn check_archives(
    sd: &SignedData,
    si: &SignerInfo,
    content: Option<&[u8]>,
    env: &Env,
) -> Vec<ArchiveStamp> {
    let Ok(ats) = oid_der(ATTR_ARCHIVE_TIMESTAMP_V3) else {
        return vec![];
    };
    si.unsigned_values()
        .into_iter()
        .filter(|(t, _)| *t == ats)
        .map(
            |(_, token)| match check_archive(sd, si, content, &token, env) {
                Ok(s) => s,
                Err(e) => {
                    // say when and by whom, if the token can be read at all
                    let t = SignedData::parse_inner(&token).ok();
                    ArchiveStamp {
                        checked: true,
                        error: Some(e.to_string()),
                        time: t
                            .as_ref()
                            .and_then(|t| t.content.as_deref())
                            .and_then(|c| TstInfo::parse(c).ok())
                            .map(|i| i.gen_time),
                        tsa: tsp::token_cert(&token).map(|c| c.cn()),
                        ..Default::default()
                    }
                }
            },
        )
        .collect()
}

fn check_archive(
    sd: &SignedData,
    si: &SignerInfo,
    content: Option<&[u8]>,
    token: &[u8],
    env: &Env,
) -> Result<ArchiveStamp> {
    let t = SignedData::parse_inner(token)?;
    let tsi = t
        .signers
        .first()
        .ok_or_else(|| Error::new("time-stamp token without a signer"))?;
    let index_oid = oid_der(ATTR_ATS_HASH_INDEX_V3)?;
    let indexes: Vec<Vec<u8>> = tsi
        .unsigned_values()
        .into_iter()
        .filter(|(o, _)| *o == index_oid)
        .map(|(_, v)| v)
        .collect();
    let [index] = indexes.as_slice() else {
        return Err(Error::new(tr(
            "the archive timestamp must carry exactly one hash index",
        )));
    };
    let info = TstInfo::parse(
        t.content
            .as_deref()
            .ok_or_else(|| Error::new("time stamp without TSTInfo"))?,
    )?;
    let alg = info.imprint_alg.clone();
    let k = ber::<AtsHashIndex>(index).ok();
    let Some(k) = k.filter(|k| k.hash_ind_algorithm.oid.to_string() == alg) else {
        return Err(Error::new(tr(
            "the archive timestamp's hash index is malformed",
        )));
    };
    // every value the index lists must still be in the signature
    let hashes = |items: &mut dyn Iterator<Item = Vec<u8>>| -> Result<Vec<Vec<u8>>> {
        items.map(|b| Ok(gost::hash(&alg, &b)?)).collect()
    };
    let present = [
        hashes(&mut sd.certs.iter().cloned())?,
        hashes(&mut sd.crl_items().into_iter())?,
        hashes(
            &mut si
                .unsigned_values()
                .into_iter()
                .map(|(t, v)| [t, v].concat()),
        )?,
    ];
    let gone = [
        tr("a certificate the archive timestamp covers is no longer in the signature"),
        tr("a revocation answer the archive timestamp covers is no longer in the signature"),
        tr("an unsigned attribute the archive timestamp covers is no longer in the signature"),
    ];
    let listed = [
        &k.certificates_hash_index,
        &k.crls_hash_index,
        &k.unsigned_attrs_hash_index,
    ];
    for (n, list) in listed.iter().enumerate() {
        for h in list.iter() {
            if !present[n].iter().any(|p| p.as_slice() == h.as_bytes()) {
                return Err(Error::new(gone[n]));
            }
        }
    }
    let Some(content) = content else {
        return Ok(ArchiveStamp {
            time: Some(info.gen_time),
            error: Some(
                tr("not checked: the signed document is needed to check the archive timestamp")
                    .into(),
            ),
            ..Default::default()
        });
    };
    let input = imprint_input(sd, si, content, &alg, index)?;
    let mut r = SignerReport::default();
    tsp::check_token(&mut r, &input, token, env)?;
    let valid = r.timestamp_ok == Some(true);
    Ok(ArchiveStamp {
        checked: true,
        time: r.timestamp_time,
        tsa: r.timestamp_info,
        valid,
        trusted: r.timestamp_trusted == Some(true),
        error: (!valid).then(|| {
            tr("the archive timestamp does not match the signature (it or the signature was changed)")
                .into()
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::Env;
    use crate::report::Answer;
    use crate::time::encode_generalized;

    use der_testkit as der;
    use kzcrypto::ocsp::testkit::{GOOD, Reply, key};

    const DAY: i64 = 86_400_000;

    struct Fx {
        ca: crate::p12::Key,
        carol: Cert,
        env: Env,
    }

    fn fx() -> Fx {
        let ca = key("ocsp/ca.p12");
        let carol = key("ocsp/carol.p12").cert;
        let env = Env::new(crate::trust::trust_store(vec![ca.cert.clone()]));
        Fx { ca, carol, env }
    }

    impl Fx {
        /// An OCSP answer about carol made at `made`, revoked at `revoked`.
        fn ocsp(&self, made: i64, revoked: Option<i64>) -> Vec<u8> {
            Reply {
                signer: &self.ca,
                certs: vec![],
                issuer: &self.ca.cert,
                serial: self.carol.serial.clone(),
                status: match revoked {
                    Some(t) => der::tlv(der::ctx(1), &encode_generalized(t).unwrap()),
                    None => GOOD.to_vec(),
                },
                this_update: made,
                next_update: None,
                nonce: None,
                version: false,
            }
            .encode()
        }

        /// A CRL under `issuer`'s name, current from `this` to `next`, listing carol as revoked
        /// at `revoked`; a delta list when `delta`.
        fn crl(
            &self,
            issuer: &[u8],
            this: i64,
            next: i64,
            revoked: Option<i64>,
            delta: bool,
        ) -> Vec<u8> {
            let mut tbs = vec![
                der::small_int(1),
                der::alg_null(self.ca.private_key.sig_oid()),
                issuer.to_vec(),
                encode_generalized(this).unwrap(),
                encode_generalized(next).unwrap(),
            ];
            if let Some(t) = revoked {
                tbs.push(der::seq(&[&der::seq(&[
                    &der::uint(&self.carol.serial),
                    &encode_generalized(t).unwrap(),
                ])]));
            }
            if delta {
                let ext = der::seq(&[
                    &der::oid("2.5.29.27"),
                    &der::boolean(true),
                    &der::octets(&der::small_int(1)),
                ]);
                tbs.push(der::tlv(der::ctx(0), &der::seq(&[&ext])));
            }
            let refs: Vec<&[u8]> = tbs.iter().map(Vec::as_slice).collect();
            let tbs = der::seq(&refs);
            let sig = self.ca.private_key.sign(&tbs, &mut crate::OsRng).unwrap();
            der::seq(&[
                &tbs,
                &der::alg_null(self.ca.private_key.sig_oid()),
                &der::bit_string(&sig),
            ])
        }

        fn status(&self, k: &Kept, at: i64) -> Option<KeptStatus> {
            k.status(&self.carol, &self.ca.cert, &self.env, at)
        }
    }

    fn ocsps(o: Vec<Vec<u8>>) -> Kept {
        Kept {
            ocsps: o,
            ..Default::default()
        }
    }

    /// Kept OCSP answers: fresh when made no more than five minutes before the time checked at;
    /// a revocation after that time is good then; a stale answer only when nothing better.
    #[test]
    fn kept_ocsp_answers() {
        let f = fx();
        let at = crate::time::now_ms() / 1000 * 1000 - 10 * DAY;
        let minute = 60_000;
        let s = f
            .status(&ocsps(vec![f.ocsp(at - 5 * minute, None)]), at)
            .unwrap();
        assert!(s.fresh && s.answer == CertStatus::Good && s.source == Source::Ocsp);
        assert_eq!(s.this_update, Some(at - 5 * minute));
        assert!(s.responder.is_some());
        let s = f
            .status(&ocsps(vec![f.ocsp(at - 6 * minute, None)]), at)
            .unwrap();
        assert!(!s.fresh && s.answer == CertStatus::Good);

        // revoked before the time checked at, or after it
        let s = f
            .status(&ocsps(vec![f.ocsp(at, Some(at - DAY))]), at)
            .unwrap();
        assert_eq!(s.answer, CertStatus::Revoked);
        let s = f
            .status(&ocsps(vec![f.ocsp(at + DAY, Some(at + 1000))]), at)
            .unwrap();
        assert_eq!(s.answer, CertStatus::Good);
        assert!(s.status.contains("revoked later"), "{}", s.status);
        let s = f
            .status(&ocsps(vec![f.ocsp(at + DAY, Some(at))]), at)
            .unwrap();
        assert_eq!(s.answer, CertStatus::Revoked, "revoked at that very time");

        // a stale revocation still says revoked; a stale good answer gives way to a fresh one
        let s = f
            .status(
                &ocsps(vec![f.ocsp(at - DAY, Some(at - 2 * DAY)), f.ocsp(at, None)]),
                at,
            )
            .unwrap();
        assert_eq!(s.answer, CertStatus::Revoked);
        let s = f
            .status(&ocsps(vec![f.ocsp(at - DAY, None), f.ocsp(at, None)]), at)
            .unwrap();
        assert!(s.fresh && s.this_update == Some(at));
        // ... and to a current list
        let k = Kept {
            ocsps: vec![f.ocsp(at - DAY, None)],
            crls: vec![f.crl(&f.ca.cert.subject, at - DAY, at + DAY, None, false)],
            ..Default::default()
        };
        assert_eq!(f.status(&k, at).unwrap().source, Source::Crl);
        // answers that can't be read count for nothing
        assert!(f.status(&ocsps(vec![b"junk".to_vec()]), at).is_none());
        assert!(f.status(&Kept::default(), at).is_none());
    }

    #[test]
    fn kept_lists() {
        let f = fx();
        let at = crate::time::now_ms() / 1000 * 1000 - 10 * DAY;
        let name = f.ca.cert.subject.clone();
        let lists = |l: Vec<Vec<u8>>| Kept {
            crls: l,
            ..Default::default()
        };
        let full = |revoked| f.crl(&name, at - DAY, at + DAY, revoked, false);
        let s = f.status(&lists(vec![full(None)]), at).unwrap();
        assert!(s.answer == CertStatus::Good && s.fresh && s.source == Source::Crl);
        assert_eq!(s.this_update, Some(at - DAY));
        assert!(s.responder.is_none());
        assert_eq!(
            f.status(&lists(vec![full(Some(at - 1000))]), at)
                .unwrap()
                .answer,
            CertStatus::Revoked
        );
        // listed, but revoked after the time checked at
        let s = f.status(&lists(vec![full(Some(at + 1000))]), at).unwrap();
        assert!(
            s.answer == CertStatus::Good && s.status.contains("revoked later"),
            "{}",
            s.status
        );

        // a delta list current then decides, the latest of them
        let delta = |this: i64, revoked| f.crl(&name, this, at + DAY, revoked, true);
        let s = f
            .status(
                &lists(vec![full(None), delta(at - DAY, Some(at - 1000))]),
                at,
            )
            .unwrap();
        assert_eq!(s.answer, CertStatus::Revoked);
        assert_eq!(s.this_update, Some(at - DAY));
        let s = f
            .status(
                &lists(vec![full(None), delta(at - DAY, Some(at + 1000))]),
                at,
            )
            .unwrap();
        assert!(s.status.contains("revoked later"), "{}", s.status);
        let s = f
            .status(
                &lists(vec![
                    delta(at - DAY, None),
                    full(None),
                    delta(at - 1000, None),
                ]),
                at,
            )
            .unwrap();
        assert_eq!(s.this_update, Some(at - 1000));
        // one that was not current then is left out
        let stale = f.crl(&name, at - 3 * DAY, at - 2 * DAY, Some(at - 1000), true);
        assert_eq!(
            f.status(&lists(vec![full(None), stale]), at)
                .unwrap()
                .answer,
            CertStatus::Good
        );
        // a list under another CA's name, or only a delta: nothing
        let other = f.crl(&f.carol.subject, at - DAY, at + DAY, None, false);
        assert!(f.status(&lists(vec![other]), at).is_none());
        assert!(f.status(&lists(vec![delta(at - DAY, None)]), at).is_none());
    }

    /// Kept data goes into a CMS in both places (SignedData's fields and the signer's
    /// attributes), and reads back from either.
    #[test]
    fn keeping_and_reading_back() {
        let f = fx();
        let carol = key("ocsp/carol.p12");
        let now = crate::time::now_ms();
        let kept = Kept {
            certs: vec![f.ca.cert.der.clone()],
            ocsps: vec![f.ocsp(now, None)],
            crls: vec![f.crl(&f.ca.cert.subject, now - DAY, now + DAY, None, false)],
        };
        assert!(!kept.is_empty() && Kept::default().is_empty());
        for one in [
            Kept {
                certs: vec![],
                ocsps: vec![],
                ..kept.clone()
            },
            Kept {
                certs: vec![],
                crls: vec![],
                ..kept.clone()
            },
            Kept {
                ocsps: vec![],
                crls: vec![],
                ..kept.clone()
            },
        ] {
            assert!(!one.is_empty());
        }
        assert_eq!(kept.certificates(), vec![f.ca.cert.clone()]);
        let mut list = vec![];
        add(&mut list, b"");
        add(&mut list, b"x");
        add(&mut list, b"x");
        assert_eq!(list, vec![b"x".to_vec()]);

        let fresh = || {
            crate::cms::sign_once(
                b"doc",
                crate::cms::ID_DATA,
                true,
                &carol.private_key,
                &carol.cert,
                crate::time::now_ms(),
                &mut crate::OsRng,
            )
            .unwrap()
        };
        let mut sd = fresh();
        embed(&mut sd, 0, &kept).unwrap();
        assert_eq!(sd.crl_items().len(), 2);
        let back = Kept::from_cms(&sd, None);
        assert_eq!(back.ocsps, kept.ocsps);
        assert_eq!(back.crls, kept.crls);
        assert!(back.certs.contains(&f.ca.cert.der) && back.certs.contains(&carol.cert.der));
        // from the attributes alone
        let si = sd.signers[0].clone();
        let bare = SignedData {
            certs: vec![],
            crls: None,
            ..sd.clone()
        };
        let back = Kept::from_cms(&bare, Some(&si));
        assert_eq!(
            back,
            Kept {
                certs: vec![f.ca.cert.der.clone()],
                ..kept.clone()
            }
        );
        // embedding again adds no second set of attributes
        let n = sd.signers[0].unsigned_attrs.len();
        embed(&mut sd, 0, &kept).unwrap();
        assert_eq!(sd.signers[0].unsigned_attrs.len(), n);

        // with an archive timestamp, the data goes only into SignedData's fields, and what the
        // timestamp token carries counts as kept
        let token = crate::cms::sign_once(
            b"x",
            crate::tsp::TST_INFO,
            true,
            &f.ca.private_key,
            &f.ca.cert,
            crate::time::now_ms(),
            &mut crate::OsRng,
        )
        .unwrap()
        .encode()
        .unwrap();
        let mut sd = fresh();
        sd.signers[0]
            .add_unsigned(ATTR_ARCHIVE_TIMESTAMP_V3, &token)
            .unwrap();
        embed(&mut sd, 0, &kept).unwrap();
        assert_eq!(sd.signers[0].unsigned_attrs.len(), 1);
        let si = sd.signers[0].clone();
        let bare = SignedData {
            certs: vec![],
            crls: None,
            ..sd.clone()
        };
        assert_eq!(
            Kept::from_cms(&bare, Some(&si)).certs,
            vec![f.ca.cert.der.clone()]
        );
        // only certificates: no revocation values
        let mut sd = fresh();
        embed(
            &mut sd,
            0,
            &Kept {
                certs: kept.certs.clone(),
                ..Default::default()
            },
        )
        .unwrap();
        let types: Vec<String> = sd.signers[0]
            .unsigned()
            .into_iter()
            .map(|(o, _)| o)
            .collect();
        assert_eq!(types, [ATTR_CERT_VALUES]);

        // the TSAs of a signer's timestamps, signature and archive ones
        let mut si = sd.signers[0].clone();
        si.add_unsigned(crate::cms::ATTR_TIMESTAMP_TOKEN, &token)
            .unwrap();
        si.add_unsigned(ATTR_ARCHIVE_TIMESTAMP_V3, &token).unwrap();
        assert_eq!(tsa_certs(&si), vec![f.ca.cert.clone(), f.ca.cert.clone()]);
    }

    /// A local server answering every request with `body` (200), or 500 when None.
    fn serve(body: Option<Vec<u8>>) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/x", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut s) = conn else { continue };
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                // the headers, and a POST's body by its length
                loop {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend(&chunk[..n]),
                    }
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let _ = match &body {
                    Some(b) => s
                        .write_all(
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", b.len())
                                .as_bytes(),
                        )
                        .and_then(|_| s.write_all(b)),
                    None => s.write_all(b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n"),
                };
            }
        });
        url
    }

    /// Gathering validation data for a new signature: an OCSP answer, or else the CA's list;
    /// a revoked certificate is refused.
    #[test]
    fn gathering() {
        let f = fx();
        let now = crate::time::now_ms();
        let with_list = |list: Option<Vec<u8>>| {
            let uri = der::tlv(der::ctx_prim(6), serve(list).as_bytes());
            let dp = der::seq(&[&der::seq(&[&der::tlv(
                der::ctx(0),
                &der::tlv(der::ctx(0), &uri),
            )])]);
            let mut c = f.carol.clone();
            c.extensions.push(("2.5.29.31".into(), dp));
            c
        };
        let good_list = f.crl(&f.ca.cert.subject, now - DAY, now + DAY, None, false);
        let revoked_list = f.crl(
            &f.ca.cert.subject,
            now - DAY,
            now + DAY,
            Some(now - DAY),
            false,
        );
        // the OCSP server fails, or answers with an error status: the list decides
        let failing = serve(None);
        let refusing = serve(Some(der::seq(&[&der::tlv(der::ENUMERATED, &[3])])));
        for ocsp_url in [&failing, &refusing] {
            let c = with_list(Some(good_list.clone()));
            let g = gather(&[(c.clone(), true)], ocsp_url, &f.env, now);
            assert!(
                g.refused.is_empty() && g.warnings.is_empty(),
                "{:?} {:?}",
                g.refused,
                g.warnings
            );
            assert_eq!(g.kept.crls, vec![good_list.clone()]);
            assert!(g.kept.certs.contains(&c.der) && g.kept.certs.contains(&f.ca.cert.der));

            let c = with_list(Some(revoked_list.clone()));
            let g = gather(&[(c, true)], ocsp_url, &f.env, now);
            assert_eq!(g.refused.len(), 1, "{:?}", g.warnings);
            assert!(g.refused[0].contains("not usable"), "{:?}", g.refused);
            assert!(g.kept.crls.is_empty());

            // neither answers
            let c = with_list(None);
            let g = gather(&[(c, true)], ocsp_url, &f.env, now);
            assert!(g.refused.is_empty());
            assert!(
                g.warnings
                    .iter()
                    .any(|w| w.contains("No revocation data could be kept")),
                "{:?}",
                g.warnings
            );
        }
    }

    /// What kept data does to a report: it stands in for an online check that is off or got no
    /// answer, and with an online check asked for, only a fresh good answer at a trusted time
    /// counts as good.
    #[test]
    fn kept_data_in_a_report() {
        use crate::verify::{CertCheck, apply_kept};
        let f = fx();
        let at = crate::time::now_ms() / 1000 * 1000 - 10 * DAY;
        let check = |trusted_time| CertCheck {
            at,
            trusted_time,
            valid_at: true,
            issuer: Some(f.ca.cert.clone()),
            ocsp_good: true,
        };
        let run = |k: &Kept, online: Option<Answer>, trusted: bool| {
            let mut sr = SignerReport {
                revocation: online,
                ..Default::default()
            };
            let mut good = true;
            let had = apply_kept(
                &mut sr,
                &f.carol,
                k,
                &f.env,
                &check(trusted),
                online.map(|_| "http://ocsp"),
                &mut good,
            );
            (had, good, sr)
        };
        let fresh = ocsps(vec![f.ocsp(at, None)]);
        let stale = ocsps(vec![f.ocsp(at - DAY, None)]);
        let revoked = ocsps(vec![f.ocsp(at, Some(at - DAY))]);

        // no online check
        let (had, good, sr) = run(&fresh, None, false);
        assert!(had && good);
        assert_eq!(sr.status(), Some(CertStatus::Good));
        assert_eq!(sr.revocation_source, Some(Source::KeptOcsp));
        assert!(
            sr.ocsp_status
                .unwrap()
                .contains("(answer kept in the signature)")
        );
        assert!(sr.warnings.is_empty());
        let (_, good, _) = run(&revoked, None, false);
        assert!(!good);
        let (_, good, sr) = run(&stale, None, false);
        assert!(good);
        assert!(
            sr.warnings.iter().any(|w| w.contains("older than")),
            "{:?}",
            sr.warnings
        );
        let list = Kept {
            crls: vec![f.crl(&f.ca.cert.subject, at - DAY, at + DAY, None, false)],
            ..Default::default()
        };
        assert_eq!(
            run(&list, None, false).2.revocation_source,
            Some(Source::KeptCrl)
        );

        // an online check that got no answer
        assert!(run(&fresh, Some(Answer::NoAnswer), true).1);
        assert!(
            !run(&fresh, Some(Answer::NoAnswer), false).1,
            "not at a trusted time"
        );
        assert!(!run(&stale, Some(Answer::NoAnswer), true).1, "not fresh");
        assert!(!run(&revoked, Some(Answer::NoAnswer), true).1);
        // one that did answer stands
        let (had, good, sr) = run(&revoked, Some(Answer::Said(CertStatus::Good)), true);
        assert!(had && good);
        assert_eq!(sr.status(), Some(CertStatus::Good));
        assert!(sr.revocation_source.is_none());
        // nothing kept
        let (had, good, sr) = run(&Kept::default(), None, false);
        assert!(!had && good && sr.revocation.is_none());
    }

    #[test]
    fn archive_timestamps_in_a_report() {
        use crate::verify::report_archives;
        let stamp = |checked, valid, trusted| ArchiveStamp {
            checked,
            valid,
            trusted,
            time: Some(0),
            tsa: Some("T".into()),
            error: Some("why".into()),
        };
        let run = |a: Vec<ArchiveStamp>| {
            let mut sr = SignerReport {
                archive_timestamps: a,
                ..Default::default()
            };
            let ok = report_archives(&mut sr);
            (ok, sr)
        };
        let (ok, sr) = run(vec![stamp(true, true, true)]);
        assert!(ok && sr.warnings.is_empty() && sr.notes.is_empty());
        assert_eq!(sr.archive_timestamps.len(), 1);
        let (ok, sr) = run(vec![stamp(false, false, false)]);
        assert!(ok && sr.warnings.is_empty());
        assert!(sr.notes[0].contains("why"), "{:?}", sr.notes);
        let (ok, sr) = run(vec![stamp(true, false, true)]);
        assert!(
            !ok && sr.warnings[0].contains("not valid: why"),
            "{:?}",
            sr.warnings
        );
        let (ok, sr) = run(vec![stamp(true, true, false)]);
        assert!(
            ok && sr.warnings[0].contains("'T' is not a trusted"),
            "{:?}",
            sr.warnings
        );
    }

    /// The online check falls back to the CA's list when OCSP gives no answer.
    #[test]
    fn online_revocation_check() {
        use crate::verify::revocation;
        let f = fx();
        let now = crate::time::now_ms();
        let list = f.crl(&f.ca.cert.subject, now - DAY, now + DAY, None, false);
        let uri = der::tlv(der::ctx_prim(6), serve(Some(list)).as_bytes());
        let dp = der::seq(&[&der::seq(&[&der::tlv(
            der::ctx(0),
            &der::tlv(der::ctx(0), &uri),
        )])]);
        let mut c = f.carol.clone();
        c.extensions.push(("2.5.29.31".into(), dp));
        let dead = serve(None);
        let (good, status, answer, source) = revocation(&c, Some(&f.ca.cert), &dead, &f.env, None);
        assert!(
            good && answer == Some(CertStatus::Good) && source == Some(Source::Crl),
            "{status}"
        );
        assert!(status.contains("(OCSP: "), "{status}");
        // no list either
        let (good, _, answer, source) = revocation(&f.carol, Some(&f.ca.cert), &dead, &f.env, None);
        assert!(!good && answer.is_none() && source.is_none());
        let (_, _, _, source) = revocation(&c, None, &dead, &f.env, None);
        assert!(source.is_none());

        // revoked a day ago: still good as of a trusted timestamp made before that
        let list = f.crl(
            &f.ca.cert.subject,
            now - DAY,
            now + DAY,
            Some(now - DAY),
            false,
        );
        let uri = der::tlv(der::ctx_prim(6), serve(Some(list)).as_bytes());
        let dp = der::seq(&[&der::seq(&[&der::tlv(
            der::ctx(0),
            &der::tlv(der::ctx(0), &uri),
        )])]);
        let mut c = f.carol.clone();
        c.extensions.push(("2.5.29.31".into(), dp));
        let check = |at| revocation(&c, Some(&f.ca.cert), &dead, &f.env, at);
        let (good, status, answer, _) = check(Some(now - 2 * DAY));
        assert!(good && answer == Some(CertStatus::Good), "{status}");
        assert!(
            status.starts_with("GOOD at the signing time (revoked later"),
            "{status}"
        );
        for at in [None, Some(now - DAY), Some(now)] {
            let (good, status, answer, _) = check(at);
            assert!(
                !good && answer == Some(CertStatus::Revoked),
                "{at:?}: {status}"
            );
        }
    }

    /// The network and the clock come from the Env: a list is fetched once and kept until the
    /// hour is up, and an OCSP server that can't be reached falls back to it.
    #[test]
    fn revocation_through_env() {
        use crate::env::{Clock, Transport};
        use crate::verify::revocation;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

        struct Net(Vec<u8>, AtomicUsize, AtomicUsize);
        impl Transport for Net {
            fn post(&self, server: crate::Server, url: &str, _: &str, _: &[u8]) -> Result<Vec<u8>> {
                self.1.fetch_add(1, Ordering::SeqCst);
                assert_eq!(server, crate::Server::Ocsp);
                Err(crate::Error::Network {
                    server,
                    url: url.into(),
                    problem: crate::NetProblem::Status(500),
                })
            }
            fn get(&self, server: crate::Server, _: &str, limit: u64) -> Result<Vec<u8>> {
                assert_eq!(server, crate::Server::RevocationList);
                assert!(limit >= 1 << 20);
                self.2.fetch_add(1, Ordering::SeqCst);
                Ok(self.0.clone())
            }
        }
        struct Tick(AtomicI64);
        impl Clock for Tick {
            fn now_ms(&self) -> i64 {
                self.0.load(Ordering::SeqCst)
            }
        }

        let f = fx();
        let now = 1_900_000_000_000;
        let list = f.crl(&f.ca.cert.subject, now - DAY, now + DAY, None, false);
        let net = Arc::new(Net(list, AtomicUsize::new(0), AtomicUsize::new(0)));
        let clock = Arc::new(Tick(AtomicI64::new(now)));
        let env = Env::new(crate::trust::trust_store(vec![f.ca.cert.clone()]))
            .with_net(net.clone())
            .with_clock(clock.clone());
        let uri = der::tlv(der::ctx_prim(6), b"http://crl.test/ca.crl");
        let dp = der::seq(&[&der::seq(&[&der::tlv(
            der::ctx(0),
            &der::tlv(der::ctx(0), &uri),
        )])]);
        let mut c = f.carol.clone();
        c.extensions.push(("2.5.29.31".into(), dp));

        let check = || revocation(&c, Some(&f.ca.cert), "http://ocsp.test", &env, None);
        let (good, status, answer, source) = check();
        assert!(
            good && answer == Some(CertStatus::Good) && source == Some(Source::Crl),
            "{status}"
        );
        assert_eq!(net.1.load(Ordering::SeqCst), 1, "OCSP asked first");
        assert_eq!(net.2.load(Ordering::SeqCst), 1);
        clock.0.store(now + 59 * 60_000, Ordering::SeqCst);
        assert!(check().0);
        assert_eq!(net.2.load(Ordering::SeqCst), 1, "kept for the hour");
        clock.0.store(now + 61 * 60_000, Ordering::SeqCst);
        assert!(check().0);
        assert_eq!(net.2.load(Ordering::SeqCst), 2, "fetched again after it");
        // a fresh Env starts with no lists
        let other = Env::new(crate::trust::trust_store(vec![f.ca.cert.clone()]))
            .with_net(net.clone())
            .with_clock(clock.clone());
        assert!(revocation(&c, Some(&f.ca.cert), "http://ocsp.test", &other, None).0);
        assert_eq!(net.2.load(Ordering::SeqCst), 3);
        // past the list's nextUpdate it no longer says good
        clock.0.store(now + 2 * DAY, Ordering::SeqCst);
        let (good, status, _, _) = check();
        assert!(!good, "{status}");
    }

    #[test]
    fn revoked_later_unless_compromised() {
        let at = 1_000;
        let g = |r| good_if_later(CertStatus::Revoked, "REVOKED".into(), r, at).0;
        assert_eq!(g(Some((2_000, 2_000))), CertStatus::Good);
        assert_eq!(
            g(Some((1_000, 1_000))),
            CertStatus::Revoked,
            "at the same moment"
        );
        assert_eq!(
            g(Some((2_000, 500))),
            CertStatus::Revoked,
            "invalid since before"
        );
        assert_eq!(
            g(Some((2_000, i64::MIN))),
            CertStatus::Revoked,
            "key compromise"
        );
        assert_eq!(g(None), CertStatus::Revoked);
        assert_eq!(
            good_if_later(CertStatus::Unknown, "?".into(), Some((2_000, 2_000)), at).0,
            CertStatus::Unknown
        );
    }
}
