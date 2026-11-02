//! Long-term signatures (ETSI EN 319 122-1 B-LT and B-LTA; Order 500/НҚ p.5-8): the
//! certificates and revocation answers needed to check a signature years later, kept inside
//! it, and archive timestamps over all of it.

use crate::cert::Cert;
use crate::cms::{SignedData, SignerInfo};
use crate::der;
use crate::i18n::{tr, trf};
use crate::keys::alg_id;
use crate::report::{ArchiveStamp, SignerReport};
use crate::trust::TrustStore;
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
                        if let Ok(t) = der::parse(&v).and_then(|t| t.children()) {
                            for c in t.iter() {
                                add(&mut k.certs, c.raw);
                            }
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
            let Ok(t) = der::parse(&item) else { continue };
            if t.tag == der::SEQUENCE {
                add(&mut self.crls, &item);
            } else if t.tag == der::ctx(1)
                && let Ok(k) = t.children()
                && k.len() == 2
                && k[0].oid().is_ok_and(|o| o == RI_OCSP)
            {
                add(&mut self.ocsps, k[1].raw);
            }
        }
    }

    /// RevocationValues: crlVals [0] SEQUENCE OF CertificateList, ocspVals [1] SEQUENCE OF
    /// BasicOCSPResponse.
    fn add_revocation_values(&mut self, v: &[u8]) {
        let Ok(rv) = der::parse(v).and_then(|t| t.children()) else {
            return;
        };
        for part in rv.iter() {
            let Ok(list) = part.inner().and_then(|i| i.children()) else {
                continue;
            };
            for x in list.iter() {
                if part.tag == der::ctx(0) {
                    add(&mut self.crls, x.raw);
                } else if part.tag == der::ctx(1) {
                    add(&mut self.ocsps, &ocsp::wrap_basic(x.raw));
                }
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
    pub fn status(
        &self,
        c: &Cert,
        issuer: &Cert,
        trust: &TrustStore,
        at: i64,
    ) -> Option<KeptStatus> {
        let mut stale = None;
        for raw in &self.ocsps {
            let Ok(a) = ocsp::read_embedded(raw, c, issuer, trust, at) else {
                continue;
            };
            if a.cert_status.is_empty() {
                continue;
            }
            let fresh = a.this_update.is_some_and(|u| u + 5 * MINUTE >= at);
            let s = KeptStatus {
                answer: a.cert_status,
                status: a.status,
                source: "ocsp",
                fresh,
                this_update: a.this_update,
                responder: a.responder,
            };
            if fresh || s.answer == "revoked" {
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
                .filter(|l| l.is_delta && l.unusable(c, issuer, at).is_none())
                .max_by_key(|l| l.this_update);
            let (_, status, answer) = crl::evaluate(base, delta, false, c, issuer, at);
            if !answer.is_empty() {
                return Some(KeptStatus {
                    answer,
                    status,
                    source: "crl",
                    fresh: true,
                    this_update: Some(delta.map_or(base.this_update, |d| d.this_update)),
                    responder: None,
                });
            }
        }
        stale
    }
}

/// A revocation answer found in kept validation data.
pub struct KeptStatus {
    /// "good", "revoked" or "unknown".
    pub answer: &'static str,
    /// For people.
    pub status: String,
    /// "ocsp" or "crl".
    pub source: &'static str,
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
}

/// Fetches the validation data for `targets` (signers' certificates and their TSAs'; with
/// `true` for those whose untrusted path is worth a warning, since a TSA's is reported with
/// its timestamp):
/// their CA paths up to the root, an OCSP answer for each target (or else its CA's CRL), and
/// each CA certificate's CRL from the CA above it. A revoked certificate is an error; data
/// that cannot be fetched is a warning.
pub fn gather(
    targets: &[(Cert, bool)],
    ocsp_url: &str,
    trust: &TrustStore,
    now: i64,
) -> Result<Gathered> {
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
                        &[&c.cn(), &chain.status],
                    ));
                }
                continue;
            }
        };
        for i in &chain.issuers {
            add(&mut g.kept.certs, &i.der);
        }
        revocation(&mut g, &c, &issuer, leaf.then_some(ocsp_url), trust, now)?;
        queue.push_back((issuer, false, false));
    }
    Ok(g)
}

fn revocation(
    g: &mut Gathered,
    c: &Cert,
    issuer: &Cert,
    ocsp_url: Option<&str>,
    trust: &TrustStore,
    now: i64,
) -> Result<()> {
    let revoked = |status: &str| {
        Error::new(trf(
            "The certificate '{}' is revoked: {}",
            &[&c.cn(), &status],
        ))
    };
    let mut why = Vec::new();
    if let Some(url) = ocsp_url {
        match ocsp::fetch(c, issuer, url, trust) {
            Ok(a) if a.cert_status == "good" => {
                add(&mut g.kept.ocsps, &a.raw);
                if let Some(r) = &a.responder {
                    add(&mut g.kept.certs, &r.der);
                }
                return Ok(());
            }
            Ok(a) if a.cert_status == "revoked" => return Err(revoked(&a.status)),
            Ok(a) => why.push(a.status),
            Err(e) => why.push(trf("ERROR: could not check OCSP ({})", &[&e])),
        }
    }
    match crl::lists(c, now) {
        Ok((base, delta, due)) => {
            let (_, status, answer) = crl::evaluate(&base, delta.as_deref(), due, c, issuer, now);
            match answer {
                "good" => {
                    add(&mut g.kept.crls, &base.raw);
                    if let Some(d) = &delta {
                        add(&mut g.kept.crls, &d.raw);
                    }
                    return Ok(());
                }
                "revoked" => return Err(revoked(&status)),
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
    Ok(())
}

/// An OCSP answer as an item of SignedData's `crls` (RFC 5940 other revocation info).
fn ocsp_item(raw: &[u8]) -> Vec<u8> {
    der::tlv(der::ctx(1), &der::cat(&[&der::oid(RI_OCSP), raw]))
}

/// Puts `kept` into `sd`: its certificates and `crls`, as ETSI B-LT keeps them, and, for the
/// signer `idx` when it has none yet and no archive timestamp, the certValues and
/// revocationValues attributes Order 500/НҚ p.8 names.
pub fn embed(sd: &mut SignedData, idx: usize, kept: &Kept) {
    sd.add_certs(&kept.certs);
    let mut items = kept.crls.clone();
    items.extend(kept.ocsps.iter().map(|o| ocsp_item(o)));
    sd.add_crl_items(&items);
    let si = &mut sd.signers[idx];
    let has: Vec<String> = si.unsigned().into_iter().map(|(o, _)| o).collect();
    if has.iter().any(|o| o == ATTR_ARCHIVE_TIMESTAMP_V3) {
        return;
    }
    if !has.iter().any(|o| o == ATTR_REVOCATION_VALUES) {
        let basics: Vec<Vec<u8>> = kept
            .ocsps
            .iter()
            .filter_map(|o| ocsp::basic_of(o))
            .collect();
        let mut parts = Vec::new();
        if !kept.crls.is_empty() {
            let refs: Vec<&[u8]> = kept.crls.iter().map(Vec::as_slice).collect();
            parts.push(der::tlv(der::ctx(0), &der::seq(&refs)));
        }
        if !basics.is_empty() {
            let refs: Vec<&[u8]> = basics.iter().map(Vec::as_slice).collect();
            parts.push(der::tlv(der::ctx(1), &der::seq(&refs)));
        }
        if !parts.is_empty() {
            let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            si.add_unsigned(ATTR_REVOCATION_VALUES, &der::seq(&refs));
        }
    }
    if !has.iter().any(|o| o == ATTR_CERT_VALUES) && !kept.certs.is_empty() {
        let refs: Vec<&[u8]> = kept.certs.iter().map(Vec::as_slice).collect();
        si.add_unsigned(ATTR_CERT_VALUES, &der::seq(&refs));
    }
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
    let h = |b: &[u8]| gost::hash(alg, b).map(|x| der::octets(&x));
    let certs = sd.certs.iter().map(|c| h(c)).collect::<Result<Vec<_>>>()?;
    let crls = sd
        .crl_items()
        .iter()
        .map(|c| h(c))
        .collect::<Result<Vec<_>>>()?;
    let attrs = si
        .unsigned_values()
        .iter()
        .map(|(t, v)| h(&der::cat(&[t, v])))
        .collect::<Result<Vec<_>>>()?;
    let seq_of = |v: &[Vec<u8>]| der::seq(&v.iter().map(Vec::as_slice).collect::<Vec<_>>());
    Ok(der::seq(&[
        &der::seq(&[&der::oid(alg)]),
        &seq_of(&certs),
        &seq_of(&crls),
        &seq_of(&attrs),
    ]))
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
    Ok(der::cat(&[
        &der::oid(&sd.content_type),
        &gost::hash(alg, content)?,
        &si.archive_fields(),
        index,
    ]))
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
) -> Result<()> {
    let si = &sd.signers[idx];
    let key_alg = sd.signer_cert(si).map(|c| c.key_alg()).unwrap_or_default();
    let (alg, policy) = tsp::hash_and_policy_for(&key_alg);
    let index = hash_index(sd, si, alg)?;
    let input = imprint_input(sd, si, content, alg, &index)?;
    let token = tsp::request(url, alg, &gost::hash(alg, &input)?, policy)?;
    let mut t = SignedData::parse_inner(&token)?;
    if t.signers.len() != 1 {
        return Err(Error::new("time-stamp token signed by multiple signers."));
    }
    t.signers[0].add_unsigned(ATTR_ATS_HASH_INDEX_V3, &index);
    t.add_certs(&extra.certs);
    let mut items = extra.crls.clone();
    items.extend(extra.ocsps.iter().map(|o| ocsp_item(o)));
    t.add_crl_items(&items);
    sd.signers[idx].add_unsigned(ATTR_ARCHIVE_TIMESTAMP_V3, &t.encode());
    Ok(())
}

/// Checks every archive timestamp of `si`. `content`: the signed document (None when it is not
/// at hand: the timestamps are then not checked).
pub fn check_archives(
    sd: &SignedData,
    si: &SignerInfo,
    content: Option<&[u8]>,
    trust: &TrustStore,
) -> Vec<ArchiveStamp> {
    let ats = der::oid(ATTR_ARCHIVE_TIMESTAMP_V3);
    si.unsigned_values()
        .into_iter()
        .filter(|(t, _)| *t == ats)
        .map(
            |(_, token)| match check_archive(sd, si, content, &token, trust) {
                Ok(s) => s,
                Err(e) => {
                    // say when and by whom, if the token can be read at all
                    let t = SignedData::parse_inner(&token).ok();
                    ArchiveStamp {
                        checked: true,
                        error: Some(e.0),
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
    trust: &TrustStore,
) -> Result<ArchiveStamp> {
    let t = SignedData::parse_inner(token)?;
    let tsi = t
        .signers
        .first()
        .ok_or_else(|| Error::new("time-stamp token without a signer"))?;
    let index_oid = der::oid(ATTR_ATS_HASH_INDEX_V3);
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
    let k = der::parse(index)?.items(der::SEQUENCE)?;
    if k.len() != 4 || alg_id(&k[0])?.0 != alg {
        return Err(Error::new(tr(
            "the archive timestamp's hash index is malformed",
        )));
    }
    // every value the index lists must still be in the signature
    let hashes = |items: &mut dyn Iterator<Item = Vec<u8>>| -> Result<Vec<Vec<u8>>> {
        items.map(|b| gost::hash(&alg, &b)).collect()
    };
    let present = [
        hashes(&mut sd.certs.iter().cloned())?,
        hashes(&mut sd.crl_items().into_iter())?,
        hashes(
            &mut si
                .unsigned_values()
                .into_iter()
                .map(|(t, v)| der::cat(&[&t, &v])),
        )?,
    ];
    let gone = [
        tr("a certificate the archive timestamp covers is no longer in the signature"),
        tr("a revocation answer the archive timestamp covers is no longer in the signature"),
        tr("an unsigned attribute the archive timestamp covers is no longer in the signature"),
    ];
    for (n, list) in k[1..].iter().enumerate() {
        for h in list.children()?.iter() {
            if !present[n].contains(&h.octets()?) {
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
    tsp::check_token(&mut r, &input, token, trust)?;
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
