//! Creates CAdES-BES signatures the way NCALayer does, and adds them next to existing ones
//! (co-signing).

use crate::cert;
use crate::cert::Cert;
use crate::cms::{self, SignedData};
use crate::der;
use crate::i18n::{tr, trf};
use crate::p12::Key;
use crate::report::{SignResult, SignerReport};
use crate::trust::TrustStore;
use crate::{Error, Result, gost, ltv, tsp};

/// Checks the signer's own certificate before signing (Order 500/НҚ p.4): issued by a trusted
/// CA, valid now, allowed to sign under its CA's policy, and, with `ocsp_url`, not revoked
/// (OCSP, or the CA's revocation list when OCSP gives no answer). Any failure refuses signing;
/// a revocation check that got no answer is a warning, returned.
pub fn check_key(c: &Cert, ocsp_url: Option<&str>, trust: &TrustStore) -> Result<Vec<String>> {
    let refuse = |why: String| Err(Error::new(trf("Your key cannot sign: {}", &[&why])));
    let now = crate::time::now_ms();
    if now > c.not_after {
        return refuse(trf(
            "the certificate expired on {}.",
            &[&crate::time::fmt(Some(c.not_after))],
        ));
    }
    if now < c.not_before {
        return refuse(trf(
            "the certificate is not valid until {}.",
            &[&crate::time::fmt(Some(c.not_before))],
        ));
    }
    let chain = trust.check(c, now);
    if !chain.ok {
        return refuse(trf(
            "{} (kzsigner trusts NCA RK; a test CA's certificate can be added with --trust)",
            &[&chain.status],
        ));
    }
    if let Some(why) = cert::usage_problem(c, chain.issuer.as_ref()) {
        return refuse(why);
    }
    let mut warnings = Vec::new();
    if let Some(url) = ocsp_url {
        let (_, status, answer, _) =
            crate::verify::revocation(c, chain.issuer.as_ref(), url, trust, None);
        match answer {
            "good" => {}
            "" => warnings.push(trf(
                "Could not check that your key is not revoked: {}",
                &[&status],
            )),
            _ => return refuse(status),
        }
    }
    Ok(warnings)
}

/// Signs `input`. If `input` is a signed CMS and `cosign_if_cms` is set, the new signature is
/// added to it; a detached CMS then needs `detached_original`.
pub fn sign(
    input: &[u8],
    key: &Key,
    detached: bool,
    tsa_url: Option<&str>,
    cosign_if_cms: bool,
    detached_original: Option<&[u8]>,
    trust: &TrustStore,
) -> Result<SignResult> {
    let existing = if cosign_if_cms {
        SignedData::try_parse(input)
    } else {
        None
    };
    let mut r = SignResult {
        warnings: cert::key_warnings(&key.cert),
        ..Default::default()
    };
    let (content, attach): (&[u8], bool) = match &existing {
        None => (input, !detached),
        Some(e) => match &e.content {
            Some(c) => (c, true),
            None => match detached_original {
                Some(o) => {
                    require_same_document(e, o)?;
                    (o, false)
                }
                None => {
                    return Err(Error::new(tr(
                        "This .cms has no embedded document (detached signature). Provide the original file to add a signature.",
                    )));
                }
            },
        },
    };
    // a co-signature covers the same content type as the existing signatures
    let content_type = existing
        .as_ref()
        .map_or(cms::ID_DATA, |e| e.content_type.as_str());
    let mut out = cms::sign_once(content, content_type, attach, &key.private_key, &key.cert)
        .map_err(|e| Error::new(trf("Signing failed: {}", &[&e])))?;
    if let Some(url) = tsa_url {
        timestamp(&mut out, url, key, trust, &mut r)?;
    }
    r.signature = out.signers[0].signature.clone();
    if let Some(e) = &existing {
        out = e.merge(&out);
        r.cosigned = true;
    }
    r.cms = out.encode();
    r.signer_count = out.signers.len();
    Ok(r)
}

/// Refuses a hash whose length is not the key's digest length.
pub fn check_hash_length(hash: &[u8], key: &Key) -> Result<()> {
    let oid = key.private_key.digest_oid();
    let want = gost::digest_len(oid)?;
    if hash.len() != want {
        return Err(Error::new(trf(
            "The hash is {} bytes long, but this key signs {}-byte hashes ({}).",
            &[&hash.len(), &want, &cert::digest_label(Some(oid))],
        )));
    }
    Ok(())
}

/// Signs a document known only by its hash `hash` (made with the key's digest algorithm: GOST
/// 34.11-2015 for 2015 keys, GOST 34.311-95 for 2004 keys, SHA-256 for RSA) into a detached .cms,
/// as NCALayer's createCAdESFromBase64Hash does; checking it needs the document itself.
pub fn sign_hash(
    hash: &[u8],
    key: &Key,
    tsa_url: Option<&str>,
    trust: &TrustStore,
) -> Result<SignResult> {
    check_hash_length(hash, key)?;
    let mut r = SignResult {
        warnings: cert::key_warnings(&key.cert),
        signer_count: 1,
        ..Default::default()
    };
    let mut out = cms::sign_digest(hash, cms::ID_DATA, &key.private_key, &key.cert, true, &[])
        .map_err(|e| Error::new(trf("Signing failed: {}", &[&e])))?;
    if let Some(url) = tsa_url {
        timestamp(&mut out, url, key, trust, &mut r)?;
    }
    r.signature = out.signers[0].signature.clone();
    r.cms = out.encode();
    Ok(r)
}

/// Adds an NCA timestamp to the single signer of `out` and checks it, as verify would.
pub fn timestamp(
    out: &mut SignedData,
    url: &str,
    key: &Key,
    trust: &TrustStore,
    r: &mut SignResult,
) -> Result<()> {
    tsp::stamp(out, url, key.private_key.scheme())?;
    // the token's signature must hold; an untrusted TSA is reported, as verify would
    let mut check = SignerReport::default();
    let tsa_ca = tsp::check(&mut check, &out.signers[0], trust);
    let chain = trust.check(&key.cert, crate::time::now_ms());
    if let (Some(t), Some(i), true) = (&tsa_ca, &chain.issuer, chain.ok) {
        tsp::same_ca(&mut check, t, i, trust);
    }
    if check.timestamp_ok != Some(true) {
        return Err(Error::new(trf(
            "The timestamp server's answer does not match the request: {}",
            &[&format!(
                "{} ({})",
                tr("invalid timestamp signature"),
                check.timestamp_info.unwrap_or_default()
            )],
        )));
    }
    r.warnings.extend(check.warnings);
    r.timestamped = true;
    Ok(())
}

/// Makes the signatures of a .cms long-term (CAdES B-LT): the certificates and revocation
/// answers needed to check them later go into it. With `archive` (B-LTA), each also gets an
/// archive timestamp over all of it; doing that again later renews it. `original`: the
/// document of a detached .cms, which archive timestamps need. `only`: just the signer with
/// that signature value.
#[allow(clippy::too_many_arguments)]
pub fn extend(
    raw: &[u8],
    original: Option<&[u8]>,
    archive: bool,
    tsa_url: &str,
    ocsp_url: &str,
    trust: &TrustStore,
    only: Option<&[u8]>,
) -> Result<SignResult> {
    let mut sd = SignedData::parse(raw)?;
    let content = match (&sd.content, original) {
        (Some(c), _) => Some(c.clone()),
        (None, Some(o)) => {
            require_same_document(&sd, o)?;
            Some(o.to_vec())
        }
        (None, None) => None,
    };
    if archive && content.is_none() {
        return Err(Error::new(tr(
            "This .cms has no embedded document (detached signature). Provide the original file to add an archive timestamp.",
        )));
    }
    let mut r = SignResult {
        signer_count: sd.signers.len(),
        ..Default::default()
    };
    let now = crate::time::now_ms();
    let mut todo: Vec<(usize, bool, ltv::Kept)> = Vec::new();
    for (idx, si) in sd.signers.iter().enumerate() {
        if only.is_some_and(|o| o != si.signature) {
            continue;
        }
        let Some(c) = sd.signer_cert(si) else {
            r.warnings.push(
                tr("The signer's certificate is not included in the .cms, so this signature cannot be checked.").into(),
            );
            continue;
        };
        let name = cert::holder_name(&c);
        let tsas = ltv::tsa_certs(si);
        if tsas.is_empty() {
            r.warnings.push(trf(
                "The signature of {} has no timestamp: a long-term signature needs one, so it stays checkable only while the certificate is valid.",
                &[&name],
            ));
            continue;
        }
        let archived = si
            .unsigned()
            .iter()
            .any(|(o, _)| o == ltv::ATTR_ARCHIVE_TIMESTAMP_V3);
        // renewing an archived signature needs data only for its timestamps' TSAs: what shows
        // the signer's certificate good at the signing time is kept already, and a later
        // revocation must not stop the renewal
        let mut targets = if archived { vec![] } else { vec![(c, true)] };
        targets.extend(tsas.into_iter().map(|t| (t, false)));
        let g = ltv::gather(&targets, ocsp_url, trust, now);
        r.warnings.extend(g.warnings);
        if !archived && !g.refused.is_empty() {
            r.warnings.push(trf(
                "The signature of {} was not extended: {}",
                &[&name, &g.refused.join("; ")],
            ));
            continue;
        }
        r.warnings.extend(g.refused);
        todo.push((idx, archived, g.kept));
    }
    if todo.is_empty() {
        return Err(Error::new(trf(
            "No signature could be made long-term: {}",
            &[&r.warnings.join(" ")],
        )));
    }
    // the validation data goes in first, so that the archive timestamps cover it
    for (idx, archived, kept) in &todo {
        if !archived {
            ltv::embed(&mut sd, *idx, kept);
        }
    }
    if let (true, Some(content)) = (archive, &content) {
        for (idx, archived, kept) in &todo {
            // a signature archived before keeps what is new inside its new archive timestamp
            let extra = if *archived {
                kept.without(&ltv::Kept::from_cms(&sd, Some(&sd.signers[*idx])))
            } else {
                ltv::Kept::default()
            };
            ltv::archive(&mut sd, *idx, content, tsa_url, &extra)?;
        }
        r.timestamped = true;
    }
    r.cms = sd.encode();
    Ok(r)
}

/// Refuses to co-sign a detached .cms over a different document than the one its signers
/// signed: every existing signer's signed message digest must match `original`.
fn require_same_document(existing: &SignedData, original: &[u8]) -> Result<()> {
    for si in &existing.signers {
        let Some(md) = si.signed_attr(cms::ATTR_MESSAGE_DIGEST) else {
            continue;
        };
        let check = || -> Result<bool> {
            let signed = der::parse(&md)?.expect(der::OCTET_STRING)?.octets()?;
            Ok(signed == gost::hash(&si.digest_alg, original)?)
        };
        match check() {
            Ok(true) => {}
            Ok(false) => {
                return Err(Error::new(tr(
                    "The original file does not match this .cms: its existing signatures are for a different document.",
                )));
            }
            Err(e) => {
                return Err(Error::new(trf(
                    "Could not check the original file against the .cms: {}",
                    &[&e],
                )));
            }
        }
    }
    Ok(())
}
