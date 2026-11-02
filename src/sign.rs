//! Creates CAdES-BES signatures the way NCALayer does, and adds them next to existing ones
//! (co-signing).

use crate::cert;
use crate::cms::{self, SignedData};
use crate::der;
use crate::i18n::{tr, trf};
use crate::p12::Key;
use crate::report::{SignResult, SignerReport};
use crate::trust::TrustStore;
use crate::{Error, Result, gost, tsp};

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
    if let Some(e) = &existing {
        out = e.merge(&out);
        r.cosigned = true;
    }
    r.cms = out.encode();
    r.signer_count = out.signers.len();
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
