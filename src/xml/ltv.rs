//! XAdES long-term signatures (ETSI EN 319 132-1 5.5): the validation data kept in the
//! signature (B-LT: CertificateValues and RevocationValues, later ones in
//! TimeStampValidationData), and archive timestamps over all of it (B-LTA), renewed by adding
//! another.

use roxmltree::{Document, Node, NodeId};

use super::c14n::{self, Method};
use super::{
    DS, XADES, b64, child, children, encoding, method_of, parse, qualifying, reference_octets,
    signatures, signer_cert,
};
use crate::cert::{self, Cert};
use crate::i18n::{tr, trf};
use crate::ltv::{self as cades_ltv, Kept};
use crate::report::{ArchiveStamp, SignResult, SignerReport};
use crate::trust::TrustStore;
use crate::tsp::{self, TstInfo};
use crate::{Error, Result, cms, gost, time};

pub const XADES141: &str = "http://uri.etsi.org/01903/v1.4.1#";

/// A signature's UnsignedSignatureProperties.
fn unsigned_props<'a, 'i>(sig: Node<'a, 'i>) -> Option<Node<'a, 'i>> {
    qualifying(sig)
        .and_then(|q| child(q, XADES, "UnsignedProperties"))
        .and_then(|u| child(u, XADES, "UnsignedSignatureProperties"))
}

fn archive_stamps<'a, 'i>(usp: Node<'a, 'i>) -> impl Iterator<Item = Node<'a, 'i>> {
    children(usp, XADES141, "ArchiveTimeStamp")
}

/// The validation data the signature keeps.
pub fn kept(sig: Node) -> Kept {
    let mut k = Kept::default();
    let Some(usp) = unsigned_props(sig) else {
        return k;
    };
    let holders = usp.children().filter(|n| {
        n.is_element()
            && (n.tag_name().namespace() == Some(XADES)
                && matches!(
                    n.tag_name().name(),
                    "CertificateValues" | "RevocationValues"
                )
                || n.tag_name().namespace() == Some(XADES141)
                    && n.tag_name().name() == "TimeStampValidationData")
    });
    for h in holders {
        for n in h.descendants().filter(|n| n.is_element()) {
            let list = match (n.tag_name().namespace(), n.tag_name().name()) {
                (Some(XADES), "EncapsulatedX509Certificate") => &mut k.certs,
                (Some(XADES), "EncapsulatedOCSPValue") => &mut k.ocsps,
                (Some(XADES), "EncapsulatedCRLValue") => &mut k.crls,
                _ => continue,
            };
            if let Some(v) = b64(Some(n))
                && !list.contains(&v)
            {
                list.push(v);
            }
        }
    }
    k
}

/// The timestamp tokens of the signature: its signature timestamps and archive timestamps.
fn tokens(sig: Node) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let Some(usp) = unsigned_props(sig) else {
        return (vec![], vec![]);
    };
    let enc = |n: Node| b64(child(n, XADES, "EncapsulatedTimeStamp"));
    (
        children(usp, XADES, "SignatureTimeStamp")
            .filter_map(enc)
            .collect(),
        archive_stamps(usp).filter_map(enc).collect(),
    )
}

/// What an archive timestamp covers (EN 319 132-1 5.5.2.2): each reference's data, then
/// SignedInfo, SignatureValue, KeyInfo, the unsigned signature properties before `upto` (all
/// of them when None) and the other ds:Object elements, canonicalized with `method`.
fn archive_input(
    text: &str,
    doc: &Document,
    sig: Node,
    upto: Option<NodeId>,
    method: &Method,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let si = child(sig, DS, "SignedInfo").ok_or_else(|| Error::new("no SignedInfo"))?;
    for r in children(si, DS, "Reference") {
        out.extend(reference_octets(text, doc, sig, r)?.1);
    }
    for name in ["SignedInfo", "SignatureValue", "KeyInfo"] {
        if let Some(n) = child(sig, DS, name) {
            out.extend(c14n::canonicalize(text, n, method, &[]));
        }
    }
    if let Some(usp) = unsigned_props(sig) {
        for n in usp
            .children()
            .filter(|n| n.is_element())
            .take_while(|n| Some(n.id()) != upto)
        {
            out.extend(c14n::canonicalize(text, n, method, &[]));
        }
    }
    let qp = qualifying(sig).map(|q| q.id());
    for o in children(sig, DS, "Object") {
        if !o.descendants().any(|d| Some(d.id()) == qp) {
            out.extend(c14n::canonicalize(text, o, method, &[]));
        }
    }
    Ok(out)
}

/// Checks the archive timestamps of `sig`.
pub fn check_archives(
    text: &str,
    doc: &Document,
    sig: Node,
    trust: &TrustStore,
) -> Vec<ArchiveStamp> {
    let Some(usp) = unsigned_props(sig) else {
        return vec![];
    };
    archive_stamps(usp)
        .map(|a| {
            let token = b64(child(a, XADES, "EncapsulatedTimeStamp"));
            let checked = (|| -> Result<ArchiveStamp> {
                let token = token.clone().ok_or_else(|| Error::new("no EncapsulatedTimeStamp"))?;
                let method = child(a, DS, "CanonicalizationMethod")
                    .and_then(method_of)
                    .unwrap_or_else(Method::inclusive);
                let input = archive_input(text, doc, sig, Some(a.id()), &method)?;
                let mut r = SignerReport::default();
                tsp::check_token(&mut r, &input, &token, trust)?;
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
            })();
            checked.unwrap_or_else(|e| ArchiveStamp {
                checked: true,
                error: Some(e.0),
                time: token.as_deref().and_then(gen_time),
                tsa: token.as_deref().and_then(tsp::token_cert).map(|c| c.cn()),
                ..Default::default()
            })
        })
        .collect()
}

fn gen_time(token: &[u8]) -> Option<i64> {
    let t = cms::SignedData::parse_inner(token).ok()?;
    TstInfo::parse(t.content.as_deref()?)
        .ok()
        .map(|i| i.gen_time)
}

/// Elements holding `k`, in the xades namespace (declared on each, so they read the same
/// wherever they go).
fn values(k: &Kept) -> String {
    let mut s = String::new();
    let decl = format!(" xmlns:xades=\"{XADES}\"");
    if !k.certs.is_empty() {
        s.push_str(&format!("<xades:CertificateValues{decl}>"));
        for c in &k.certs {
            s.push_str(&format!(
                "<xades:EncapsulatedX509Certificate>{}</xades:EncapsulatedX509Certificate>",
                crate::base64_encode(c)
            ));
        }
        s.push_str("</xades:CertificateValues>");
    }
    if !k.ocsps.is_empty() || !k.crls.is_empty() {
        s.push_str(&format!("<xades:RevocationValues{decl}>"));
        if !k.crls.is_empty() {
            s.push_str("<xades:CRLValues>");
            for c in &k.crls {
                s.push_str(&format!(
                    "<xades:EncapsulatedCRLValue>{}</xades:EncapsulatedCRLValue>",
                    crate::base64_encode(c)
                ));
            }
            s.push_str("</xades:CRLValues>");
        }
        if !k.ocsps.is_empty() {
            s.push_str("<xades:OCSPValues>");
            for o in &k.ocsps {
                s.push_str(&format!(
                    "<xades:EncapsulatedOCSPValue>{}</xades:EncapsulatedOCSPValue>",
                    crate::base64_encode(o)
                ));
            }
            s.push_str("</xades:OCSPValues>");
        }
        s.push_str("</xades:RevocationValues>");
    }
    s
}

/// Inserts `xml` at the end of the signature's UnsignedSignatureProperties.
fn append_unsigned(text: &str, sig_index: usize, xml: &str) -> Result<String> {
    let doc = parse(text)?;
    let sig = signatures(&doc)[sig_index];
    let usp = unsigned_props(sig).ok_or_else(|| Error::new("no unsigned properties"))?;
    let range = usp.range();
    let close = range.start
        + text[range.clone()]
            .rfind("</")
            .ok_or_else(|| Error::new("unsigned properties without an end tag"))?;
    Ok(format!("{}{xml}{}", &text[..close], &text[close..]))
}

/// Makes the XAdES signatures of the XML document `input` long-term (B-LT): the CA
/// certificates and revocation answers needed to check them later go into each. With
/// `archive` (B-LTA), each also gets an archive timestamp over all of it; doing that again
/// later renews it. `only`: just the signature with that SignatureValue.
pub fn extend(
    input: &[u8],
    archive: bool,
    tsa_url: &str,
    ocsp_url: &str,
    trust: &TrustStore,
    only: Option<&[u8]>,
) -> Result<SignResult> {
    let (text, enc, bom) = encoding::decode(input)?;
    let mut out = text;
    let count = signatures(&parse(&out)?).len();
    let mut r = SignResult {
        signer_count: count,
        ..Default::default()
    };
    let now = time::now_ms();
    let mut done = 0;
    for i in 0..count {
        // what to add, worked out on the document as it is now
        let (add, key_alg) = {
            let doc = parse(&out)?;
            let sig = signatures(&doc)[i];
            let value = b64(child(sig, DS, "SignatureValue")).unwrap_or_default();
            if only.is_some_and(|o| o != value) {
                continue;
            }
            let Some(c) = signer_cert(sig) else {
                r.warnings.push(
                    tr("The signer's certificate is not included in the signature, so it cannot be checked.")
                        .into(),
                );
                continue;
            };
            let name = cert::holder_name(&c);
            let (stamps, archives) = tokens(sig);
            if stamps.is_empty() {
                r.warnings.push(trf(
                    "The signature of {} has no timestamp: a long-term signature needs one, so it stays checkable only while the certificate is valid.",
                    &[&name],
                ));
                continue;
            }
            let archived = !archives.is_empty();
            // renewing needs data only for the timestamps' TSAs (as for CAdES)
            let mut targets: Vec<(Cert, bool)> = if archived {
                vec![]
            } else {
                vec![(c.clone(), true)]
            };
            targets.extend(
                stamps
                    .iter()
                    .chain(&archives)
                    .filter_map(|t| tsp::token_cert(t))
                    .map(|t| (t, false)),
            );
            let g = cades_ltv::gather(&targets, ocsp_url, trust, now);
            r.warnings.extend(g.warnings);
            if !archived && !g.refused.is_empty() {
                r.warnings.push(trf(
                    "The signature of {} was not extended: {}",
                    &[&name, &g.refused.join("; ")],
                ));
                continue;
            }
            r.warnings.extend(g.refused);
            let had = kept(sig);
            let new = g.kept.without(&had);
            let add = if new.is_empty() {
                String::new()
            } else if had.is_empty() && !archived {
                values(&new)
            } else {
                // data that came later: the TSAs', for an archive timestamp to cover
                format!(
                    "<xades141:TimeStampValidationData xmlns:xades141=\"{XADES141}\">{}</xades141:TimeStampValidationData>",
                    values(&new)
                )
            };
            (add, c.key_alg())
        };
        done += 1;
        if !add.is_empty() {
            out = append_unsigned(&out, i, &add)?;
        }
        if archive {
            let input = {
                let doc = parse(&out)?;
                archive_input(&out, &doc, signatures(&doc)[i], None, &Method::inclusive())?
            };
            let (hash_oid, policy) = tsp::hash_and_policy_for(&key_alg);
            let token = tsp::request(tsa_url, hash_oid, &gost::hash(hash_oid, &input)?, policy)?;
            let mut check = SignerReport::default();
            tsp::check_token(&mut check, &input, &token, trust)?;
            if check.timestamp_ok != Some(true) {
                return Err(Error::new(trf(
                    "The timestamp server's answer does not match the request: {}",
                    &[&tr("invalid timestamp signature")],
                )));
            }
            r.warnings.extend(check.warnings);
            let stamp = format!(
                "<xades141:ArchiveTimeStamp xmlns:xades141=\"{XADES141}\" xmlns:xades=\"{XADES}\" \
                 xmlns:ds=\"{DS}\"><ds:CanonicalizationMethod Algorithm=\"{}\"/>\
                 <xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp></xades141:ArchiveTimeStamp>",
                c14n::C14N,
                crate::base64_encode(&token)
            );
            out = append_unsigned(&out, i, &stamp)?;
            r.timestamped = true;
        }
    }
    if done == 0 {
        return Err(Error::new(trf(
            "No signature could be made long-term: {}",
            &[&r.warnings.join(" ")],
        )));
    }
    let mut bytes = bom.to_vec();
    bytes.extend_from_slice(&encoding::encode(&out, enc)?);
    r.cms = bytes;
    Ok(r)
}
