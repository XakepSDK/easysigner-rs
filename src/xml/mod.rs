//! XML signatures: XAdES (ETSI EN 319 132) enveloped in the document, as Order 500/НҚ p.10
//! describes them, with the algorithm names NCA's Kalkan uses. Signing makes XAdES B-B, or B-T
//! with an NCA timestamp; checking also reads plain XMLDSig.

pub mod c14n;
pub mod encoding;
pub mod ltv;

use roxmltree::{Document, Node, NodeId};

use crate::cert::{self, Cert};
use crate::i18n::{tr, trf};
use crate::p12::Key;
use crate::report::{SignResult, SignerReport, VerifyReport};
use crate::trust::TrustStore;
use crate::{Error, Result, der, gost, time, tsp, verify};
use c14n::Method;

pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// XPath Filter 2.0, and the XPath 1.0 transform.
const FILTER2: &str = "http://www.w3.org/2002/06/xmldsig-filter2";
const XPATH: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
const SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// Signature algorithm names: (URI, signature OID, digest OID).
const SIGNATURE_ALGS: [(&str, &str, &str); 6] = [
    (
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512",
        gost::SIG_GOST2015_512,
        gost::H_GOST2015_512,
    ),
    (
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-256",
        gost::SIG_GOST2015_256,
        gost::H_GOST2015_256,
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311",
        gost::SIG_GOST2004,
        gost::H_GOST34311,
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        gost::SIG_SHA256_RSA,
        gost::H_SHA256,
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        "1.2.840.113549.1.1.13",
        gost::H_SHA512,
    ),
    (
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        "1.2.840.113549.1.1.5",
        gost::H_SHA1,
    ),
];

/// Digest algorithm names: (URI, OID).
const DIGEST_ALGS: [(&str, &str); 6] = [
    (
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512",
        gost::H_GOST2015_512,
    ),
    (
        "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256",
        gost::H_GOST2015_256,
    ),
    (
        "http://www.w3.org/2001/04/xmldsig-more#gost34311",
        gost::H_GOST34311,
    ),
    (SHA256, gost::H_SHA256),
    ("http://www.w3.org/2001/04/xmlenc#sha512", gost::H_SHA512),
    ("http://www.w3.org/2000/09/xmldsig#sha1", gost::H_SHA1),
];

fn digest_oid(uri: &str) -> Option<&'static str> {
    DIGEST_ALGS.iter().find(|d| d.0 == uri).map(|d| d.1)
}

fn digest_uri(oid: &str) -> &'static str {
    DIGEST_ALGS
        .iter()
        .find(|d| d.1 == oid)
        .map_or(SHA256, |d| d.0)
}

fn parse(text: &str) -> Result<Document<'_>> {
    // attribute defaults a DTD declares are part of what other tools sign, and roxmltree does
    // not add them: such documents would canonicalize differently here
    let prolog = &text[..text
        .find("<!DOCTYPE")
        .map_or(0, |i| text[i..].find("]>").map_or(text.len(), |j| i + j))];
    if prolog.contains("<!ATTLIST") {
        return Err(Error::new(tr(
            "XML documents whose DTD declares attributes are not supported.",
        )));
    }
    Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    )
    .map_err(|e| Error::new(trf("This XML document could not be read: {}", &[&e])))
}

/// Whether `data` looks like an XML document (it may still turn out to be broken).
pub fn is_xml(data: &[u8]) -> bool {
    let start = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    start.trim_ascii_start().starts_with(b"<")
}

fn is(n: &Node, ns: &str, name: &str) -> bool {
    n.is_element() && n.tag_name().namespace() == Some(ns) && n.tag_name().name() == name
}

fn child<'a, 'i>(n: Node<'a, 'i>, ns: &str, name: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| is(c, ns, name))
}

fn children<'a, 'i>(
    n: Node<'a, 'i>,
    ns: &'a str,
    name: &'a str,
) -> impl Iterator<Item = Node<'a, 'i>> {
    n.children().filter(move |c| is(c, ns, name))
}

fn signatures<'a, 'i>(doc: &'a Document<'i>) -> Vec<Node<'a, 'i>> {
    doc.descendants()
        .filter(|n| is(n, DS, "Signature"))
        .collect()
}

/// Base64 content, whitespace and line breaks allowed.
fn b64(n: Option<Node>) -> Option<Vec<u8>> {
    let s: String = n?
        .text()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    crate::base64_decode(&s)
}

/// The element whose Id (or ID, id) is `id`; None when there is none, or more than one (a
/// signature must not be fooled by a copy of what it signed).
fn by_id<'a, 'i>(doc: &'a Document<'i>, id: &str) -> Option<Node<'a, 'i>> {
    let mut found = doc.descendants().filter(|n| {
        n.is_element()
            && ["Id", "ID", "id"]
                .iter()
                .any(|a| n.attribute(*a) == Some(id))
    });
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

fn xsd_time(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Signs the XML document `input` with an enveloped XAdES signature (B-B, or B-T with a
/// timestamp from `tsa_url`), added as the last child of its root element.
pub fn sign(
    input: &[u8],
    key: &Key,
    tsa_url: Option<&str>,
    trust: &TrustStore,
) -> Result<SignResult> {
    let (text, enc, bom) = encoding::decode(input)?;
    let text = text.as_str();
    let doc = parse(text)?;
    let existing = signatures(&doc);
    if !existing.iter().all(|s| leaves_room(*s)) {
        return Err(Error::new(tr(
            "This XML document is already signed, and its signature covers everything in it, so another signature inside it would break that one. Add yours as a .cms file or a card instead.",
        )));
    }
    let mut r = SignResult {
        warnings: cert::key_warnings(&key.cert),
        signer_count: existing.len() + 1,
        cosigned: !existing.is_empty(),
        ..Default::default()
    };
    let digest = key.private_key.digest_oid();
    let sig_uri = SIGNATURE_ALGS
        .iter()
        .find(|a| a.1 == key.private_key.sig_oid())
        .map(|a| a.0)
        .ok_or_else(|| Error::new("no XML signature algorithm for this key"))?;
    let dig_uri = digest_uri(digest);
    let inc = Method::inclusive();

    // the document as the signature's enveloped reference will see it
    let skip: Vec<NodeId> = existing.iter().map(|n| n.id()).collect();
    let doc_digest = gost::hash(digest, &c14n::canonicalize(text, doc.root(), &inc, &skip))?;

    let mut idb = [0u8; 8];
    crate::random(&mut idb)?;
    let id = format!("kzsig-{}", crate::hex(&idb));
    let c = &key.cert;
    let issuer_serial = der::seq(&[
        &der::seq(&[&der::tlv(der::ctx(4), &c.issuer)]),
        &der::uint(&c.serial),
    ]);
    let signed_props = format!(
        "<xades:SignedProperties Id=\"{id}-sp\"><xades:SignedSignatureProperties>\
         <xades:SigningTime>{}</xades:SigningTime><xades:SigningCertificateV2><xades:Cert>\
         <xades:CertDigest><ds:DigestMethod Algorithm=\"{SHA256}\"/><ds:DigestValue>{}</ds:DigestValue>\
         </xades:CertDigest><xades:IssuerSerialV2>{}</xades:IssuerSerialV2></xades:Cert>\
         </xades:SigningCertificateV2></xades:SignedSignatureProperties></xades:SignedProperties>",
        xsd_time(time::now_ms()),
        crate::base64_encode(&gost::sha256(&c.der)),
        crate::base64_encode(&issuer_serial),
    );
    let c14n_uri = c14n::C14N;
    let signed_info = format!(
        "<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{c14n_uri}\"/>\
         <ds:SignatureMethod Algorithm=\"{sig_uri}\"/>\
         <ds:Reference URI=\"\"><ds:Transforms><ds:Transform Algorithm=\"{ENVELOPED}\"/>\
         <ds:Transform Algorithm=\"{FILTER2}\"><dsig-xpath:XPath xmlns:dsig-xpath=\"{FILTER2}\" \
         Filter=\"subtract\">/descendant::ds:Signature</dsig-xpath:XPath></ds:Transform>\
         <ds:Transform Algorithm=\"{c14n_uri}\"/></ds:Transforms>\
         <ds:DigestMethod Algorithm=\"{dig_uri}\"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference>\
         <ds:Reference Type=\"{SIGNED_PROPERTIES}\" URI=\"#{id}-sp\"><ds:Transforms>\
         <ds:Transform Algorithm=\"{c14n_uri}\"/></ds:Transforms>\
         <ds:DigestMethod Algorithm=\"{dig_uri}\"/><ds:DigestValue>@@{id}-sp@@</ds:DigestValue>\
         </ds:Reference></ds:SignedInfo>",
        crate::base64_encode(&doc_digest),
    );
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{DS}\" Id=\"{id}\">{signed_info}\
         <ds:SignatureValue>@@{id}-sv@@</ds:SignatureValue><ds:KeyInfo><ds:X509Data>\
         <ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo><ds:Object>\
         <xades:QualifyingProperties xmlns:xades=\"{XADES}\" Target=\"#{id}\">{signed_props}@@{id}-up@@\
         </xades:QualifyingProperties></ds:Object></ds:Signature>",
        crate::base64_encode(&c.der),
    );

    // into the root element, at its end
    let root = doc.root_element();
    let range = root.range();
    let tag = &text[range.clone()];
    let mut out = String::with_capacity(text.len() + signature.len() + 64);
    if tag.ends_with("/>") {
        let qname = tag[1..]
            .split(|c: char| c.is_whitespace() || c == '/' || c == '>')
            .next()
            .unwrap_or_default();
        out.push_str(&text[..range.end - 2]);
        out.push('>');
        out.push_str(&signature);
        out.push_str(&format!("</{qname}>"));
    } else {
        let close = range.start
            + tag
                .rfind("</")
                .ok_or_else(|| Error::new("XML root element without an end tag"))?;
        out.push_str(&text[..close]);
        out.push_str(&signature);
        out.push_str(&text[close..range.end]);
    }
    out.push_str(&text[range.end..]);

    // the signed properties' digest, then the signature over SignedInfo
    let sp_digest = {
        let d = parse(&out)?;
        let sp = by_id(&d, &format!("{id}-sp"))
            .ok_or_else(|| Error::new("signed properties not found"))?;
        gost::hash(digest, &c14n::canonicalize(&out, sp, &inc, &[]))?
    };
    out = out.replacen(
        &format!("@@{id}-sp@@"),
        &crate::base64_encode(&sp_digest),
        1,
    );
    let value = {
        let d = parse(&out)?;
        let s = by_id(&d, &id).ok_or_else(|| Error::new("signature not found"))?;
        let si = child(s, DS, "SignedInfo").ok_or_else(|| Error::new("SignedInfo not found"))?;
        key.private_key
            .sign(&c14n::canonicalize(&out, si, &inc, &[]))?
    };
    out = out.replacen(&format!("@@{id}-sv@@"), &crate::base64_encode(&value), 1);
    r.signature = value;

    let unsigned = match tsa_url {
        Some(url) => {
            let stamped = {
                let d = parse(&out)?;
                let s = by_id(&d, &id).ok_or_else(|| Error::new("signature not found"))?;
                let sv = child(s, DS, "SignatureValue")
                    .ok_or_else(|| Error::new("SignatureValue not found"))?;
                c14n::canonicalize(&out, sv, &inc, &[])
            };
            let token = timestamp(&stamped, url, key, trust, &mut r)?;
            format!(
                "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>\
                 <xades:SignatureTimeStamp Id=\"{id}-ts\"><ds:CanonicalizationMethod Algorithm=\"{c14n_uri}\"/>\
                 <xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>\
                 </xades:UnsignedSignatureProperties></xades:UnsignedProperties>",
                crate::base64_encode(&token)
            )
        }
        None => String::new(),
    };
    out = out.replacen(&format!("@@{id}-up@@"), &unsigned, 1);
    let mut bytes = bom.to_vec();
    bytes.extend_from_slice(&encoding::encode(&out, enc)?);
    r.cms = bytes;
    Ok(r)
}

/// An NCA timestamp over `stamped` (the canonical SignatureValue), checked as verifying would.
fn timestamp(
    stamped: &[u8],
    url: &str,
    key: &Key,
    trust: &TrustStore,
    r: &mut SignResult,
) -> Result<Vec<u8>> {
    let (hash_oid, policy) = tsp::hash_and_policy_for(&key.cert.key_alg());
    let token = tsp::request(url, hash_oid, &gost::hash(hash_oid, stamped)?, policy)?;
    let mut check = SignerReport::default();
    let tsa_ca = tsp::check_token(&mut check, stamped, &token, trust)?;
    let chain = trust.check(&key.cert, time::now_ms());
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
    Ok(token)
}

/// Checks every XML signature in the document `input`.
pub fn verify(input: &[u8], trust: &TrustStore, ocsp_url: Option<&str>) -> Result<VerifyReport> {
    let (text, ..) = encoding::decode(input)?;
    let text = text.as_str();
    let doc = parse(text)?;
    let mut rep = VerifyReport {
        has_content: true,
        content_size: input.len() as u64,
        content_sha256: Some(crate::hex(&gost::sha256(input))),
        ..Default::default()
    };
    for s in signatures(&doc) {
        rep.signers.push(check_one(text, &doc, s, trust, ocsp_url));
    }
    rep.signers
        .sort_by_key(|s| match s.trusted_time().or(s.signing_time) {
            Some(t) => (0, t),
            None => (1, 0),
        });
    for (k, s) in rep.signers.iter_mut().enumerate() {
        s.index = k + 1;
    }
    rep.valid = !rep.signers.is_empty() && rep.signers.iter().all(|s| s.valid);
    if rep.signers.is_empty() {
        rep.warnings
            .push(tr("The file contains no signatures.").into());
    }
    Ok(rep)
}

/// The signer's certificate among those in KeyInfo: the one no other one was issued by.
fn signer_cert(sig: Node) -> Option<Cert> {
    let key_info = child(sig, DS, "KeyInfo")?;
    let certs: Vec<Cert> = key_info
        .descendants()
        .filter(|n| is(n, DS, "X509Certificate"))
        .filter_map(|n| Cert::parse(&b64(Some(n))?).ok())
        .collect();
    certs
        .iter()
        .find(|c| {
            !certs
                .iter()
                .any(|o| o != *c && cert::names_equal(&o.issuer, &c.subject))
        })
        .or(certs.first())
        .cloned()
}

/// The canonicalization a CanonicalizationMethod or Transform element names.
fn method_of(n: Node) -> Option<Method> {
    let mut m = Method::by_uri(n.attribute("Algorithm")?)?;
    if let Some(p) = n
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "InclusiveNamespaces")
        .and_then(|c| c.attribute("PrefixList"))
    {
        m.inclusive_prefixes = p.split_whitespace().map(str::to_string).collect();
    }
    Some(m)
}

/// A reference's data after its transforms: the node it covers, the octets, and the digest
/// algorithm.
pub(crate) fn reference_octets<'a, 'i>(
    text: &str,
    doc: &'a Document<'i>,
    sig: Node<'a, 'i>,
    r: Node<'a, 'i>,
) -> Result<(Node<'a, 'i>, Vec<u8>, &'static str)> {
    let uri = r.attribute("URI").unwrap_or_default();
    let target = if uri.is_empty() {
        doc.root()
    } else if let Some(id) = uri.strip_prefix('#') {
        by_id(doc, id).ok_or_else(|| {
            Error::new(trf(
                "The signed part {} is missing or appears more than once.",
                &[&uri],
            ))
        })?
    } else {
        return Err(Error::new(trf(
            "The signature refers to {}, outside the document; such signatures are not supported.",
            &[&uri],
        )));
    };
    let mut skip: Vec<NodeId> = Vec::new();
    let mut method = Method::inclusive();
    if let Some(ts) = child(r, DS, "Transforms") {
        for t in children(ts, DS, "Transform") {
            let alg = t.attribute("Algorithm").unwrap_or_default();
            if alg == ENVELOPED {
                skip.push(sig.id());
            } else if excludes_signatures(t) {
                skip.extend(signatures(doc).iter().map(|n| n.id()));
            } else if let Some(m) = method_of(t) {
                method = m;
            } else {
                return Err(Error::new(trf(
                    "The signature uses a transform that is not supported: {}",
                    &[&alg],
                )));
            }
        }
    }
    // a same-document reference never includes comments
    method.comments = false;
    let dm = child(r, DS, "DigestMethod")
        .and_then(|d| d.attribute("Algorithm"))
        .unwrap_or_default();
    let oid = digest_oid(dm).ok_or_else(|| {
        Error::new(trf(
            "The signature uses a digest algorithm that is not supported: {}",
            &[&dm],
        ))
    })?;
    Ok((
        target,
        c14n::canonicalize(text, target, &method, &skip),
        oid,
    ))
}

/// Whether the Transform `t` leaves out every signature in the document: an XPath Filter 2.0
/// "subtract" of all ds:Signature elements, or the XPath 1.0 filter
/// not(ancestor-or-self::ds:Signature). Only these forms are understood.
fn excludes_signatures(t: Node) -> bool {
    let alg = t.attribute("Algorithm").unwrap_or_default();
    let Some(x) = t
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "XPath")
    else {
        return false;
    };
    let expr: String = x
        .text()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    // the prefix the expression uses must name the signature namespace there
    let names_signature = |e: &str| {
        e.split_once(':').is_some_and(|(p, rest)| {
            rest == "Signature" && x.lookup_namespace_uri(Some(p)) == Some(DS)
        })
    };
    match alg {
        FILTER2 => {
            x.tag_name().namespace() == Some(FILTER2)
                && x.attribute("Filter") == Some("subtract")
                && ["//", "/descendant::"]
                    .iter()
                    .any(|a| expr.strip_prefix(a).is_some_and(names_signature))
        }
        XPATH => expr
            .strip_prefix("not(ancestor-or-self::")
            .and_then(|e| e.strip_suffix(')'))
            .is_some_and(names_signature),
        _ => false,
    }
}

/// Checks one reference of a signature: returns the node it covers.
fn check_reference<'a, 'i>(
    text: &str,
    doc: &'a Document<'i>,
    sig: Node<'a, 'i>,
    r: Node<'a, 'i>,
) -> Result<Node<'a, 'i>> {
    let uri = r.attribute("URI").unwrap_or_default();
    let (target, octets, oid) = reference_octets(text, doc, sig, r)?;
    let want = b64(child(r, DS, "DigestValue")).unwrap_or_default();
    if gost::hash(oid, &octets)? != want {
        return Err(Error::new(if uri.is_empty() {
            tr("Signature check failed: the document's content hash does not match the signed hash (the document was changed).").to_string()
        } else {
            trf("The signed part {} was changed after signing.", &[&uri])
        }));
    }
    Ok(target)
}

/// Whether another signature can go inside the XML document `input`: every signature there
/// leaves the others out of what it signs.
pub fn has_room(input: &[u8]) -> bool {
    encoding::decode(input).is_ok_and(|(text, ..)| {
        parse(&text).is_ok_and(|doc| signatures(&doc).into_iter().all(leaves_room))
    })
}

/// Whether the signature `sig` still holds when another signature is added to the document:
/// each reference to the whole document leaves out every signature.
fn leaves_room(sig: Node) -> bool {
    child(sig, DS, "SignedInfo").is_some_and(|si| {
        children(si, DS, "Reference")
            .filter(|r| r.attribute("URI").unwrap_or_default().is_empty())
            .all(|r| {
                child(r, DS, "Transforms")
                    .is_some_and(|ts| children(ts, DS, "Transform").any(excludes_signatures))
            })
    })
}

/// Checks the signature `sig` and its signer.
fn check_one(
    text: &str,
    doc: &Document,
    sig: Node,
    trust: &TrustStore,
    ocsp_url: Option<&str>,
) -> SignerReport {
    let mut sr = SignerReport {
        kind: Some("XAdES".into()),
        ..Default::default()
    };
    let Some(c) = signer_cert(sig) else {
        sr.signature_error = Some(
            tr("The signer's certificate is not included in the signature, so it cannot be checked.")
                .into(),
        );
        return sr;
    };
    cert::describe(&mut sr, &c);

    // the XAdES properties
    let qp = qualifying(sig);
    let sp = qp.and_then(|q| child(q, XADES, "SignedProperties"));
    let ssp = sp.and_then(|s| child(s, XADES, "SignedSignatureProperties"));
    match check_signed_info(text, doc, sig, &c, &mut sr) {
        Ok(covered) => {
            let whole = covered
                .iter()
                .any(|n| *n == doc.root().id() || *n == doc.root_element().id());
            // the properties count only when signed
            let props = sp.is_some_and(|s| covered.contains(&s.id()));
            let ssp = ssp.filter(|_| props);
            sr.signing_time = ssp
                .and_then(|s| child(s, XADES, "SigningTime"))
                .and_then(|t| t.text())
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t.trim()).ok())
                .map(|t| t.timestamp_millis());
            let cert_ref = ssp.map(|s| signing_certificate_matches(s, &c));
            if !whole {
                sr.signature_error = Some(
                    tr("This signature covers only part of the document, so the rest could be changed without notice.")
                        .into(),
                );
            } else if cert_ref == Some(false) {
                sr.signature_error = Some(
                    tr("The signed reference to the signer's certificate does not match the certificate in the file.").into(),
                );
            } else {
                sr.signature_ok = true;
            }
            if !props {
                sr.kind = Some("XMLDSig".into());
                sr.warnings.push(
                    tr("This is a plain XML signature without signed XAdES properties (signing time, signer's certificate), which Order 500/НҚ p.10 asks for.")
                        .into(),
                );
            }
        }
        Err(e) => sr.signature_error = Some(e.0),
    }

    // the signature timestamp, over the canonical SignatureValue
    let mut tsa_ca = None;
    let stamp = qp
        .and_then(|q| child(q, XADES, "UnsignedProperties"))
        .and_then(|u| child(u, XADES, "UnsignedSignatureProperties"))
        .and_then(|u| child(u, XADES, "SignatureTimeStamp"));
    if let Some(st) = stamp {
        let method = child(st, DS, "CanonicalizationMethod")
            .and_then(method_of)
            .unwrap_or_else(Method::inclusive);
        let stamped = child(sig, DS, "SignatureValue")
            .map(|sv| c14n::canonicalize(text, sv, &method, &[]))
            .unwrap_or_default();
        match b64(child(st, XADES, "EncapsulatedTimeStamp"))
            .ok_or_else(|| Error::new("no EncapsulatedTimeStamp"))
            .and_then(|tok| tsp::check_token(&mut sr, &stamped, &tok, trust))
        {
            Ok(ca) => tsa_ca = ca,
            Err(e) => {
                sr.timestamp_ok = Some(false);
                sr.timestamp_info = Some(trf("unreadable timestamp: {}", &[&e.0]));
            }
        }
    }

    let check = verify::check_certificate(&mut sr, &c, tsa_ca, trust, ocsp_url);
    let mut ocsp_good = check.ocsp_good;
    let kept = ltv::kept(sig);
    let kept_found =
        verify::apply_kept(&mut sr, &c, &kept, trust, &check, ocsp_url, &mut ocsp_good);
    sr.archive_timestamps = ltv::check_archives(text, doc, sig, trust);
    let archives_ok = verify::report_archives(&mut sr);
    sr.level = Some(verify::level(&sr, kept_found));
    sr.valid = sr.signature_ok
        && sr.chain_ok
        && sr.usage_error.is_none()
        && check.valid_at
        && sr.timestamp_ok != Some(false)
        && ocsp_good
        && archives_ok;
    sr
}

/// The signature's QualifyingProperties.
fn qualifying<'a, 'i>(sig: Node<'a, 'i>) -> Option<Node<'a, 'i>> {
    let sig_id = sig.attribute("Id");
    children(sig, DS, "Object")
        .flat_map(|o| children(o, XADES, "QualifyingProperties"))
        .find(|q| {
            sig_id.is_none() || q.attribute("Target").and_then(|t| t.strip_prefix('#')) == sig_id
        })
}

/// Checks the references and the signature over SignedInfo; returns the nodes signed.
fn check_signed_info(
    text: &str,
    doc: &Document,
    sig: Node,
    c: &Cert,
    sr: &mut SignerReport,
) -> Result<Vec<NodeId>> {
    let si = child(sig, DS, "SignedInfo")
        .ok_or_else(|| Error::new(tr("The XML signature has no SignedInfo.")))?;
    let sm = child(si, DS, "SignatureMethod")
        .and_then(|m| m.attribute("Algorithm"))
        .unwrap_or_default();
    let &(_, sig_oid, dig_oid) = SIGNATURE_ALGS.iter().find(|a| a.0 == sm).ok_or_else(|| {
        Error::new(trf(
            "The signature uses an algorithm that is not supported: {}",
            &[&sm],
        ))
    })?;
    sr.algorithm = Some(cert::alg_name(sig_oid, Some(dig_oid)));
    let method = child(si, DS, "CanonicalizationMethod")
        .and_then(method_of)
        .ok_or_else(|| {
            Error::new(tr(
                "The signature uses a canonicalization method that is not supported.",
            ))
        })?;
    let value = b64(child(sig, DS, "SignatureValue")).unwrap_or_default();
    let ok = c.public_key()?.verify(
        sig_oid,
        Some(dig_oid),
        &c14n::canonicalize(text, si, &method, &[]),
        &value,
    )?;
    if !ok {
        return Err(Error::new(tr(
            "Signature does not match the document (the document or signature was changed).",
        )));
    }
    let mut covered = Vec::new();
    let mut sha1 = dig_oid == gost::H_SHA1;
    for r in children(si, DS, "Reference") {
        covered.push(check_reference(text, doc, sig, r)?.id());
        sha1 |= child(r, DS, "DigestMethod")
            .and_then(|d| d.attribute("Algorithm"))
            .and_then(digest_oid)
            == Some(gost::H_SHA1);
    }
    if sha1 {
        sr.warnings.push(
            tr("The signature uses SHA-1, which is no longer safe: a document with the same hash can be made.")
                .into(),
        );
    }
    Ok(covered)
}

/// Whether a SigningCertificate(V2) property names `c` (true when there is none).
fn signing_certificate_matches(ssp: Node, c: &Cert) -> bool {
    let Some(sc) = child(ssp, XADES, "SigningCertificateV2")
        .or_else(|| child(ssp, XADES, "SigningCertificate"))
    else {
        return true;
    };
    children(sc, XADES, "Cert").any(|cert| {
        let Some(cd) = child(cert, XADES, "CertDigest") else {
            return false;
        };
        let alg = child(cd, DS, "DigestMethod")
            .and_then(|d| d.attribute("Algorithm"))
            .and_then(digest_oid);
        let want = b64(child(cd, DS, "DigestValue"));
        match (alg, want) {
            (Some(a), Some(w)) => gost::hash(a, &c.der).is_ok_and(|h| h == w),
            _ => false,
        }
    })
}
