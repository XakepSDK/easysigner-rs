//! X.509 certificates: [`kzcrypto::cert`], plus names, purposes and key warnings for people.

pub use kzcrypto::cert::*;

use crate::gost;
use crate::i18n::{tr, trf};
use crate::report::SignerReport;
use crate::time;

/// Why `c` may not sign (see [`kzcrypto::cert::may_not_sign`]), in the reader's language.
pub fn usage_problem(c: &Cert, issuer: Option<&Cert>) -> Option<String> {
    may_not_sign(c, issuer).map(|t| crate::i18n::text(&t))
}

// ------------------------------------------------------------------ for people

/// The holder's name for people: CN plus given name.
pub fn holder_name(c: &Cert) -> String {
    let mut sr = SignerReport::default();
    describe(&mut sr, c);
    sr.name()
}

/// Fills the certificate part of a report: who, issuer, serial, validity, purposes.
pub fn describe(sr: &mut SignerReport, c: &Cert) {
    sr.cert_der = Some(c.der.clone());
    sr.subject = rdns(&c.subject);
    sr.subject_dn = Some(dn(&c.subject));
    let issuer_dn = dn(&c.issuer);
    sr.issuer_cn = Some(
        get(&rdns(&c.issuer), "CN")
            .map(str::to_string)
            .unwrap_or_else(|| issuer_dn.clone()),
    );
    sr.issuer_dn = Some(issuer_dn);
    sr.serial_hex = Some(c.serial_hex());
    sr.not_before = Some(c.not_before);
    sr.not_after = Some(c.not_after);
    sr.cert_types = types(c);
    if let Some(iin) = get(&sr.subject, "SERIALNUMBER").and_then(|s| s.strip_prefix("IIN")) {
        let iin = iin.to_string();
        sr.subject.push(("IIN".into(), iin));
    }
    if let Some(bin) = get(&sr.subject, "OU").and_then(|s| s.strip_prefix("BIN")) {
        let bin = bin.to_string();
        sr.subject.push(("BIN".into(), bin));
    }
}

/// Certificate purposes from key usage and extended key usage (NCA's type names).
pub fn types(c: &Cert) -> Vec<String> {
    let mut t = Vec::new();
    if c.key_usage().is_some_and(|k| k[KU_NON_REPUDIATION]) {
        t.push("SIGNATURE".into());
    }
    let eku = c.extended_key_usage();
    for (oid, name) in [
        (EKU_CLIENT_AUTH, "AUTHENTICATION"),
        (EKU_SERVER_AUTH, "SSL"),
        (EKU_OCSP_SIGNING, "OCSP_RESPONSE_SIGNING"),
        (EKU_TIME_STAMPING, "TSP_SIGNING"),
    ] {
        if eku.iter().any(|o| o == oid) {
            t.push(name.into());
        }
    }
    t
}

/// Warnings about a key that is unsuitable for signing documents (e.g. an AUTH key).
pub fn key_warnings(c: &Cert) -> Vec<String> {
    let mut w = Vec::new();
    let now = time::now_ms();
    if now > c.not_after {
        w.push(trf(
            "The certificate expired on {}.",
            &[&time::fmt(Some(c.not_after))],
        ));
    }
    if now < c.not_before {
        w.push(trf(
            "The certificate is not valid until {}.",
            &[&time::fmt(Some(c.not_before))],
        ));
    }
    if c.key_usage().is_some_and(|k| !k[KU_NON_REPUDIATION]) {
        w.push(
            tr("This certificate has no 'non-repudiation' key usage, so it looks like an authentication (AUTH_) key. Documents are normally signed with the signing key (RSA_... / GOSTKNCA_... file); some services will reject this signature.")
                .into(),
        );
    }
    w
}

pub fn alg_name(enc_oid: &str, digest_oid: Option<&str>) -> String {
    match enc_oid {
        gost::SIG_GOST2015_512 | gost::KEY_GOST2015_512 => {
            "GOST 34.10-2015 (512) / GOST 34.11-2015".into()
        }
        gost::SIG_GOST2015_256 | gost::KEY_GOST2015_256 => {
            "GOST 34.10-2015 (256) / GOST 34.11-2015".into()
        }
        gost::SIG_GOST2004 | gost::KEY_GOST2004 => "GOST 34.310-2004 / GOST 34.311-95".into(),
        gost::RSA_ENCRYPTION | gost::SIG_SHA256_RSA => {
            format!("RSA / {}", digest_label(digest_oid))
        }
        o => format!("{o} / {}", digest_label(digest_oid)),
    }
}

/// Algorithm label for a certificate's own key.
pub fn key_alg_name(c: &Cert) -> String {
    let k = c.key_alg();
    if k == gost::RSA_ENCRYPTION {
        "RSA".into()
    } else {
        alg_name(&k, None)
    }
}

pub fn digest_label(oid: Option<&str>) -> String {
    match oid {
        Some(gost::H_SHA256) => "SHA-256".into(),
        Some(gost::H_SHA1) => "SHA-1".into(),
        Some(gost::H_GOST34311) => "GOST 34.311-95".into(),
        Some(gost::H_GOST2015_512) => "GOST 34.11-2015 (512)".into(),
        Some(gost::H_GOST2015_256) => "GOST 34.11-2015 (256)".into(),
        Some(o) => o.into(),
        None => "null".into(),
    }
}
