//! A check's result, shown to people: the verdict, then each signer.

#[allow(unused_imports)]
use super::*;

/// The main reason a check failed, in a sentence.
pub(super) fn failure_reason(r: &VerifyReport) -> String {
    let Some(s) = r.signers.iter().find(|s| !s.valid) else {
        return r
            .warnings
            .first()
            .cloned()
            .unwrap_or_else(|| tr("This file has no signatures.").into());
    };
    if !s.signature_ok {
        return s
            .signature_error
            .clone()
            .unwrap_or_else(|| tr("The document was changed after it was signed.").into());
    }
    if s.cert_valid_at_signing == Some(false) {
        if s.trusted_time().is_some() {
            return tr("The signer's key was not valid when the document was signed (expired, or not yet valid).").into();
        }
        return tr("The signer's key is not valid now, and the signature has no trusted timestamp that would show it was valid when the document was signed.").into();
    }
    if !s.chain_ok {
        return trf(
            "The signer's key was not issued by NCA RK: {}",
            &[&s.chain_status.clone().unwrap_or_default()],
        );
    }
    if let Some(e) = &s.usage_error {
        return trf("The signer's key may not sign documents: {}", &[e]);
    }
    if let Some(o) = &s.ocsp_status {
        return trf("The signer's key check failed: {}", &[o]);
    }
    tr("A signature failed the checks; see the details below.").into()
}

/// Every failing signature is otherwise fine and only lacks a revocation answer (no network,
/// or the OCSP server could not be used): a warning, not a verdict against the document.
pub(super) fn revocation_unchecked(r: &VerifyReport) -> bool {
    let failing: Vec<&SignerReport> = r.signers.iter().filter(|s| !s.valid).collect();
    !failing.is_empty()
        && failing.iter().all(|s| {
            s.signature_ok
                && s.chain_ok
                && s.usage_error.is_none()
                && s.timestamp_ok != Some(false)
                && s.cert_valid_at_signing != Some(false)
                && s.ocsp_answer == Some("")
        })
}

/// The result of a check: a verdict, then each signer.
pub fn report(ui: &mut egui::Ui, r: &VerifyReport) {
    let n = r.signers.len();
    if r.valid {
        banner(ui, Tone::Good, |ui| {
            let title = if n == 1 {
                tr("The signature is valid").to_string()
            } else {
                trf("All {} signatures are valid", &[&n])
            };
            verdict(ui, Icon::ShieldCheck, Tone::Good, &title);
            let text = if r.card_document.is_some() {
                tr(
                    "The document inside the card has not been changed since it was signed, and the keys were issued by NCA RK.",
                )
            } else {
                tr(
                    "The document has not been changed since it was signed, and the keys were issued by NCA RK.",
                )
            };
            ui.add(egui::Label::new(text).wrap());
        });
    } else if revocation_unchecked(r) {
        banner(ui, Tone::Warn, |ui| {
            verdict(
                ui,
                Icon::Warning,
                Tone::Warn,
                tr("Valid, but not checked for revocation"),
            );
            ui.add(
                egui::Label::new(tr(
                    "The document has not been changed and the keys were issued by NCA RK, but NCA's revocation service could not be reached, so it is not known whether a key was revoked. Check the internet connection and open the file again.",
                ))
                .wrap(),
            );
        });
    } else {
        banner(ui, Tone::Bad, |ui| {
            verdict(
                ui,
                Icon::XCircle,
                Tone::Bad,
                tr("Do not trust this document"),
            );
            ui.add(egui::Label::new(failure_reason(r)).wrap());
        });
    }
    for w in &r.warnings {
        warning(ui, w);
    }
    for s in &r.signers {
        ui.add_space(8.0);
        card(ui, |ui| signer(ui, r, s));
    }
}

/// A verdict's title with its icon.
pub(super) fn verdict(ui: &mut egui::Ui, icon: Icon, tone: Tone, title: &str) {
    ui.horizontal(|ui| {
        icons::show(ui, icon, 30.0, tone.color(ui));
        ui.add(egui::Label::new(tone.text(ui, title).size(20.0).strong()).wrap());
    });
}

pub(super) fn signer(ui: &mut egui::Ui, r: &VerifyReport, s: &SignerReport) {
    ui.horizontal(|ui| {
        let (icon, tone) = if s.valid {
            (Icon::Check, Tone::Good)
        } else {
            (Icon::Close, Tone::Bad)
        };
        icons::show(ui, icon, 18.0, tone.color(ui));
        ui.label(RichText::new(s.name()).strong().size(16.0));
    });
    egui::Grid::new(("signer", s.index))
        .num_columns(2)
        .spacing([14.0, 4.0])
        .show(ui, |ui| {
            let mut row = |k: &str, v: String, tone: Tone| {
                ui.label(Tone::Muted.text(ui, k));
                ui.add(egui::Label::new(tone.text(ui, v)).wrap());
                ui.end_row();
            };
            if let Some(v) = s.get("IIN") {
                row(tr("IIN"), v.into(), Tone::Plain);
            }
            if let Some(o) = s.get("O") {
                let bin = s
                    .get("BIN")
                    .map(|b| trf(" · BIN {}", &[&b]))
                    .unwrap_or_default();
                row(tr("Organization"), format!("{o}{bin}"), Tone::Plain);
            }
            row(tr("Signed on"), signed_on(s), Tone::Plain);
            let (doc, tone) = if s.signature_ok {
                (tr("Not changed since signing ✔").to_string(), Tone::Good)
            } else {
                (s.signature_error.clone().unwrap_or_default(), Tone::Bad)
            };
            row(tr("Document"), doc, tone);
            let (key, tone) = if !s.chain_ok {
                (s.chain_status.clone().unwrap_or_default(), Tone::Bad)
            } else if let Some(e) = &s.usage_error {
                (e.clone(), Tone::Bad)
            } else {
                (tr("Issued by NCA RK ✔").to_string(), Tone::Good)
            };
            row(tr("Key"), key, tone);
            let (rev, tone) = match (&s.ocsp_status, s.ocsp_answer) {
                (Some(o), Some("good")) => (o.clone(), Tone::Good),
                (Some(o), Some("")) => (o.clone(), Tone::Warn),
                (Some(o), _) if s.valid => (o.clone(), Tone::Plain),
                (Some(o), _) => (o.clone(), Tone::Bad),
                (None, _) => (
                    tr("Not checked (the online check is off in More options)").into(),
                    Tone::Muted,
                ),
            };
            row(tr("Revoked?"), rev, tone);
        });
    for w in &s.warnings {
        warning(ui, w);
    }
    egui::CollapsingHeader::new(tr("Technical details"))
        .id_salt(("details", s.index))
        .show(ui, |ui| {
            egui::Grid::new(("tech", s.index))
                .num_columns(2)
                .spacing([14.0, 3.0])
                .show(ui, |ui| {
                    let mut row = |k: &str, v: String| {
                        ui.label(Tone::Muted.text(ui, k));
                        ui.add(egui::Label::new(v).wrap());
                        ui.end_row();
                    };
                    if let Some(k) = &s.kind {
                        row(tr("Type"), k.clone());
                    }
                    for n in &s.notes {
                        row(tr("Covers"), n.clone());
                    }
                    if let Some(name) = &r.card_document {
                        row(tr("Document in the card"), name.clone());
                    }
                    if let Some(h) = &r.content_sha256 {
                        row(
                            tr("Document fingerprint"),
                            trf("{} bytes, SHA-256 {}", &[&r.content_size, h]),
                        );
                    }
                    if let Some(v) = s.get("E") {
                        row(tr("Email"), v.into());
                    }
                    row(tr("Time"), signed_at(s));
                    if let Some(l) = s.level {
                        row(tr("Long-term"), level_text(l).into());
                    }
                    for a in &s.archive_timestamps {
                        row(tr("Archive timestamp"), archive_text(a));
                    }
                    row(tr("Algorithm"), s.algorithm.clone().unwrap_or_default());
                    row(
                        tr("Certificate"),
                        trf(
                            "serial {}, valid {} – {}",
                            &[
                                &s.serial_hex.clone().unwrap_or_default(),
                                &time::fmt(s.not_before),
                                &time::fmt(s.not_after),
                            ],
                        ),
                    );
                    row(tr("Issuer"), s.issuer_cn.clone().unwrap_or_default());
                });
        });
}

/// When it was signed, in plain words.
pub(super) fn signed_on(s: &SignerReport) -> String {
    match s.timestamp_time {
        Some(ts) if s.trusted_time().is_some() => {
            trf("{} · time confirmed by NCA", &[&time::fmt(Some(ts))])
        }
        Some(ts) => trf(
            "{} · time stamp not confirmed (see details)",
            &[&time::fmt(Some(ts))],
        ),
        None => trf(
            "{} · time from the signer's computer",
            &[&time::fmt(s.signing_time)],
        ),
    }
}

/// What a signature's ETSI level means, in plain words.
pub(super) fn level_text(l: &str) -> &'static str {
    match l {
        "B-B" => tr("B-B: no timestamp, checkable only while the key is valid"),
        "B-T" => tr("B-T: with a timestamp"),
        "B-LT" => tr("B-LT: NCA's revocation answers are kept in it"),
        "B-LTA" => tr("B-LTA: revocation answers kept, and an archive timestamp"),
        _ => "",
    }
}

pub(super) fn archive_text(a: &crate::report::ArchiveStamp) -> String {
    let state = if !a.checked || !a.valid {
        format!(" ({})", a.error.clone().unwrap_or_default())
    } else if a.trusted {
        " ✔".into()
    } else {
        tr(" (TSA not trusted)").into()
    };
    trf(
        "{} · timestamp by {}{}",
        &[
            &time::fmt(a.time),
            &a.tsa.clone().unwrap_or_default(),
            &state,
        ],
    )
}

pub(super) fn signed_at(s: &SignerReport) -> String {
    let Some(ts) = s.timestamp_time else {
        return trf("{} · signer's own clock", &[&time::fmt(s.signing_time)]);
    };
    let state = if s.timestamp_ok != Some(true) {
        tr(" (INVALID)")
    } else if s.timestamp_trusted == Some(true) {
        " ✔"
    } else {
        tr(" (TSA not trusted)")
    };
    trf(
        "{} · timestamp by {}{}",
        &[
            &time::fmt(Some(ts)),
            &s.timestamp_info.clone().unwrap_or_default(),
            &state,
        ],
    )
}
