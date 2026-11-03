//! The Sign and Signed screens: the document, the key, how to sign, and saving.

use super::*;

impl App {
    pub(super) fn sign_screen(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        card(ui, |ui| {
            step(ui, tr("1 · Document"));
            if let Some(d) = self.sign.doc.clone() {
                file_title(ui, &d);
                if icons::button(
                    ui,
                    Icon::Open,
                    tr("Open the document"),
                    14.0,
                    egui::vec2(0.0, 32.0),
                    false,
                )
                .on_hover_text(tr(
                    "Read it before you sign: it opens in the program your computer uses for it.",
                ))
                .clicked()
                {
                    self.view_doc(&ctx, d);
                }
            }
            let doc = self.sign.doc.clone();
            if let Some(f) = self.file_field(ui, "doc", tr("Document to sign"), &doc) {
                self.set_doc(&ctx, f);
            }
            self.sign.doc_note.show(ui);
            if self.sign.doc_is_detached_cms {
                ui.add_space(4.0);
                let o = self.sign.sign_original.clone();
                if let Some(f) = self.file_field(
                    ui,
                    "sign_original",
                    tr("This signature file does not contain the document. Choose the signed document:"),
                    &o,
                ) {
                    self.sign.sign_original = Some(f);
                }
            }
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            step(ui, tr("2 · Your signature key"));
            let kf = self.key.file.clone();
            if let Some(f) = self.file_field(
                ui,
                "key",
                tr("Key file (.p12), for example GOSTKNCA_… or RSA_…"),
                &kf,
            ) {
                self.set_key_file(&ctx, f);
            }
            ui.horizontal(|ui| {
                let l = ui.label(tr("Password"));
                let r = ui
                    .add(
                        egui::TextEdit::singleline(&mut self.key.password)
                            .password(!self.key.show_password)
                            .desired_width(if self.narrow {
                                // room for the eye button beside it
                                let eye = ui.spacing().interact_size.y.max(22.0) + 8.0;
                                (ui.available_width() - eye - ui.spacing().item_spacing.x).max(80.0)
                            } else {
                                240.0
                            }),
                    )
                    .labelled_by(l.id);
                if r.lost_focus() {
                    self.open_key(&ctx);
                }
                let hint = if self.key.show_password {
                    tr("Hide password")
                } else {
                    tr("Show password")
                };
                if eye_button(ui, self.key.show_password, hint).clicked() {
                    self.key.show_password = !self.key.show_password;
                }
            });
            if self.key.aliases.len() > 1 {
                let before = self.key.alias.clone();
                ui.horizontal(|ui| {
                    ui.label(tr("Key in the file:"));
                    egui::ComboBox::from_id_salt("alias")
                        .selected_text(self.key.alias.clone().unwrap_or_default())
                        .show_ui(ui, |ui| {
                            for a in self.key.aliases.clone() {
                                ui.selectable_value(&mut self.key.alias, Some(a.clone()), a);
                            }
                        });
                });
                if self.key.alias != before {
                    self.open_key(&ctx);
                }
            }
            if self.key.opened.is_some() {
                let tone = if self.key.ok { Tone::Good } else { Tone::Warn };
                banner(ui, tone, |ui| self.key.note.show(ui));
            } else {
                self.key.note.show(ui);
            }
        });
        ui.add_space(10.0);
        card(ui, |ui| {
            step(ui, tr("3 · How to save the signed document"));
            self.how_to_save(ui);
        });
        ui.add_space(12.0);
        let can_sign = !self.sign.signing
            && self.sign.doc.is_some()
            && self.key.opened.is_some()
            && (!self.sign.doc_is_detached_cms || self.sign.sign_original.is_some());
        let label = if self.sign.signing {
            tr("Signing…")
        } else {
            tr("Sign")
        };
        let hint = if self.sign.doc.is_none() {
            tr("Choose the document first.")
        } else if self.key.opened.is_none() {
            tr("Choose your key file and type its password.")
        } else if self.sign.doc_is_detached_cms && self.sign.sign_original.is_none() {
            tr("Choose the signed document.")
        } else {
            ""
        };
        if self.narrow {
            let w = ui.available_width();
            let clicked = ui
                .add_enabled_ui(can_sign, |ui| {
                    icons::button(ui, Icon::Pen, label, 17.0, egui::vec2(w, 52.0), true)
                })
                .inner
                .clicked();
            if clicked {
                self.sign(&ctx);
            }
            if !hint.is_empty() {
                ui.vertical_centered(|ui| ui.label(Tone::Muted.text(ui, hint)));
            }
            ui.add_space(8.0);
        } else {
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let clicked = ui
                        .add_enabled_ui(can_sign, |ui| {
                            icons::button(ui, Icon::Pen, label, 16.0, egui::vec2(120.0, 38.0), true)
                        })
                        .inner
                        .clicked();
                    if clicked {
                        self.sign(&ctx);
                    }
                    ui.label(Tone::Muted.text(ui, hint));
                });
            });
        }
    }

    /// The three ways to sign, and their options.
    pub(super) fn how_to_save(&mut self, ui: &mut egui::Ui) {
        let kind = self.sign.doc_kind;
        // a signed file keeps its own kind: a .cms gets another .cms signature, and so on
        let locked = matches!(kind, DocKind::Cms | DocKind::Card | DocKind::SignedPdf);
        let pdf_ok = matches!(kind, DocKind::Pdf | DocKind::SignedPdf);
        // the second way: inside the document itself, a PDF's or an XML document's
        let inside = if matches!(kind, DocKind::Xml | DocKind::SignedXml(_)) {
            (
                SignAs::Xml,
                tr("Inside the XML"),
                tr(
                    "Keeps the XML document, with the signature inside it (XAdES). Only for XML files.",
                ),
                matches!(kind, DocKind::Xml | DocKind::SignedXml(true)),
            )
        } else {
            (
                SignAs::Pdf,
                tr("Inside the PDF"),
                tr("Still opens as a normal PDF. Only for PDF files."),
                pdf_ok && (!locked || kind == DocKind::SignedPdf),
            )
        };
        let options = [
            (
                SignAs::Cms,
                tr("Signature file"),
                tr("Saves a .cms file, like NCALayer and eGov. Recommended."),
                !locked || kind == DocKind::Cms,
            ),
            inside,
            (
                SignAs::Card,
                tr("Printable card"),
                tr("A PDF that shows the document and who signed it, to print or send."),
                !locked || kind == DocKind::Card,
            ),
        ];
        // the three boxes as tall as the tallest one was on the last frame
        let height_id = egui::Id::unique("how_to_save_height");
        let height = ui
            .ctx()
            .data(|d| d.get_temp::<f32>(height_id))
            .unwrap_or(60.0);
        let mut tallest: f32 = 0.0;
        let narrow = self.narrow;
        let sign_as = &mut self.sign.sign_as;
        let mut option =
            |ui: &mut egui::Ui,
             i: usize,
             (value, title, desc, enabled): (SignAs, &str, &str, bool)| {
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    let id = ui.scope_id().with(("how", i));
                    let hovered =
                        enabled && ui.ctx().read_response(id).is_some_and(|r| r.hovered());
                    let v = ui.visuals();
                    let stroke = if *sign_as == value {
                        egui::Stroke::new(2.0, v.selection.bg_fill)
                    } else if hovered {
                        egui::Stroke::new(1.0, v.widgets.hovered.fg_stroke.color)
                    } else {
                        v.widgets.noninteractive.bg_stroke
                    };
                    let frame = egui::Frame::new()
                        .stroke(stroke)
                        .corner_radius(10.0)
                        .inner_margin(if narrow { 12.0 } else { 10.0 })
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            if !narrow {
                                ui.set_min_height(height);
                            }
                            ui.add_enabled_ui(enabled, |ui| {
                                ui.vertical(|ui| {
                                    ui.radio_value(sign_as, value, RichText::new(title).strong());
                                    ui.add(
                                        egui::Label::new(Tone::Muted.text(ui, desc).size(12.5))
                                            .wrap()
                                            .selectable(false),
                                    );
                                })
                                .response
                                .rect
                                .height()
                            })
                            .inner
                        });
                    tallest = tallest.max(frame.inner);
                    // the whole box picks the option, not only its radio button
                    let r = ui.interact(frame.response.rect, id, egui::Sense::click());
                    if enabled {
                        if r.clicked() {
                            *sign_as = value;
                        }
                        if r.hovered() {
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        }
                    }
                });
            };
        if narrow {
            for (i, o) in options.into_iter().enumerate() {
                option(ui, i, o);
                ui.add_space(4.0);
            }
        } else {
            ui.columns(3, |cols| {
                for (i, o) in options.into_iter().enumerate() {
                    option(&mut cols[i], i, o);
                }
            });
        }
        if (tallest - height).abs() > 0.5 {
            ui.ctx().data_mut(|d| d.insert_temp(height_id, tallest));
            ui.ctx().request_repaint();
        }
        ui.add_space(6.0);
        if self.sign.sign_as == SignAs::Card && kind != DocKind::Card {
            ui.horizontal(|ui| {
                ui.label(tr("Card language:"));
                egui::ComboBox::from_id_salt("card_lang")
                    .selected_text(card_lang_name(self.sign.card_lang))
                    .show_ui(ui, |ui| {
                        for l in [CardLang::Ru, CardLang::Kk, CardLang::KkRu] {
                            ui.selectable_value(&mut self.sign.card_lang, l, card_lang_name(l));
                        }
                    });
            });
        }
        egui::CollapsingHeader::new(tr("More options"))
            .id_salt("more_options")
            .show(ui, |ui| {
                if self.sign.sign_as == SignAs::Card {
                    ui.add_enabled(
                        false,
                        egui::Checkbox::new(
                            &mut true,
                            tr("Official signing time and key check from NCA (always on a card; needs internet)"),
                        ),
                    );
                    if kind != DocKind::Card {
                        ui.checkbox(
                            &mut self.sign.card_qr,
                            tr("Also print the signatures as QR codes"),
                        );
                    }
                } else {
                    ui.checkbox(
                        &mut self.sign.timestamp,
                        tr("Add the official signing time from NCA (needs internet; only a fingerprint of the document is sent)"),
                    );
                    ui.add_enabled(
                        self.sign.timestamp && self.ocsp,
                        egui::Checkbox::new(
                            &mut self.sign.long_term,
                            tr("Keep it checkable for years: store NCA's revocation answers in the signature and add an archive timestamp (long-term signature)"),
                        ),
                    );
                }
                if self.sign.sign_as == SignAs::Pdf {
                    ui.checkbox(
                        &mut self.sign.stamp,
                        tr("Show a stamp with your name and the signing time on the last page"),
                    );
                }
                if self.sign.sign_as == SignAs::Cms {
                    ui.add_enabled(
                        !self.sign.doc_is_cms,
                        egui::Checkbox::new(
                            &mut self.sign.detached,
                            tr("Keep the document out of the signature file (then send both files together)"),
                        ),
                    );
                }
            });
    }

    // ------------------------------------------------------------------ Signed

    pub(super) fn signed_screen(&mut self, ui: &mut egui::Ui) {
        let Some(d) = self.sign.done.clone() else {
            self.screen = Screen::Start;
            return;
        };
        ui.vertical_centered(|ui| {
            ui.add_space(24.0);
            let good = Tone::Good.color(ui);
            icons::badge(ui, Icon::Check, 80.0, good, good.gamma_multiply(0.14));
            ui.add_space(6.0);
            ui.label(
                RichText::new(if d.cosigned {
                    tr("Signature added")
                } else {
                    tr("Signed")
                })
                .size(24.0)
                .strong(),
            );
            ui.add_space(6.0);
            let when = if d.timestamped {
                tr("The signing time is confirmed by NCA.")
            } else {
                tr("The signing time comes from this computer's clock.")
            };
            ui.add(
                egui::Label::new(format!(
                    "{} {}",
                    trf("{} is signed by {}.", &[&d.doc_name, &d.signer]),
                    when
                ))
                .wrap(),
            );
            if d.signer_count > 1 {
                ui.label(trf("Signatures in the file now: {}", &[&d.signer_count]));
            }
            ui.add_space(12.0);
        });
        card(ui, |ui| {
            file_title_with(ui, &d.saved, Icon::FileCheck);
            // on Android the file is in the app's own folder until Android's Save as or Share
            // takes it somewhere the user can see
            if !cfg!(target_os = "android") {
                ui.label(
                    Tone::Muted.text(
                        ui,
                        trf(
                            "Saved in {}",
                            &[&d.saved
                                .parent()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default()],
                        ),
                    ),
                );
            }
            let what = match d.sign_as {
                SignAs::Cms if d.detached => tr(
                    "Send this .cms file together with the document: it holds only your signature.",
                ),
                SignAs::Cms => {
                    tr("Send this .cms file: it holds both the document and your signature.")
                }
                SignAs::Pdf => {
                    tr("This PDF opens in any PDF viewer and carries your signature inside it.")
                }
                SignAs::Xml => tr("This XML document carries your signature inside it (XAdES)."),
                SignAs::Card => tr(
                    "This PDF shows the document and its signatures; the original file and the signatures are attached inside it.",
                ),
            };
            ui.add(egui::Label::new(what).wrap());
        });
        for w in &d.warnings {
            warning(ui, w);
        }
        ui.add_space(14.0);
        let android = cfg!(target_os = "android");
        action_row(ui, self.narrow, |ui, size, min| {
            let (icon, reveal) = if android {
                (Icon::Share, tr("Share"))
            } else {
                (Icon::Folder, tr("Show in folder"))
            };
            if icons::button(ui, icon, reveal, size, min, true).clicked() {
                self.dialogs.reveal(&d.saved);
            }
            if android
                && icons::button(
                    ui,
                    Icon::Download,
                    tr("Save to the phone…"),
                    size,
                    min,
                    false,
                )
                .clicked()
            {
                self.dialogs.saved(&d.saved);
            }
            if icons::button(ui, Icon::Pen, tr("Sign another document"), size, min, false).clicked()
            {
                self.sign.doc = None;
                self.sign.doc_note = Note::default();
                self.sign.doc_kind = DocKind::Other;
                self.sign.doc_is_cms = false;
                self.sign.doc_is_detached_cms = false;
                self.sign.sign_original = None;
                self.screen = Screen::Sign;
            }
        });
    }

    // ------------------------------------------------------------------ fields

    pub fn set_doc(&mut self, ctx: &egui::Context, file: PathBuf) {
        self.sign.doc = Some(file.clone());
        self.sign.doc_request += 1;
        let request = self.sign.doc_request;
        self.sign.doc_is_detached_cms = false;
        self.sign.doc_is_cms = false;
        self.sign.doc_kind = DocKind::Other;
        self.sign.sign_original = None;
        self.sign.doc_note = Note::default();
        self.background(ctx, move |e| {
            let r = std::fs::read(&file)
                .map_err(|err| format!("{}: {err}", file.display()))
                .and_then(|data| {
                    if e.is_signed_cms(&data) {
                        let rep = e.verify(&data, None, None).map_err(|x| x.0)?;
                        Ok((DocKind::Cms, Some(rep)))
                    } else if e.card_original(&data).is_some() {
                        let rep = e.verify(&data, None, None).map_err(|x| x.0)?;
                        Ok((DocKind::Card, Some(rep)))
                    } else if e.is_pdf(&data) {
                        match e.verify(&data, None, None) {
                            Ok(rep) if !rep.signers.is_empty() => {
                                Ok((DocKind::SignedPdf, Some(rep)))
                            }
                            _ => Ok((DocKind::Pdf, None)),
                        }
                    } else if e.is_xml(&data) {
                        match e.verify(&data, None, None) {
                            Ok(rep) if !rep.signers.is_empty() => {
                                Ok((DocKind::SignedXml(e.xml_has_room(&data)), Some(rep)))
                            }
                            Ok(_) => Ok((DocKind::Xml, None)),
                            Err(_) => Ok((DocKind::Other, None)),
                        }
                    } else {
                        Ok((DocKind::Other, None))
                    }
                });
            Msg::DocChecked(request, r)
        });
    }

    pub fn set_key_file(&mut self, ctx: &egui::Context, file: PathBuf) {
        self.key.file = Some(file);
        self.key.aliases.clear();
        self.key.alias = None;
        self.open_key(ctx);
    }

    /// Opens the key with the current file, password and alias, unless that is already done.
    pub fn open_key(&mut self, ctx: &egui::Context) {
        let Some(f) = self.key.file.clone() else {
            return;
        };
        let wanted = self.key.alias.clone();
        let pw_hash = crate::hex(&crate::gost::sha256(self.key.password.as_bytes()));
        let request = key_request(&f, wanted.as_deref(), &pw_hash);
        if self.key.opened_for.as_deref() == Some(request.as_str()) && self.key.opened.is_some() {
            return; // nothing changed (e.g. focus lost)
        }
        self.key.opened = None;
        self.key.opened_for = None;
        // any key still being opened is for an older file, password or alias: ignore it
        self.key.request += 1;
        let id = self.key.request;
        if self.key.password.is_empty() {
            self.key.note = Note::default();
            return;
        }
        self.key.note = Note(vec![(tr("Opening key…").into(), Tone::Muted)]);
        let pw = self.key.password.clone();
        self.background(ctx, move |e| {
            let r = std::fs::read(&f)
                .map_err(|err| format!("{}: {err}", f.display()))
                .and_then(|d| {
                    e.open_key(&d, &pw, wanted.as_deref())
                        .map(Box::new)
                        .map_err(|x| x.0)
                });
            Msg::KeyOpened(id, f, pw_hash, r)
        });
    }

    pub(super) fn describe_key(&self, k: &Key) -> Note {
        let s = self.engine.describe(&k.cert);
        let text = |t: String| (t, Tone::Plain);
        let mut n = vec![(s.name(), Tone::Strong)];
        if let Some(iin) = s.get("IIN") {
            n.push(text(trf("IIN {}", &[&iin])));
        }
        if let Some(o) = s.get("O") {
            let bin = s
                .get("BIN")
                .map(|b| trf(" (BIN {})", &[&b]))
                .unwrap_or_default();
            n.push(text(format!("{o}{bin}")));
        }
        n.push(text(trf(
            "Valid until {} · {}",
            &[
                &time::fmt(s.not_after),
                &s.algorithm.clone().unwrap_or_default(),
            ],
        )));
        let issuer = s.issuer_cn.clone().unwrap_or_default();
        if s.chain_ok {
            n.push((trf("Issuer: {} ✔", &[&issuer]), Tone::Plain));
        } else {
            n.push((
                trf("Issuer: {} (not a trusted NCA RK issuer)", &[&issuer]),
                Tone::Bad,
            ));
        }
        if let Some(e) = &s.usage_error {
            n.push((trf("This key may not sign documents: {}", &[e]), Tone::Bad));
        }
        for w in self.engine.key_warnings(&k.cert) {
            n.push((format!("⚠ {w}"), Tone::Warn));
        }
        Note(n)
    }

    pub fn sign(&mut self, ctx: &egui::Context) {
        let (Some(doc), Some(key)) = (self.sign.doc.clone(), self.key.opened.clone()) else {
            return;
        };
        let det = self.sign.detached && !self.sign.doc_is_cms;
        // NCA's timestamp server no longer serves GOST 34.310-2004 keys
        let gost2004 = key.cert.key_alg() == crate::gost::KEY_GOST2004;
        let skip_tsa = self.sign.timestamp && gost2004 && self.sign.sign_as != SignAs::Card;
        let tsa = (self.sign.timestamp && !skip_tsa).then(|| DEFAULT_TSA_URL.to_string());
        // the long-term data comes from NCA's OCSP server: not when online checks are off
        let long_term =
            tsa.is_some() && self.ocsp && self.sign.long_term && self.sign.sign_as != SignAs::Card;
        let stamp = self.sign.stamp.then(|| crate::pdf::stamp::Stamp {
            lang: Some(crate::i18n::lang()),
            ..Default::default()
        });
        // check that the key is not revoked (Order 500/НҚ p.4.3), unless online checks are off
        let ocsp = self.ocsp.then(|| DEFAULT_OCSP_URL.to_string());
        let sign_as = self.sign.sign_as;
        let (qr, lang) = (self.sign.card_qr, self.sign.card_lang);
        let card_cosign = self.sign.doc_kind == DocKind::Card;
        let orig = if self.sign.doc_is_detached_cms {
            self.sign.sign_original.clone()
        } else {
            None
        };
        self.sign.signing = true;
        self.background(ctx, move |e| {
            let r = (|| -> Result<SignResult, String> {
                let input =
                    std::fs::read(&doc).map_err(|err| format!("{}: {err}", doc.display()))?;
                let o = orig
                    .map(|p| std::fs::read(&p).map_err(|err| format!("{}: {err}", p.display())))
                    .transpose()?;
                let r = match sign_as {
                    SignAs::Cms => e.sign(
                        &input,
                        &key,
                        det,
                        tsa.as_deref(),
                        ocsp.as_deref(),
                        true,
                        o.as_deref(),
                    ),
                    SignAs::Xml => e.sign_xml(&input, &key, tsa.as_deref(), ocsp.as_deref()),
                    SignAs::Pdf => e.sign_pdf_with(
                        &input,
                        &key,
                        tsa.as_deref(),
                        ocsp.as_deref(),
                        stamp.as_ref(),
                    ),
                    SignAs::Card => {
                        let name = doc
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        // adding to a card keeps how it was made
                        let (lang, qr) = if card_cosign {
                            (None, None)
                        } else {
                            (Some(lang), Some(qr))
                        };
                        e.sign_card(
                            &input,
                            &name,
                            &key,
                            DEFAULT_TSA_URL,
                            DEFAULT_OCSP_URL,
                            lang,
                            qr,
                        )
                    }
                }
                .map_err(|x| x.0)?;
                let mut r = r;
                if skip_tsa {
                    r.warnings.push(tr("No timestamp: NCA's timestamp server no longer serves GOST 34.310-2004 keys.").into());
                }
                if !long_term {
                    return Ok(r);
                }
                // the document a detached .cms signs
                let doc = if det { Some(&input) } else { o.as_ref() };
                Ok(e.extend_new(
                    r,
                    doc.map(Vec::as_slice),
                    crate::ltv::Level::Lta,
                    DEFAULT_TSA_URL,
                    DEFAULT_OCSP_URL,
                ))
            })();
            Msg::Signed(doc, sign_as, r)
        });
    }

    pub(super) fn save_signed(&mut self, doc: &Path, sign_as: SignAs, r: SignResult) {
        let suggested = if r.cosigned {
            doc.to_path_buf()
        } else {
            match sign_as {
                SignAs::Cms => PathBuf::from(format!("{}.cms", doc.display())),
                SignAs::Pdf => crate::signed_name(doc, "pdf"),
                SignAs::Xml => crate::signed_name(doc, "xml"),
                SignAs::Card => PathBuf::from(format!("{}.card.pdf", doc.display())),
            }
        };
        let Some(out) = self.dialogs.save(&suggested) else {
            return;
        };
        if let Err(e) = std::fs::write(&out, &r.cms) {
            self.message = Some((trf("Could not save: {}", &[&e]), true));
            return;
        }
        self.dialogs.saved(&out);
        let doc_name = doc
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.sign.done = Some(Done {
            saved: out,
            doc_name,
            signer: self.key.holder.clone().unwrap_or_default(),
            cosigned: r.cosigned,
            timestamped: r.timestamped || sign_as == SignAs::Card,
            sign_as,
            detached: sign_as == SignAs::Cms && self.sign.detached && !self.sign.doc_is_cms,
            signer_count: r.signer_count,
            warnings: r.warnings,
        });
        self.screen = Screen::Signed;
    }
}

pub(super) fn card_lang_name(l: CardLang) -> &'static str {
    match l {
        CardLang::Ru => tr("Russian"),
        CardLang::Kk => tr("Kazakh"),
        CardLang::KkRu => tr("Kazakh and Russian"),
    }
}

impl App {
    /// A document check came back: what the document is, and how it can be signed.
    pub(super) fn doc_checked(
        &mut self,
        ctx: &egui::Context,
        id: u64,
        r: Result<(DocKind, Option<VerifyReport>), String>,
    ) {
        if id != self.sign.doc_request {
            return;
        }
        let route = std::mem::take(&mut self.sign.route_signed_to_check);
        if route
            && matches!(
                &r,
                Ok((
                    DocKind::Cms | DocKind::SignedPdf | DocKind::Card | DocKind::SignedXml(_),
                    _
                ))
            )
            && let Some(f) = self.sign.doc.take()
        {
            // a signed file opened from the start: the person most likely wants to see
            // who signed it (adding a signature is one click away, from Sign)
            self.screen = Screen::Check;
            self.sign.doc_note = Note::default();
            self.set_cms(ctx, f);
            return;
        }
        match r {
            Ok((kind, rep)) => {
                self.sign.doc_kind = kind;
                if let Some(rep) = rep {
                    let names: Vec<String> = rep.signers.iter().map(SignerReport::name).collect();
                    self.sign.doc_note = Note(vec![
                            (
                                trf(
                                    "Already signed ({}): {}.",
                                    &[&rep.signers.len(), &names.join(", ")],
                                ),
                                Tone::Plain,
                            ),
                            (
                                match kind {
                                    DocKind::Card => tr(
                                        "Your signature will be added to this document card.",
                                    ),
                                    DocKind::SignedPdf => {
                                        tr("Your signature can be added inside this PDF.")
                                    }
                                    DocKind::SignedXml(true) => tr(
                                        "Your signature can be added inside this XML document.",
                                    ),
                                    DocKind::SignedXml(false) => tr(
                                        "Another signature cannot go inside this XML document without breaking the first one; yours can go into a .cms file or a card.",
                                    ),
                                    _ => tr("Your signature will be added to this file."),
                                }
                                .into(),
                                Tone::Strong,
                            ),
                        ]);
                    if kind == DocKind::Cms {
                        self.sign.doc_is_cms = true;
                        self.sign.detached = false;
                        self.sign.doc_is_detached_cms = !rep.has_content;
                    }
                }
                self.sign.sign_as = match kind {
                    DocKind::Cms => SignAs::Cms,
                    DocKind::Card => SignAs::Card,
                    DocKind::SignedPdf => SignAs::Pdf,
                    DocKind::Xml => SignAs::Xml,
                    DocKind::SignedXml(true) => SignAs::Xml,
                    DocKind::SignedXml(false) => SignAs::Cms,
                    DocKind::Other | DocKind::Pdf if self.sign.sign_as == SignAs::Xml => {
                        SignAs::Cms
                    }
                    DocKind::Other if self.sign.sign_as == SignAs::Pdf => SignAs::Cms,
                    _ => self.sign.sign_as,
                };
            }
            Err(e) => self.sign.doc_note = Note::error(&e),
        }
    }

    /// A key was opened (or could not be).
    pub(super) fn key_opened(
        &mut self,
        id: u64,
        f: &Path,
        pw_hash: &str,
        r: Result<Box<Key>, String>,
    ) {
        if id != self.key.request {
            return;
        }
        match r {
            Ok(k) => {
                if !k.other_aliases.is_empty() && self.key.aliases.is_empty() {
                    self.key.aliases = std::iter::once(k.alias.clone())
                        .chain(k.other_aliases.iter().cloned())
                        .collect();
                    self.key.alias = Some(k.alias.clone());
                }
                self.key.note = self.describe_key(&k);
                let d = self.engine.describe(&k.cert);
                self.key.holder = Some(d.name());
                self.key.ok = d.chain_ok
                    && d.usage_error.is_none()
                    && self.engine.key_warnings(&k.cert).is_empty();
                self.key.alias = Some(k.alias.clone());
                self.key.opened_for = Some(key_request(f, Some(&k.alias), pw_hash));
                self.key.opened = Some(Arc::new(*k));
            }
            Err(e) => {
                self.key.holder = None;
                self.key.note = Note::error(&e);
            }
        }
    }

    /// Signing finished: save the result, or say why it failed.
    pub(super) fn signed(&mut self, doc: &Path, sign_as: SignAs, r: Result<SignResult, String>) {
        self.sign.signing = false;
        match r {
            Ok(r) => self.save_signed(doc, sign_as, r),
            Err(e) => {
                // NCA's time (on by default) and a card's key check need the internet
                let offline_hint = e.contains(DEFAULT_TSA_URL) || e.contains(DEFAULT_OCSP_URL);
                let e = if offline_hint && sign_as == SignAs::Card {
                    format!(
                        "{e}\n\n{}",
                        tr(
                            "A printable card needs the internet: it gets the official time and the key check from NCA. Check the connection and try again, or save a signature file instead."
                        )
                    )
                } else if offline_hint {
                    format!(
                        "{e}\n\n{}",
                        tr(
                            "Getting the official time from NCA needs the internet. Check the connection and try again, or turn off the NCA time under More options."
                        )
                    )
                } else {
                    e
                };
                self.message = Some((e, true));
            }
        }
    }
}
