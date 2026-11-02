//! The Check screen: a signed file, its check, and taking its document out.

#[allow(unused_imports)]
use super::*;

impl App {
    pub(super) fn check_screen(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        card(ui, |ui| {
            if let Some(c) = &self.check.cms {
                file_title(ui, c);
            }
            let c = self.check.cms.clone();
            if let Some(f) = self.file_field(
                ui,
                "cms",
                tr("Signed file (.cms, signed PDF or document card)"),
                &c,
            ) {
                self.set_cms(&ctx, f);
            }
            if self.check.show_verify_original {
                let o = self.check.verify_original.clone();
                if let Some(f) = self.file_field(
                    ui,
                    "verify_original",
                    tr("This signature file does not contain the document. Choose the signed document:"),
                    &o,
                ) {
                    self.check.verify_original = Some(f);
                    self.verify(&ctx);
                }
            }
            egui::CollapsingHeader::new(tr("More options"))
                .id_salt("check_options")
                .show(ui, |ui| {
                    if ui
                        .checkbox(
                            &mut self.ocsp,
                            tr("Check online that the signers' keys were not revoked (needs internet)"),
                        )
                        .changed()
                        && self.check.cms.is_some()
                    {
                        self.verify(&ctx);
                    }
                });
        });
        ui.add_space(10.0);
        if self.check.checking {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(tr("Checking…"));
            });
            return;
        }
        match &self.check.result {
            Some(Ok(r)) => {
                let r = r.clone();
                report(ui, &r);
                let can_extract = r.has_content && !r.is_pdf;
                // a detached signature has nothing to show until its original is chosen
                let can_view = r.has_content || r.is_pdf || self.check.verify_original.is_some();
                ui.add_space(10.0);
                action_row(ui, self.narrow, |ui, size, min| {
                    // the main action only when the document can be trusted
                    if can_view
                        && icons::button(
                            ui,
                            Icon::Open,
                            tr("Open the document"),
                            size,
                            min,
                            r.valid,
                        )
                        .clicked()
                        && let Some(c) = self.check.cms.clone()
                    {
                        let o = self.check.verify_original.clone();
                        self.view_file(&ctx, c, o, ViewFor::Check(self.check.verify_request));
                    }
                    if can_extract
                        && icons::button(
                            ui,
                            Icon::Download,
                            tr("Save the document…"),
                            size,
                            min,
                            false,
                        )
                        .clicked()
                    {
                        self.extract(&ctx);
                    }
                });
            }
            Some(Err(e)) => {
                let e = e.clone();
                banner(ui, Tone::Bad, |ui| {
                    ui.label(
                        RichText::new(tr("This file could not be checked"))
                            .strong()
                            .size(18.0),
                    );
                    ui.add(egui::Label::new(e).wrap());
                });
            }
            None => {
                ui.label(Tone::Muted.text(
                    ui,
                    tr("Choose a signed file above, or drop it onto this window."),
                ));
            }
        }
    }

    pub fn set_cms(&mut self, ctx: &egui::Context, file: PathBuf) {
        self.check.cms = Some(file);
        self.check.verify_original = None;
        self.verify(ctx);
    }

    pub fn verify(&mut self, ctx: &egui::Context) {
        let Some(file) = self.check.cms.clone() else {
            return;
        };
        let orig = self.check.verify_original.clone();
        let ocsp = self.ocsp.then(|| DEFAULT_OCSP_URL.to_string());
        self.check.verify_request += 1;
        let id = self.check.verify_request;
        self.check.checking = true;
        self.background(ctx, move |e| {
            let r = (|| -> Result<VerifyReport, String> {
                let data =
                    std::fs::read(&file).map_err(|err| format!("{}: {err}", file.display()))?;
                let o = orig
                    .map(|p| std::fs::read(&p).map_err(|err| format!("{}: {err}", p.display())))
                    .transpose()?;
                e.verify(&data, o.as_deref(), ocsp.as_deref())
                    .map_err(|x| x.0)
            })();
            Msg::Verified(id, r)
        });
    }

    pub fn extract(&mut self, ctx: &egui::Context) {
        let Some(file) = self.check.cms.clone() else {
            return;
        };
        self.background(ctx, move |e| {
            let r = std::fs::read(&file)
                .map_err(|err| format!("{}: {err}", file.display()))
                .and_then(|d| taken_out(e, &file, &d));
            Msg::Extracted(file, r)
        });
    }

    pub(super) fn save_extracted(&mut self, file: &Path, base: String, data: Vec<u8>) {
        let Some(out) = self.dialogs.save(&file.with_file_name(base)) else {
            return;
        };
        self.message = Some(match std::fs::write(&out, &data) {
            // Android's own "Save as" comes next and says where it went
            Ok(()) if cfg!(target_os = "android") => {
                self.dialogs.saved(&out);
                return;
            }
            Ok(()) => (
                trf("Saved {} bytes to\n{}", &[&data.len(), &out.display()]),
                false,
            ),
            Err(e) => (trf("Could not save: {}", &[&e]), true),
        });
    }

    // ------------------------------------------------------------------ results
}

impl App {
    /// A check came back.
    pub(super) fn verified(&mut self, id: u64, r: Result<VerifyReport, String>) {
        if id != self.check.verify_request {
            return;
        }
        self.check.checking = false;
        if let Ok(rep) = &r {
            self.check.show_verify_original = !rep.has_content;
        }
        self.check.result = Some(r);
    }
}
