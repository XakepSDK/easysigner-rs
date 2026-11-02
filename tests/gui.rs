//! Drives the window like a person: from the start screen, choose a document and key, type the
//! password, sign, then check the result and save the original back out. File dialogs are
//! scripted, and the network is not used (no NCA time, no revocation check).
#![cfg(feature = "gui")]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use eframe::egui;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use kzsigner::cert::Cert;
use kzsigner::gui::{App, Dialogs, Screen};

/// File dialogs that answer from a queue.
#[derive(Clone, Default)]
struct Scripted(Arc<Mutex<VecDeque<PathBuf>>>, Arc<Mutex<Vec<PathBuf>>>);

impl Scripted {
    fn next(&self, p: PathBuf) {
        self.0.lock().unwrap().push_back(p);
    }
}

impl Dialogs for Scripted {
    fn open(&mut self, _: &'static str, _: Option<&Path>) -> Option<PathBuf> {
        self.0.lock().unwrap().pop_front()
    }
    fn save(&mut self, _: &Path) -> Option<PathBuf> {
        self.0.lock().unwrap().pop_front()
    }
    /// Files opened for reading are noted, not shown.
    fn view(&mut self, path: &Path) -> Result<(), String> {
        self.1.lock().unwrap().push(path.to_path_buf());
        Ok(())
    }
}

/// The window's language is global: one test at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn settle(h: &mut Harness<'_, App>) {
    for _ in 0..400 {
        h.run_steps(2);
        if !h.state().busy() {
            h.run_steps(2);
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    panic!("background work did not finish");
}

#[test]
fn sign_then_verify_in_the_window() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kalkan");
    let dir = std::env::temp_dir().join(format!("kzsigner-gui-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let doc = dir.join("doc.txt");
    std::fs::write(&doc, "Договор №1 test document\n").unwrap();

    let ca = Cert::parse_any(&std::fs::read(fx.join("ca_gost2015.cer")).unwrap()).unwrap();
    let dialogs = Scripted::default();
    let mut app = App::new(kzsigner::Engine::new(vec![ca]), Box::new(dialogs.clone()));
    // safe by default: NCA time and the revocation check are on
    assert!(app.timestamp && app.ocsp);
    (app.timestamp, app.ocsp) = (false, false);
    let mut h = Harness::builder()
        .with_size([780.0, 720.0])
        .build_ui_state(|ui, app: &mut App| app.ui(ui), app);
    h.run();
    h.get_all_by_label("Sign a document")
        .next()
        .unwrap()
        .click();
    h.run();
    assert_eq!(h.state().screen, Screen::Sign);

    // 1. document, 2. key and password
    dialogs.next(doc.clone());
    h.get_all_by_label("Browse…").next().unwrap().click();
    settle(&mut h);
    // the key's path is pasted into its field (with the quotes Windows' "Copy as path" adds)
    let key_field = h.get_by_label("Key file (.p12), for example GOSTKNCA_… or RSA_…");
    key_field.focus();
    key_field.type_text(&format!("\"{}\"", fx.join("alice_gost2015.p12").display()));
    h.run();
    h.key_press(egui::Key::Enter);
    settle(&mut h);
    assert_eq!(h.state().key_file, Some(fx.join("alice_gost2015.p12")));
    let pw = h.get_by_role(egui::accesskit::Role::PasswordInput);
    pw.focus();
    pw.type_text("Qwerty12");
    h.run();
    // the eye shows the password as plain text, and hides it again
    // (a key open may be running in the background: step instead of waiting for quiet)
    h.get_by_label("Show password").click();
    h.run_steps(2);
    assert!(
        h.query_by_role(egui::accesskit::Role::PasswordInput)
            .is_none()
    );
    h.get_by_label("Hide password").click();
    h.run_steps(2);
    let pw = h.get_by_role(egui::accesskit::Role::PasswordInput);
    pw.focus();
    h.run_steps(2);
    h.key_press(egui::Key::Enter);
    settle(&mut h);
    assert!(
        h.query_by_label_contains("ИВАНОВ АЛИБЕК").is_some(),
        "key details are shown"
    );

    // the document can be read before signing (Art. 50)
    h.get_by_label("Open the document").click();
    // which file to show is worked out off the UI thread
    settle(&mut h);
    assert_eq!(*dialogs.1.lock().unwrap(), std::slice::from_ref(&doc));

    // sign and save
    let out = dir.join("doc.txt.cms");
    dialogs.next(out.clone());
    h.get_by_label("Sign").click();
    settle(&mut h);
    assert_eq!(h.state().screen, Screen::Signed, "{:?}", h.state().message);
    let done = h.state().done.clone().unwrap();
    assert_eq!(done.saved, out);
    assert_eq!(done.signer, "ИВАНОВ АЛИБЕК");
    assert!(
        h.query_by_label_contains("doc.txt is signed by ИВАНОВ АЛИБЕК")
            .is_some()
    );

    // check the new file
    h.get_by_label("Back").click();
    h.run();
    h.get_all_by_label("Check a signed file")
        .next()
        .unwrap()
        .click();
    h.run();
    dialogs.next(out.clone());
    h.get_by_label("Browse…").click();
    settle(&mut h);
    assert!(
        h.query_by_label_contains("The signature is valid")
            .is_some(),
        "report shown"
    );
    assert!(
        h.query_by_label_contains("Not changed since signing")
            .is_some()
    );

    // save the original document back out
    let back = dir.join("back.txt");
    dialogs.next(back.clone());
    h.get_by_label("Save the document…").click();
    settle(&mut h);
    assert_eq!(std::fs::read(&back).unwrap(), std::fs::read(&doc).unwrap());

    // switch the language from the menu: the report is redone in it
    // (the choice is remembered in a file under the config folder: keep it in the test folder)
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", &dir);
        std::env::set_var("APPDATA", &dir);
    }
    h.get_by_label("OK").click();
    h.run();
    for (name, valid, tab) in [
        (
            "Русский",
            "Подпись действительна",
            "Проверить подписанный файл",
        ),
        ("Қазақша", "Қолтаңба жарамды", "Қол қойылған файлды тексеру"),
    ] {
        h.get_by_value(kzsigner::i18n::lang().name())
            .click_accesskit();
        h.run_steps(3);
        h.get_by_label(name).click();
        settle(&mut h);
        assert!(h.query_by_label_contains(valid).is_some(), "{name} report");
        assert!(h.query_by_label(tab).is_some(), "{name} tab");
    }
    assert_eq!(
        std::fs::read_to_string(dir.join("kzsigner/language")).unwrap(),
        "kk"
    );
    kzsigner::i18n::set(kzsigner::i18n::Lang::En);
    println!("GUI OK");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pdf_signing_and_cards_in_the_window() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    kzsigner::i18n::set(kzsigner::i18n::Lang::En);
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let dir = std::env::temp_dir().join(format!("kzsigner-gui-pdf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pdf = dir.join("plain.pdf");
    std::fs::copy(fx.join("pdf/plain.pdf"), &pdf).unwrap();
    let ca = Cert::parse_any(&std::fs::read(fx.join("kalkan/ca_rsa.cer")).unwrap()).unwrap();
    let key_file = fx.join("kalkan/alice_rsa.p12");

    // a card to check later, made without the network (no timestamp)
    let key = kzsigner::p12::open(&std::fs::read(&key_file).unwrap(), "Qwerty12", None).unwrap();
    let engine = kzsigner::Engine::new(vec![ca.clone()]);
    let doc = std::fs::read(&pdf).unwrap();
    let cms = engine
        .sign(&doc, &key, true, None, None, false, None)
        .unwrap()
        .cms;
    let card = kzsigner::pdf::card::build(
        &kzsigner::pdf::card::CardInput {
            doc: &doc,
            file_name: "plain.pdf",
            signatures: vec![("plain.pdf.1.cms".into(), cms)],
            lang: kzsigner::pdf::card::CardLang::Ru,
            qr: true,
        },
        &kzsigner::trust::TrustStore::new(vec![ca.clone()]),
    )
    .unwrap();
    let card_file = dir.join("plain.pdf.card.pdf");
    std::fs::write(&card_file, card).unwrap();

    let dialogs = Scripted::default();
    let mut app = App::new(engine, Box::new(dialogs.clone()));
    (app.timestamp, app.ocsp) = (false, false);
    let mut h = Harness::builder()
        .with_size([780.0, 760.0])
        .build_ui_state(|ui, app: &mut App| app.ui(ui), app);
    h.run();
    h.get_all_by_label("Sign a document")
        .next()
        .unwrap()
        .click();
    h.run();
    dialogs.next(pdf.clone());
    h.get_all_by_label("Browse…").next().unwrap().click();
    settle(&mut h);
    let key_field = h.get_by_label("Key file (.p12), for example GOSTKNCA_… or RSA_…");
    key_field.focus();
    key_field.type_text(&key_file.display().to_string());
    h.run();
    h.key_press(egui::Key::Enter);
    let pw = h.get_by_role(egui::accesskit::Role::PasswordInput);
    pw.focus();
    pw.type_text("Qwerty12");
    h.run();
    h.key_press(egui::Key::Enter);
    settle(&mut h);

    // sign inside the PDF
    // the whole box picks the option, its text too, not only the radio button
    h.get_by_label("Still opens as a normal PDF. Only for PDF files.")
        .click();
    h.run();
    assert_eq!(h.state().sign_as, kzsigner::gui::SignAs::Pdf);
    // with a visible stamp (More options)
    h.get_by_label("More options").click();
    h.run();
    h.get_by_label("Show a stamp with your name and the signing time on the last page")
        .click();
    h.run();
    assert!(h.state().stamp);
    h.get_by_label("More options").click();
    h.run();
    let out = dir.join("plain-signed.pdf");
    dialogs.next(out.clone());
    h.get_by_label("Sign").click();
    settle(&mut h);
    assert_eq!(h.state().screen, Screen::Signed, "{:?}", h.state().message);
    let signed = std::fs::read(&out).unwrap();
    assert!(signed.starts_with(&doc));
    assert!(
        signed[doc.len()..].windows(3).any(|w| w == b"/AP"),
        "the stamp is drawn"
    );

    // check the signed PDF, then the card, and save the card's document
    h.get_by_label("Back").click();
    h.run();
    h.get_all_by_label("Check a signed file")
        .next()
        .unwrap()
        .click();
    h.run();
    dialogs.next(out.clone());
    h.get_by_label("Browse…").click();
    settle(&mut h);
    assert!(
        h.query_by_label_contains("The signature is valid")
            .is_some()
    );
    dialogs.next(card_file.clone());
    h.get_by_label("Browse…").click();
    settle(&mut h);
    assert!(
        h.query_by_label_contains("The document inside the card has not been changed")
            .is_some()
    );
    let back = dir.join("back.pdf");
    dialogs.next(back.clone());
    h.get_by_label("Save the document…").click();
    settle(&mut h);
    assert_eq!(std::fs::read(&back).unwrap(), doc);

    // an XML document: signed inside it (XAdES) by default, then checked
    let xml = dir.join("request.xml");
    std::fs::write(
        &xml,
        "<?xml version=\"1.0\"?>\n<request><n>7</n></request>\n",
    )
    .unwrap();
    let dialogs = Scripted::default();
    let mut app = App::new(
        kzsigner::Engine::new(vec![ca.clone()]),
        Box::new(dialogs.clone()),
    );
    (app.timestamp, app.ocsp) = (false, false);
    let mut h = Harness::builder()
        .with_size([780.0, 760.0])
        .build_ui_state(|ui, app: &mut App| app.ui(ui), app);
    h.run();
    h.get_all_by_label("Sign a document")
        .next()
        .unwrap()
        .click();
    h.run();
    dialogs.next(xml.clone());
    h.get_all_by_label("Browse…").next().unwrap().click();
    settle(&mut h);
    let key_field = h.get_by_label("Key file (.p12), for example GOSTKNCA_… or RSA_…");
    key_field.focus();
    key_field.type_text(&key_file.display().to_string());
    h.run();
    h.key_press(egui::Key::Enter);
    let pw = h.get_by_role(egui::accesskit::Role::PasswordInput);
    pw.focus();
    pw.type_text("Qwerty12");
    h.run();
    h.key_press(egui::Key::Enter);
    settle(&mut h);
    assert_eq!(h.state().sign_as, kzsigner::gui::SignAs::Xml);
    let xml_out = dir.join("request-signed.xml");
    dialogs.next(xml_out.clone());
    h.get_by_label("Sign").click();
    settle(&mut h);
    assert_eq!(h.state().screen, Screen::Signed, "{:?}", h.state().message);
    let signed = std::fs::read_to_string(&xml_out).unwrap();
    assert!(signed.contains("<ds:Signature") && signed.ends_with("</request>\n"));
    h.get_by_label("Back").click();
    h.run();
    h.get_all_by_label("Check a signed file")
        .next()
        .unwrap()
        .click();
    h.run();
    dialogs.next(xml_out.clone());
    h.get_by_label("Browse…").click();
    settle(&mut h);
    assert!(
        h.query_by_label_contains("The signature is valid")
            .is_some()
    );

    // a signed file opened from the start screen is checked, not signed again
    let mut app = App::new(
        kzsigner::Engine::new(vec![ca.clone()]),
        Box::new(Scripted::default()),
    );
    app.ocsp = false;
    app.pending_open = Some(out.clone());
    let mut h = Harness::builder()
        .with_size([780.0, 760.0])
        .build_ui_state(|ui, app: &mut App| app.ui(ui), app);
    settle(&mut h);
    assert_eq!(h.state().screen, Screen::Check);
    assert!(
        h.query_by_label_contains("The signature is valid")
            .is_some()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
