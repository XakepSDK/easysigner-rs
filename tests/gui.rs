//! Drives the window like a person: choose a document and key, type the password, sign, then
//! verify the result and save the original back out. File dialogs are scripted.
#![cfg(feature = "gui")]

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use eframe::egui;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use kzsigner::cert::Cert;
use kzsigner::gui::{App, Dialogs};

/// File dialogs that answer from a queue.
#[derive(Clone, Default)]
struct Scripted(Arc<Mutex<VecDeque<PathBuf>>>);

impl Scripted {
    fn next(&self, p: PathBuf) {
        self.0.lock().unwrap().push_back(p);
    }
}

impl Dialogs for Scripted {
    fn open(&mut self, _: Option<&Path>) -> Option<PathBuf> {
        self.0.lock().unwrap().pop_front()
    }
    fn save(&mut self, _: &Path) -> Option<PathBuf> {
        self.0.lock().unwrap().pop_front()
    }
}

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
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kalkan");
    let dir = std::env::temp_dir().join(format!("kzsigner-gui-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let doc = dir.join("doc.txt");
    std::fs::write(&doc, "Договор №1 test document\n").unwrap();

    let ca = Cert::parse_any(&std::fs::read(fx.join("ca_gost2015.cer")).unwrap()).unwrap();
    let dialogs = Scripted::default();
    let app = App::new(kzsigner::Engine::new(vec![ca]), Box::new(dialogs.clone()));
    let mut h = Harness::builder()
        .with_size([760.0, 640.0])
        .build_ui_state(|ui, app: &mut App| app.ui(ui), app);
    h.run();

    // 1. document, 2. key and password
    dialogs.next(doc.clone());
    h.get_all_by_label("Browse…").next().unwrap().click();
    settle(&mut h);
    // the key's path is pasted into its field (with the quotes Windows' "Copy as path" adds)
    let key_field = h.get_by_label("Key file (.p12), e.g. RSA_… or GOSTKNCA_…");
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
    h.get_by_label("Show password").click();
    h.run();
    assert!(
        h.query_by_role(egui::accesskit::Role::PasswordInput)
            .is_none()
    );
    h.get_by_label("Hide password").click();
    h.run();
    let pw = h.get_by_role(egui::accesskit::Role::PasswordInput);
    pw.focus();
    h.run();
    h.key_press(egui::Key::Enter);
    settle(&mut h);
    assert!(
        h.query_by_label_contains("ИВАНОВ АЛИБЕК").is_some(),
        "key details are shown"
    );

    // sign and save
    let out = dir.join("doc.txt.cms");
    dialogs.next(out.clone());
    h.get_by_label("Sign…").click();
    settle(&mut h);
    let msg = h.state().message.clone().expect("a message after signing");
    assert!(msg.0.starts_with("Signed."), "{msg:?}");
    h.get_by_label("OK").click();
    h.run();

    // verify the new file in the other tab
    h.get_by_label("Verify / Extract").click();
    h.run();
    dialogs.next(out.clone());
    h.get_by_label("Browse…").click();
    settle(&mut h);
    assert!(
        h.query_by_label_contains("Valid. Signatures: 1, all check out.")
            .is_some(),
        "report shown"
    );
    assert!(h.query_by_label_contains("Issuer").is_some());

    // save the original document back out
    let back = dir.join("back.txt");
    dialogs.next(back.clone());
    h.get_by_label("Save original document…").click();
    settle(&mut h);
    assert_eq!(std::fs::read(&back).unwrap(), std::fs::read(&doc).unwrap());

    // switch the language from the menu: the report is redone in it
    // (the choice is remembered in a file under the config folder: keep it in the test folder)
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", &dir);
        std::env::set_var("APPDATA", &dir);
    }
    for (name, valid, tab) in [
        (
            "Русский",
            "Действительно. Подписей: 1, все верны.",
            "Проверить / Извлечь",
        ),
        (
            "Қазақша",
            "Жарамды. Қолтаңбалар: 1, барлығы дұрыс.",
            "Тексеру / Шығарып алу",
        ),
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
