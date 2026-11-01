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
    dialogs.next(fx.join("alice_gost2015.p12"));
    h.get_all_by_label("Browse…").nth(1).unwrap().click();
    settle(&mut h);
    let pw = h.get_by_role(egui::accesskit::Role::PasswordInput);
    pw.focus();
    pw.type_text("Qwerty12");
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
        h.query_by_label_contains("Valid: 1 signature, all check out")
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
    println!("GUI OK");
    let _ = std::fs::remove_dir_all(&dir);
}
