//! Drives the window like a person, against fake NCA servers on 127.0.0.1 (tests/common/nca.rs):
//! add a key, sign every kind of file, check every verdict, NCA down and a revoked key, Your
//! keys, the language. File dialogs are scripted; the keys live in a temporary folder.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

use eframe::egui;
use egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use kzsigner_desktop::gui::{App, Dialogs, Pick, Screen};
use kzsigner_ffi::{CantSign, Nca, Verdict};

mod render;

#[path = "../../tests/common/nca.rs"]
#[allow(dead_code)]
mod nca;

fn fixture(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/fixtures")
        .join(p)
}

/// File dialogs that answer from a queue, and note what was viewed and revealed.
#[derive(Clone, Default)]
struct Scripted {
    next: Arc<Mutex<VecDeque<PathBuf>>>,
    viewed: Arc<Mutex<Vec<PathBuf>>>,
    revealed: Arc<Mutex<Vec<PathBuf>>>,
    asked: Arc<Mutex<Vec<Pick>>>,
}

impl Scripted {
    fn next(&self, p: impl Into<PathBuf>) {
        self.next.lock().unwrap().push_back(p.into());
    }
}

impl Dialogs for Scripted {
    fn open(&mut self, what: Pick) -> Option<PathBuf> {
        self.asked.lock().unwrap().push(what);
        self.next.lock().unwrap().pop_front()
    }
    fn save(&mut self, _: &Path) -> Option<PathBuf> {
        self.next.lock().unwrap().pop_front()
    }
    fn reveal(&mut self, path: &Path) {
        self.revealed.lock().unwrap().push(path.to_path_buf());
    }
    fn view(&mut self, path: &Path) -> Result<(), String> {
        self.viewed.lock().unwrap().push(path.to_path_buf());
        Ok(())
    }
    fn view_dir(&self) -> PathBuf {
        std::env::temp_dir().join(format!("kzsigner-gui-view-{}", std::process::id()))
    }
}

/// NCA played by fakes that can be taken down or made to say every key is revoked.
struct Fake {
    down: Arc<AtomicBool>,
    revoked: Arc<AtomicBool>,
    nca: Arc<Nca>,
}

fn fake() -> Fake {
    let down = Arc::new(AtomicBool::new(false));
    let revoked = Arc::new(AtomicBool::new(false));
    let (d, tsa) = (down.clone(), nca::tsa_answer());
    let tsa = nca::serve(
        move |b| if d.load(SeqCst) { None } else { tsa(b) },
        "application/timestamp-reply",
    );
    let r = revoked.clone();
    let (d, ocsp) = (down.clone(), nca::ocsp_answer(move || r.load(SeqCst)));
    let ocsp = nca::serve(
        move |b| if d.load(SeqCst) { None } else { ocsp(b) },
        "application/ocsp-response",
    );
    // the RSA test CA is left out: its keys stand for keys not recognized in Kazakhstan
    let mut cas: Vec<Vec<u8>> = [
        "ocsp/ca.cer",
        "keys/ca_gost2015.cer",
        "kalkan/ca_gost2015.cer",
    ]
    .iter()
    .map(|p| std::fs::read(fixture(p)).unwrap())
    .collect();
    cas.push(
        kzsigner::p12::open(
            &std::fs::read(fixture("keys/tsa.p12")).unwrap(),
            "Qwerty12",
            None,
        )
        .unwrap()
        .cert
        .der,
    );
    Fake {
        down,
        revoked,
        nca: Nca::for_tests(tsa, ocsp, cas),
    }
}

/// The window's language and its saved choice are global: one test at a time, with the
/// saved choice in a folder of the tests' own.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

struct Test {
    h: Harness<'static, App>,
    dialogs: Scripted,
    fake: Fake,
    /// A folder with the files to sign and check.
    files: PathBuf,
    _one: std::sync::MutexGuard<'static, ()>,
}

fn start(name: &str) -> Test {
    start_sized(name, [1040.0, 700.0])
}

fn start_sized(name: &str, size: [f32; 2]) -> Test {
    let one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let root = std::env::temp_dir().join(format!("kzsigner-gui-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let files = root.join("files");
    std::fs::create_dir_all(&files).unwrap();
    for f in [
        "app/act.xml",
        "app/doc.txt",
        "app/doc.txt.cms",
        "app/contract-signed.pdf",
        "app/act.txt.cms",
        "app/act-changed.txt.cms",
        "app/rsa.txt.cms",
    ] {
        let p = fixture(f);
        std::fs::copy(&p, files.join(p.file_name().unwrap())).unwrap();
    }
    // SAFETY: tests that touch the environment run one at a time (ONE_AT_A_TIME)
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", root.join("config"));
        std::env::set_var("APPDATA", root.join("config"));
    }
    kzsigner::i18n::forget();
    kzsigner::i18n::set(kzsigner::i18n::Lang::En);
    let fake = fake();
    let dialogs = Scripted::default();
    let app = App::new(
        fake.nca.clone(),
        &root.join("data"),
        Box::new(dialogs.clone()),
    );
    let mut h = Harness::builder()
        .with_size(size)
        .renderer(render::Cpu::default())
        .with_render_cursor(false)
        .build_ui_state(|ui, app: &mut App| app.ui(ui), app);
    h.run();
    Test {
        h,
        dialogs,
        fake,
        files,
        _one: one,
    }
}

impl Test {
    fn app(&self) -> &App {
        self.h.state()
    }

    /// Runs frames until the background work is done.
    fn settle(&mut self) {
        for _ in 0..800 {
            self.h.run_steps(2);
            if !self.h.state().busy() {
                self.h.run_steps(3);
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("background work did not finish");
    }

    #[track_caller]
    fn click(&mut self, label: &str) {
        let screen = self.h.state().screen;
        let n = self.h.get_all_by_label(label).next();
        n.unwrap_or_else(|| panic!("no {label:?} on {screen:?}"))
            .scroll_to_me();
        // until the scrolling has stopped: a press while it moves is not a click
        self.h.run_steps(20);
        let n = self.h.get_all_by_label(label).next();
        n.unwrap_or_else(|| panic!("no {label:?} on {screen:?}"))
            .click();
        self.h.run_steps(2);
        self.settle();
    }

    fn has(&self, label: &str) -> bool {
        self.h.query_all_by_label_contains(label).next().is_some()
    }

    #[track_caller]
    fn see(&self, label: &str) {
        assert!(self.has(label), "{label:?} not on {:?}", self.app().screen);
    }

    fn type_password(&mut self, pw: &str) {
        self.h.get_by_role(Role::PasswordInput).scroll_to_me();
        self.h.run_steps(20);
        let f = self.h.get_by_role(Role::PasswordInput);
        f.focus();
        f.type_text(pw);
        self.h.run_steps(2);
    }

    /// Opens `name` from the test's files as if dropped on the window.
    fn open(&mut self, name: &str) {
        let p = self.files.join(name);
        self.h.state_mut().pending_open = Some(p);
        self.h.run_steps(2);
        self.settle();
    }

    /// Adds carol's key (recognized by the fake NCA) from Your keys.
    fn add_carol(&mut self) {
        self.open_key("ocsp/carol.p12");
        self.type_password("Qwerty12");
        self.click("Add key");
        assert_eq!(self.app().keys.len(), 1, "{:?}", self.app().add.problem);
    }

    fn open_key(&mut self, p: &str) {
        self.h.state_mut().pending_open = Some(fixture(p));
        self.h.run_steps(2);
        assert_eq!(self.app().screen, Screen::AddKey);
    }

    /// Signs the open document with carol's password.
    fn sign(&mut self, button: &str) {
        assert_eq!(self.app().screen, Screen::Sign);
        self.type_password("Qwerty12");
        self.click(button);
    }

    fn signed_path(&self) -> PathBuf {
        assert_eq!(
            self.app().screen,
            Screen::Signed,
            "{:?} {:?}",
            self.app().sign.as_ref().map(|s| (&s.problem, &s.password)),
            self.app().message
        );
        self.app().signed.as_ref().unwrap().path.clone().unwrap()
    }

    /// Saves a screenshot as `name`.png in $KZSIGNER_SCREENS, when it is set (CI keeps them
    /// for review).
    fn shot(&mut self, name: &str) {
        let Some(dir) = std::env::var_os("KZSIGNER_SCREENS") else {
            return;
        };
        std::fs::create_dir_all(&dir).unwrap();
        self.h.run_steps(2);
        let img = self.h.render().unwrap();
        img.save(Path::new(&dir).join(format!("{name}.png")))
            .unwrap();
    }

    fn verdict(&self) -> Verdict {
        self.app()
            .check
            .as_ref()
            .unwrap()
            .result
            .as_ref()
            .unwrap()
            .verdict
    }
}

/// Everything a person can press or type into must have a name a screen reader can say
/// (Narrator, NVDA, Orca read the same tree these tests query).
#[track_caller]
fn all_named(t: &Test, screen: &str) {
    use egui_kittest::kittest::{By, NodeT};
    let interactive = [
        Role::Button,
        Role::Link,
        Role::TextInput,
        Role::PasswordInput,
        Role::CheckBox,
        Role::RadioButton,
        Role::ComboBox,
    ];
    let unnamed: Vec<String> =
        t.h.query_all(By::new().predicate(move |n| {
            interactive.contains(&n.role())
                && !n.is_hidden()
                && n.label().is_none_or(|l| l.trim().is_empty())
        }))
        .map(|n| format!("{:?} at {:?}", n.accesskit_node().role(), n.rect()))
        .collect();
    assert!(
        unnamed.is_empty(),
        "{screen}: controls a screen reader can't name: {unnamed:#?}"
    );
}

#[test]
fn first_signature_from_home_without_a_key() {
    let mut t = start("first");
    assert_eq!(t.app().screen, Screen::Home);
    t.see("Add key");
    all_named(&t, "home, no key");
    t.shot("home-no-key");

    // Sign a document without a key: Add key first, then the document is chosen
    t.click("Sign a document");
    assert_eq!(t.app().screen, Screen::AddKey);
    t.see("To sign, first add your key.");
    all_named(&t, "add key");
    t.shot("add-key");
    t.dialogs.next(fixture("ocsp/carol.p12"));
    t.click("Choose the key file");
    t.see("carol.p12");

    // a Russian keyboard
    t.type_password("Йцукен12");
    t.click("Add key");
    t.see("That password doesn't open this key.");
    t.see("Is the keyboard in Russian or Kazakh?");
    all_named(&t, "add key, wrong password");
    t.shot("add-key-wrong-password");

    // the right one, then the document chooser opens by itself
    let doc = t.files.join("doc.txt");
    t.dialogs.next(&doc);
    t.h.state_mut().add.password = "Qwerty12".into();
    t.h.run_steps(2);
    t.click("Add key");
    assert_eq!(t.app().keys.len(), 1);
    assert_eq!(
        *t.dialogs.asked.lock().unwrap().last().unwrap(),
        Pick::Document
    );
    assert_eq!(t.app().screen, Screen::Sign);
    t.see("Sign this document?");
    t.see("You get one .cms file with the document and your signature inside.");
    t.see("Saved next to the original as doc.txt.cms.");
    t.see("ТЕСТОВ ДАНИЯР");
    all_named(&t, "sign");
    t.shot("sign");

    // Read it opens the document itself
    t.click("Read it");
    assert_eq!(t.dialogs.viewed.lock().unwrap().last().unwrap(), &doc);

    // Enter in the password box signs
    let pw = t.h.get_by_role(Role::PasswordInput);
    pw.focus();
    pw.type_text("Qwerty12");
    t.h.run_steps(2);
    t.h.key_press(egui::Key::Enter);
    t.h.run_steps(2);
    t.settle();
    // (doc.txt.cms is taken: the detached signature from the fixtures)
    let out = t.signed_path();
    assert_eq!(out, t.files.join("doc.txt (2).cms"));
    t.see("Signing time confirmed by NCA");
    t.see("Send the file, not a printout");
    all_named(&t, "signed");
    t.shot("signed");
    t.click("Show in folder");
    assert_eq!(t.dialogs.revealed.lock().unwrap().last().unwrap(), &out);
    let copy = t.files.join("copy.cms");
    t.dialogs.next(&copy);
    t.click("Save a copy elsewhere");
    assert_eq!(std::fs::read(&copy).unwrap(), std::fs::read(&out).unwrap());
    t.click("Done");
    assert_eq!(t.app().screen, Screen::Home);

    // the same document again: a new name, never over the first
    t.open("doc.txt");
    t.sign("Sign");
    assert_eq!(t.signed_path(), t.files.join("doc.txt (3).cms"));

    // and the result checks valid
    t.dialogs.next(&out);
    t.click("Done");
    t.click("Check a signature");
    assert_eq!(t.app().screen, Screen::Check);
    assert_eq!(t.verdict(), Verdict::Valid);
    t.see("The signature is valid");
    all_named(&t, "check, valid");
    t.shot("check-valid");
}

#[test]
fn keys_that_cant_sign_are_refused_before_anything_is_kept() {
    let mut t = start("refused");
    // a key from a CA not recognized in Kazakhstan
    t.open_key("keys/alice_rsa.p12");
    t.type_password("Qwerty12");
    t.click("Add key");
    assert!(
        matches!(
            t.app().add.problem,
            Some(kzsigner_desktop::gui::home::AddProblem::CantSign {
                reason: CantSign::NotRecognized,
                ..
            })
        ),
        "{:?}",
        t.app().add.problem
    );
    t.see("This key isn't recognized");
    t.see("Open egov.kz");
    all_named(&t, "add key, not recognized");
    t.shot("add-key-not-recognized");
    // GOST 2004
    t.open_key("keys/alice_gost2004.p12");
    t.type_password("Qwerty12");
    t.click("Add key");
    assert!(
        matches!(
            t.app().add.problem,
            Some(kzsigner_desktop::gui::home::AddProblem::CantSign { .. })
        ),
        "{:?}",
        t.app().add.problem
    );
    // not a key at all, dropped on Add key
    t.open("doc.txt");
    assert_eq!(t.app().screen, Screen::AddKey);
    t.type_password("Qwerty12");
    t.click("Add key");
    t.see("This file isn't a signature key.");
    assert!(t.app().keys.is_empty());
    // added once, then again
    t.add_carol();
    assert_eq!(t.app().screen, Screen::Keys);
    t.open_key("ocsp/carol.p12");
    t.type_password("Qwerty12");
    t.click("Add key");
    t.see("This key is already on this computer.");
    assert_eq!(t.app().keys.len(), 1);
}

#[test]
fn every_kind_of_document_is_signed_as_the_phone_does() {
    let mut t = start("kinds");
    t.add_carol();

    // XML: inside
    t.open("act.xml");
    t.see("Your signature goes inside this XML file.");
    t.sign("Sign");
    assert_eq!(t.signed_path(), t.files.join("act-signed.xml"));
    t.click("Done");

    // a signed PDF: "Add your signature?", inside it
    t.open("contract-signed.pdf");
    t.see("Add your signature?");
    t.see("Already signed by ТЕСТОВ ДАНИЯР");
    all_named(&t, "sign, add signature");
    t.shot("sign-add-signature");
    t.sign("Add my signature");
    let pdf = t.signed_path();
    assert!(pdf.starts_with(&t.files) && pdf.extension().unwrap() == "pdf");
    t.see("The boxes on the last page only show who signed");
    t.click("Done");

    // a .cms with its document: the signature joins, the original stays as it was
    let before = std::fs::read(t.files.join("act.txt.cms")).unwrap();
    t.open("act.txt.cms");
    t.see("Add your signature?");
    t.see("Your signature joins");
    t.click("Read it");
    let viewed = t.dialogs.viewed.lock().unwrap().last().unwrap().clone();
    assert!(
        viewed
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("act.txt")
    );
    t.sign("Add my signature");
    assert_eq!(t.signed_path(), t.files.join("act.txt (2).cms"));
    assert_eq!(std::fs::read(t.files.join("act.txt.cms")).unwrap(), before);
    t.click("Done");

    // a .cms with only signatures can't be signed: it goes to Check, which asks for the document
    t.open("doc.txt.cms");
    assert_eq!(t.app().screen, Screen::Check);
    assert_eq!(t.verdict(), Verdict::NeedsDocument);
    t.see("Choose the signed document");
    all_named(&t, "check, needs document");
    t.shot("check-needs-document");
    t.dialogs.next(t.files.join("doc.txt"));
    t.click("Choose the document");
    assert_ne!(t.verdict(), Verdict::NeedsDocument);
    assert!(t.app().check.as_ref().unwrap().original.is_some());
}

#[test]
fn nca_down_then_try_again_and_a_revoked_key() {
    let mut t = start("nca");
    t.add_carol();
    t.fake.down.store(true, SeqCst);
    t.open("doc.txt");
    t.sign("Sign");
    assert_eq!(t.app().screen, Screen::Sign);
    t.see("Can't reach NCA right now");
    t.see("Nothing was signed.");
    all_named(&t, "sign, NCA down");
    t.shot("sign-nca-down");
    assert!(!t.files.join("doc.txt (2).cms").exists());
    // back up: Try again signs (the password is still there)
    t.fake.down.store(false, SeqCst);
    t.click("Try again");
    assert_eq!(t.signed_path(), t.files.join("doc.txt (2).cms"));
    t.click("Done");

    // a wrong password
    t.open("act.xml");
    t.type_password("wrong");
    t.click("Sign");
    t.see("That password doesn't open this key.");

    // revoked: refused, nothing signed
    t.fake.revoked.store(true, SeqCst);
    t.h.state_mut().sign.as_mut().unwrap().password = "Qwerty12".into();
    t.h.run_steps(2);
    t.click("Sign");
    t.see("Your key was revoked");
    assert!(!t.files.join("act-signed.xml").exists());
    all_named(&t, "sign, revoked");
    t.shot("sign-revoked");
}

#[test]
fn checking_says_what_the_phone_says() {
    let mut t = start("check");
    // not signed: offers to sign it, which needs a key first
    t.dialogs.next(t.files.join("doc.txt"));
    t.click("Check a signature");
    assert_eq!(t.verdict(), Verdict::NotSigned);
    t.see("This file isn't signed");
    all_named(&t, "check, not signed");
    t.shot("check-not-signed");
    t.click("Sign it myself");
    assert_eq!(t.app().screen, Screen::AddKey);
    t.see("To sign doc.txt, first add your key.");
    t.add_carol();
    // straight back to the document
    assert_eq!(t.app().screen, Screen::Sign);
    t.click("Back");

    // a signed file dropped on Home opens Sign, as "Add your signature?"
    t.open("act.txt.cms");
    assert_eq!(t.app().screen, Screen::Sign);
    t.click("Back");

    // valid, with NCA's answer kept in the signature
    t.dialogs.next(t.files.join("act.txt.cms"));
    t.click("Check a signature");
    assert_eq!(
        t.verdict(),
        Verdict::Valid,
        "{:?}",
        t.app().check.as_ref().unwrap().result
    );
    t.see("The signature is valid");
    t.see("ТЕСТОВ ДАНИЯР");
    t.click("Details");
    t.see("Signature details");
    t.see("CAdES, document and signatures inside the .cms");
    all_named(&t, "check, details");
    t.shot("check-details");
    t.click("Copy details");
    t.click("Open the document");
    let viewed = t.dialogs.viewed.lock().unwrap().last().cloned();
    let viewed = viewed.unwrap_or_else(|| panic!("not viewed: {:?}", t.app().message));
    assert_eq!(
        std::fs::read(&viewed).unwrap(),
        kzsigner_ffi::cms_content(std::fs::read(t.files.join("act.txt.cms")).unwrap()).unwrap()
    );

    // changed after signing
    t.dialogs.next(t.files.join("act-changed.txt.cms"));
    t.click("Check another file");
    assert_eq!(t.verdict(), Verdict::Invalid);
    t.see("Do not trust this document");
    t.see("Changed after it was signed");
    all_named(&t, "check, changed");
    t.shot("check-changed");

    // a key not recognized in Kazakhstan
    t.dialogs.next(t.files.join("rsa.txt.cms"));
    t.click("Check another file");
    assert_eq!(t.verdict(), Verdict::Invalid);
    t.see("This key isn't recognized in Kazakhstan");

    // revoked now: NCA's answer kept in the file still counts
    t.fake.revoked.store(true, SeqCst);
    t.dialogs.next(t.files.join("act.txt.cms"));
    t.click("Check another file");
    let v = t.verdict();
    assert!(v == Verdict::Valid || v == Verdict::Invalid, "{v:?}");
}

#[test]
fn your_keys_language_and_about() {
    let mut t = start("keys");
    t.add_carol();
    assert_eq!(t.app().screen, Screen::Keys);
    t.see("Opens with its password");
    all_named(&t, "your keys");
    t.shot("your-keys");

    // remove: asked first
    t.click("Remove from this computer");
    let name = t.app().keys[0].name.clone();
    t.see(&format!("Remove {name}'s key from this computer?"));
    all_named(&t, "remove");
    t.shot("remove");
    t.click("Keep it");
    assert_eq!(t.app().keys.len(), 1);

    // the language, remembered
    t.click("Русский");
    t.see("Ваши ключи");
    assert_eq!(kzsigner::i18n::saved(), Some(kzsigner::i18n::Lang::Ru));
    t.click("Қазақша");
    t.see("Сіздің кілттеріңіз");
    all_named(&t, "your keys, Kazakh");
    t.shot("your-keys-kazakh");
    t.click("Компьютердегідей");
    assert_eq!(kzsigner::i18n::saved(), None);
    kzsigner::i18n::set(kzsigner::i18n::Lang::En);
    t.h.run_steps(2);

    t.click("About kzsigner · version, license, privacy");
    assert_eq!(t.app().screen, Screen::About);
    t.see("Your documents stay on your computer");
    all_named(&t, "about");
    t.shot("about");
    t.h.key_press(egui::Key::Escape);
    t.h.run_steps(2);
    assert_eq!(t.app().screen, Screen::Keys);

    t.click("Remove from this computer");
    t.click("Remove");
    assert!(t.app().keys.is_empty());
    // the key is gone for a new window too
    t.h.key_press(egui::Key::Escape);
    t.h.run_steps(2);
    assert_eq!(t.app().screen, Screen::Home);
    t.see("Add key");
}

/// Nothing sticks out of the window's right edge (no sideways scrolling).
#[track_caller]
fn fits(t: &Test, screen: &str) {
    use egui_kittest::kittest::By;
    let right = t.h.ctx.content_rect().right() + 1.0;
    let wide: Vec<String> =
        t.h.query_all(By::new().predicate(move |n| n.label().is_some()))
            .filter(|n| n.rect().right() > right)
            .map(|n| format!("{:?}", n))
            .collect();
    assert!(
        wide.is_empty(),
        "{screen}: wider than the window: {wide:#?}"
    );
}

#[test]
fn a_narrow_window_and_large_text() {
    // the smallest window
    let mut t = start_sized("narrow", [480.0, 760.0]);
    t.add_carol();
    fits(&t, "your keys, narrow");
    t.open("contract-signed.pdf");
    all_named(&t, "sign, narrow");
    t.shot("sign-narrow");
    fits(&t, "sign, narrow");
    // text at 200 %: the same window on a screen twice as dense
    t.h.set_size(egui::vec2(960.0, 1520.0));
    t.h.set_pixels_per_point(2.0);
    t.h.run_steps(2);
    all_named(&t, "sign, 200 %");
    t.shot("sign-200-pct");
    fits(&t, "sign, 200 %");
    t.sign("Add my signature");
    t.signed_path();
    fits(&t, "signed, 200 %");
    t.dialogs.next(t.files.join("act.txt.cms"));
    t.click("Done");
    t.click("Check a signature");
    t.click("Details");
    fits(&t, "check, 200 %");
}
