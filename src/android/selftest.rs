//! The emulator test copy's test of the real screens (built with the `selftest` feature, see
//! scripts/apk.sh and scripts/android-selftest.sh). It drives the same window the phone shows,
//! through egui's test harness, on top of the real security chip code (AndroidGuard, KeyGuard
//! and the system's PIN prompt), with kzsigner's throwaway test key and CAs.
//!
//! It talks to the CI script through the log (tag KZSELFTEST): `NEED <n> <what>` asks the
//! script to do something on the device (`pin`: type the PIN into the prompt; `cancel`: close
//! the prompt; `nolock` / `lock`: remove / set the screen PIN), `DONE <n>` says it happened,
//! and the run ends with `UI PASS` or `UI FAIL <why>`.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

use super::{AndroidGuard, info, java};
use crate::Engine;
use crate::cert::Cert;
use crate::gui::{App, Dialogs, Screen};
use crate::vault::{Guard, Store};

const KEY: &[u8] = include_bytes!("../../tests/fixtures/kalkan/alice_gost2015.p12");
const CAS: [&[u8]; 3] = [
    include_bytes!("../../tests/fixtures/kalkan/ca_gost2015.cer"),
    include_bytes!("../../tests/fixtures/kalkan/ca_gost2004.cer"),
    include_bytes!("../../tests/fixtures/kalkan/ca_rsa.cer"),
];
/// On a phone a file field is one button that opens Android's file chooser.
const CHOOSE: &str = "Choose a file…";

fn log(s: &str) {
    for l in s.lines() {
        java(&format!("log\n{l}"));
    }
}

/// Waits for the test copy to be asked for its test (`--ez uitest true`), and runs it.
pub fn start() {
    // release builds abort on a panic: say why first, for the CI script
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |p| {
        log(&format!("UI FAIL panic: {p}"));
        default(p);
    }));
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            if java("selftest").as_deref() == Some("ui") {
                let r = std::panic::catch_unwind(run)
                    .unwrap_or_else(|p| Err(format!("panic: {:?}", p.downcast_ref::<String>())));
                match r {
                    Ok(()) => log("UI PASS"),
                    Err(e) => log(&format!("UI FAIL {e}")),
                }
            }
        }
    });
}

/// File dialogs that answer from a queue.
#[derive(Clone, Default)]
struct Scripted(Arc<Mutex<VecDeque<PathBuf>>>);

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
    fn view(&mut self, _: &Path) -> Result<(), String> {
        Ok(())
    }
}

macro_rules! check {
    ($c:expr, $($m:tt)*) => {
        if !$c {
            return Err(format!($($m)*));
        }
    };
}

static NEED: AtomicU32 = AtomicU32::new(0);

/// Asks the CI script for something; `done` is called when the work it waits for finished.
fn need(what: &str) -> u32 {
    let n = NEED.fetch_add(1, Ordering::SeqCst) + 1;
    log(&format!("NEED {n} {what}"));
    n
}

fn done(n: u32) {
    log(&format!("DONE {n}"));
}

type H = Harness<'static, App>;

/// Runs the window until its background work is done (a prompt may be up for a while).
fn settle(h: &mut H) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(120) {
        h.run_steps(2);
        if !h.state().busy() {
            h.run_steps(2);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err("background work did not finish in 2 minutes".into())
}

/// The emulator's Keystore is software only, so the app would keep keys behind their password
/// there. The test copy says it is hardware, so the screen lock path (the one phones take)
/// runs, still on the real Keystore and the real system prompt.
struct EmulatorChip;

impl Guard for EmulatorChip {
    fn capabilities(&self) -> crate::vault::Capabilities {
        let c = AndroidGuard.capabilities();
        crate::vault::Capabilities {
            hardware: true,
            ..c
        }
    }
    fn create(
        &self,
        name: &str,
        auth: crate::vault::ChipAuth,
    ) -> Result<crate::vault::Security, crate::vault::GuardError> {
        AndroidGuard.create(name, auth)
    }
    fn seal(
        &self,
        name: &str,
        plain: &[u8],
        aad: &[u8],
        prompt: &crate::vault::Prompt,
    ) -> Result<Vec<u8>, crate::vault::GuardError> {
        AndroidGuard.seal(name, plain, aad, prompt)
    }
    fn open(
        &self,
        name: &str,
        sealed: &[u8],
        aad: &[u8],
        prompt: &crate::vault::Prompt,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, crate::vault::GuardError> {
        AndroidGuard.open(name, sealed, aad, prompt)
    }
    fn delete(&self, name: &str) {
        AndroidGuard.delete(name)
    }
}

fn window(store_file: &Path, dialogs: &Scripted) -> Result<H, String> {
    let guard: Box<dyn Guard> = Box::new(EmulatorChip);
    let store = Store::open(store_file, guard).map_err(|e| e.to_string())?;
    let cas = CAS.iter().filter_map(|d| Cert::parse_any(d).ok()).collect();
    let mut app = App::new(Engine::new(cas), Box::new(dialogs.clone())).with_key_store(store);
    (app.sign.timestamp, app.ocsp) = (false, false);
    let mut h = Harness::builder()
        .with_size([412.0, 2400.0])
        .build_ui_state(|ui, app: &mut App| app.ui(ui), app);
    h.run();
    Ok(h)
}

/// From the start screen: the Sign screen with `doc` chosen.
fn sign_screen(h: &mut H, dialogs: &Scripted, doc: &Path) -> Result<(), String> {
    h.get_all_by_label("Sign a document")
        .next()
        .ok_or("no Sign a document")?
        .click();
    h.run();
    dialogs.next(doc.to_path_buf());
    h.get_all_by_label(CHOOSE)
        .next()
        .ok_or("no Choose a file… for the document")?
        .click();
    settle(h)
}

/// Opens the key file with its password; the store keeps it, asking `keep` of the script.
fn open_key_file(
    h: &mut H,
    dialogs: &Scripted,
    key: &Path,
    keep: Option<&str>,
) -> Result<(), String> {
    dialogs.next(key.to_path_buf());
    h.get_all_by_label(CHOOSE)
        .next()
        .ok_or("no Choose a file… for the key")?
        .click();
    settle(h)?;
    let pw = h.get_by_role(egui::accesskit::Role::PasswordInput);
    pw.focus();
    pw.type_text("Qwerty12");
    h.run();
    let n = keep.map(need);
    h.key_press(egui::Key::Enter);
    settle(h)?;
    if let Some(n) = n {
        done(n);
    }
    Ok(())
}

/// Presses Sign; the signed file is saved to `out` (none when the signing is to stop early).
fn sign(
    h: &mut H,
    dialogs: &Scripted,
    out: Option<&Path>,
    ask: Option<&str>,
) -> Result<(), String> {
    if let Some(out) = out {
        dialogs.next(out.to_path_buf());
    }
    let n = ask.map(need);
    h.get_by_label("Sign").click();
    settle(h)?;
    if let Some(n) = n {
        done(n);
    }
    Ok(())
}

fn remove_kept_key(h: &mut H) -> Result<(), String> {
    h.get_by_label("Remove this key from the phone…").click();
    h.run();
    h.get_by_label("Remove").click();
    settle(h)?;
    check!(h.state().stored_keys().is_empty(), "the key is still kept");
    check!(
        h.query_all_by_label(CHOOSE).next().is_some(),
        "no key file field after removing"
    );
    Ok(())
}

/// Waits until the device's screen lock is as `want`.
fn wait_lock(want: bool) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        if EmulatorChip.capabilities().screen_lock == want {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!("screen lock did not become {want}"))
}

fn run() -> Result<(), String> {
    crate::i18n::set(crate::i18n::Lang::En);
    let dir = info().cache.join("uitest");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let doc = dir.join("doc.txt");
    let key = dir.join("alice_gost2015.p12");
    std::fs::write(&doc, "kzsigner emulator test\n").map_err(|e| e.to_string())?;
    std::fs::write(&key, KEY).map_err(|e| e.to_string())?;
    let store_file = dir.join("keys.kzs");
    let dialogs = Scripted::default();
    wait_lock(true)?;
    let caps = AndroidGuard.capabilities();
    log(&format!("UI chip problem {:?}", AndroidGuard.problem()));
    log(&format!("UI caps {caps:?}"));

    // 1. first time: the key file and password; kept behind the screen lock, with one prompt
    log("UI step keep");
    let mut h = window(&store_file, &dialogs)?;
    sign_screen(&mut h, &dialogs, &doc)?;
    open_key_file(&mut h, &dialogs, &key, Some("pin"))?;
    check!(
        h.query_by_label_contains("Kept on this phone. Next time, sign with your fingerprint")
            .is_some(),
        "not kept behind the screen lock: {:?}",
        h.state().message
    );
    check!(h.state().stored_keys().len() == 1, "no kept key");
    // this signing goes on with the file: no second prompt
    sign(&mut h, &dialogs, Some(&dir.join("1.cms")), None)?;
    check!(
        h.state().screen == Screen::Signed,
        "signing with the file: {:?}",
        h.state().message
    );
    drop(h);

    // 2. next start: the kept key, no password; a closed prompt does nothing; then one PIN
    log("UI step kept key");
    let mut h = window(&store_file, &dialogs)?;
    sign_screen(&mut h, &dialogs, &doc)?;
    check!(
        h.query_by_role(egui::accesskit::Role::PasswordInput)
            .is_none(),
        "a password is asked for a kept key"
    );
    sign(&mut h, &dialogs, None, Some("cancel"))?;
    check!(
        h.state().screen == Screen::Sign && h.state().message.is_none(),
        "after a closed prompt: {:?} {:?}",
        h.state().screen,
        h.state().message
    );
    let out = dir.join("2.cms");
    sign(&mut h, &dialogs, Some(&out), Some("pin"))?;
    check!(
        h.state().screen == Screen::Signed,
        "signing with the kept key: {:?}",
        h.state().message
    );
    check!(out.exists(), "no signed file");

    // 3. remove it
    log("UI step remove");
    h.get_by_label("Back").click();
    h.run();
    h.get_all_by_label("Sign a document")
        .next()
        .ok_or("no Sign a document")?
        .click();
    h.run();
    remove_kept_key(&mut h)?;
    drop(h);

    // 4. no screen lock: kept behind the key's password, which is asked from then on
    log("UI step no screen lock");
    let n = need("nolock");
    wait_lock(false)?;
    done(n);
    let _ = std::fs::remove_file(&store_file);
    let mut h = window(&store_file, &dialogs)?;
    sign_screen(&mut h, &dialogs, &doc)?;
    open_key_file(&mut h, &dialogs, &key, None)?;
    check!(
        h.query_by_label_contains("Next time only the password is needed")
            .is_some(),
        "not kept behind the password: {:?}",
        h.state().message
    );
    drop(h);
    let mut h = window(&store_file, &dialogs)?;
    sign_screen(&mut h, &dialogs, &doc)?;
    let pw = h.get_by_role(egui::accesskit::Role::PasswordInput);
    pw.focus();
    pw.type_text("Qwerty12");
    h.run();
    sign(&mut h, &dialogs, Some(&dir.join("3.cms")), None)?;
    check!(
        h.state().screen == Screen::Signed,
        "signing with the password-only key: {:?}",
        h.state().message
    );
    h.get_by_label("Back").click();
    h.run();
    h.get_all_by_label("Sign a document")
        .next()
        .ok_or("no Sign a document")?
        .click();
    h.run();
    remove_kept_key(&mut h)?;
    drop(h);

    let n = need("lock");
    wait_lock(true)?;
    done(n);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
