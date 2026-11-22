//! The Android app: the same window as on the desktop, started by Android's NativeActivity.
//! Files come and go through Android's own file chooser and "Save as" (the Storage Access
//! Framework), which only the Java side can reach: `android/java/kz/kzsigner/MainActivity.java`.
//! Rust talks to it through one method, `String call(String request)`.
//!
//! Requests: `pick` (the chooser), `save\n<name>\n<path>` (copy a written file to where the
//! user chooses), `share\n<path>`, `view\n<path>` (open in another app), `keyboard\n1|0`, `info` (files dir, cache dir, language),
//! `poll` (the next event: `picked\n<path>`, `cancelled`, `open\n<path>`, `saved\n<name>`,
//! `error\n<text>`, or null).
//!
//! Keys kept in the app go through a second method, `byte[] guard(String request, byte[] a,
//! byte[] b)`, to the phone's security chip (`KeyGuard.java`); see [`AndroidGuard`].

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use eframe::egui;
use jni::objects::{JObject, JString, JValue};
use jni::{jni_sig, jni_str};

use crate::Engine;
use crate::gui::{App, DialogEvent, Dialogs};
use crate::i18n::{self, tr, trf};
use crate::vault::{Capabilities, ChipAuth, Guard, GuardError, Prompt, Security, Store};
use zeroize::Zeroizing;

pub use winit::platform::android::activity::AndroidApp;

/// The activity (a global reference owned by android-activity, valid while the app runs).
/// ndk_context only has the Application, which is not where `call` is.
static ACTIVITY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// One request to the Java side; its answer, None for null or when the call failed.
fn java(request: &str) -> Option<String> {
    let ctx = ndk_context::android_context();
    let activity = ACTIVITY.load(std::sync::atomic::Ordering::Acquire);
    if activity == 0 {
        return None;
    }
    // Safety: android-activity filled in the context with the process's VM and the activity,
    // a global reference that stays valid while the app runs
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) };
    let r = vm.attach_current_thread(|env| -> jni::errors::Result<Option<String>> {
        // a global reference owned by android-activity; JObject never deletes what it wraps
        let activity = unsafe { JObject::from_raw(env, activity as jni::sys::jobject) };
        let arg = env.new_string(request)?;
        let out = env
            .call_method(
                &activity,
                jni_str!("call"),
                jni_sig!("(Ljava/lang/String;)Ljava/lang/String;"),
                &[JValue::Object(&arg)],
            )?
            .l()?;
        if out.is_null() {
            return Ok(None);
        }
        let s = env.cast_local::<JString>(out)?;
        Ok(Some(s.try_to_string(env)?))
    });
    match r {
        Ok(v) => v,
        Err(e) => {
            eprintln!("kzsigner: {request:?} failed: {e}");
            None
        }
    }
}

/// A request to the security chip (`guard` in MainActivity, run by KeyGuard.java) with two
/// byte arrays. The answer's first byte says how it went: 0 done (the rest is the data),
/// 1 cancelled, 2 the key is gone for good, 3 failed (the rest is the reason).
fn guard_call(request: &str, a: &[u8], b: &[u8]) -> Result<Zeroizing<Vec<u8>>, GuardError> {
    let ctx = ndk_context::android_context();
    let activity = ACTIVITY.load(std::sync::atomic::Ordering::Acquire);
    if activity == 0 {
        return Err(GuardError::Failed("no activity".into()));
    }
    // Safety: as in `java`
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) };
    let r = vm.attach_current_thread(|env| -> jni::errors::Result<Vec<u8>> {
        let activity = unsafe { JObject::from_raw(env, activity as jni::sys::jobject) };
        let req = env.new_string(request)?;
        let a = env.byte_array_from_slice(a)?;
        let b = env.byte_array_from_slice(b)?;
        let out = env
            .call_method(
                &activity,
                jni_str!("guard"),
                jni_sig!("(Ljava/lang/String;[B[B)[B"),
                &[JValue::Object(&req), JValue::Object(&a), JValue::Object(&b)],
            )?
            .l()?;
        if out.is_null() {
            return Ok(vec![3]);
        }
        let out = env.cast_local::<jni::objects::JByteArray>(out)?;
        env.convert_byte_array(&out)
    });
    let out = Zeroizing::new(r.map_err(|e| GuardError::Failed(e.to_string()))?);
    match out.first() {
        Some(0) => Ok(Zeroizing::new(out[1..].to_vec())),
        Some(1) => Err(GuardError::Cancelled),
        Some(2) => Err(GuardError::KeyReset),
        _ => Err(GuardError::Failed(
            String::from_utf8_lossy(out.get(1..).unwrap_or_default()).into_owned(),
        )),
    }
}

/// Android Keystore (StrongBox or the processor's protected area) through KeyGuard.java.
struct AndroidGuard;

/// The prompt's texts travel as lines of the request.
fn prompt_lines(p: &Prompt) -> String {
    format!(
        "{}\n{}\n{}",
        one_line(&p.title),
        one_line(&p.subtitle),
        one_line(&p.detail)
    )
}

impl Guard for AndroidGuard {
    fn capabilities(&self) -> Capabilities {
        let caps = guard_call("caps", &[], &[]).unwrap_or_default();
        let s = String::from_utf8_lossy(&caps);
        let mut f = s.split(',').map(|v| v == "1");
        Capabilities {
            screen_lock: f.next().unwrap_or(false),
            biometric: f.next().unwrap_or(false),
            hardware: f.next().unwrap_or(false),
        }
    }

    fn create(&self, name: &str, auth: ChipAuth) -> Result<Security, GuardError> {
        let auth = match auth {
            ChipAuth::None => 0,
            ChipAuth::BiometricOrPin => 1,
            ChipAuth::BiometricOnly => 2,
        };
        let out = guard_call(&format!("create\n{}\n{auth}", one_line(name)), &[], &[])?;
        Ok(match out.first() {
            Some(1) => Security::Chip,
            Some(2) => Security::Protected,
            _ => Security::Software,
        })
    }

    fn seal(
        &self,
        name: &str,
        plain: &[u8],
        aad: &[u8],
        prompt: &Prompt,
    ) -> Result<Vec<u8>, GuardError> {
        let req = format!("seal\n{}\n{}", one_line(name), prompt_lines(prompt));
        Ok(guard_call(&req, plain, aad)?.to_vec())
    }

    fn open(
        &self,
        name: &str,
        sealed: &[u8],
        aad: &[u8],
        prompt: &Prompt,
    ) -> Result<Zeroizing<Vec<u8>>, GuardError> {
        let req = format!("open\n{}\n{}", one_line(name), prompt_lines(prompt));
        guard_call(&req, sealed, aad)
    }

    fn delete(&self, name: &str) {
        let _ = guard_call(&format!("delete\n{}", one_line(name)), &[], &[]);
    }
}

/// The app's private folders (files, cache) and the phone's language, asked once.
struct Info {
    files: PathBuf,
    cache: PathBuf,
}

static INFO: OnceLock<Info> = OnceLock::new();

fn info() -> &'static Info {
    INFO.get_or_init(|| {
        let s = java("info").unwrap_or_default();
        let mut l = s.lines();
        let files = l.next().unwrap_or("/data/local/tmp").to_string();
        let cache = l.next().unwrap_or(&files).to_string();
        let lang = l.next().unwrap_or("");
        i18n::set_platform(lang, PathBuf::from(&files));
        Info {
            files: PathBuf::from(files),
            cache: PathBuf::from(cache),
        }
    })
}

/// Android's file chooser and "Save as", through the activity.
#[derive(Default)]
struct AndroidDialogs {
    /// The file fields a chooser was opened for (the answer names its field).
    fields: Vec<&'static str>,
    /// When the activity was last asked.
    last_poll: Option<std::time::Instant>,
}

/// Names and paths travel in newline-separated requests: keep them on one line.
fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], "_")
}

impl Dialogs for AndroidDialogs {
    fn open(&mut self, field: &'static str, _start: Option<&Path>) -> Option<PathBuf> {
        if !self.fields.contains(&field) {
            self.fields.push(field);
        }
        java(&format!("pick\n{field}"));
        None
    }

    fn save(&mut self, suggested: &Path) -> Option<PathBuf> {
        // written to the cache first; Android's "Save as" then copies it where the user wants
        let name = suggested
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "kzsigner-file".into());
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = info().cache.join("out").join(n.to_string());
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join(name))
    }

    fn saved(&mut self, path: &Path) {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        java(&format!(
            "save\n{}\n{}",
            one_line(&name),
            one_line(&path.display().to_string())
        ));
    }

    fn view_dir(&self) -> PathBuf {
        info().cache.join("view")
    }

    fn view(&mut self, path: &Path) -> Result<(), String> {
        // an app that can't be found is reported later, through poll
        java(&format!("view\n{}", one_line(&path.display().to_string())));
        Ok(())
    }

    fn reveal(&mut self, path: &Path) {
        java(&format!("share\n{}", one_line(&path.display().to_string())));
    }

    fn keyboard(&mut self, show: bool) {
        java(if show { "keyboard\n1" } else { "keyboard\n0" });
    }

    fn poll(&mut self) -> Option<DialogEvent> {
        // the activity is asked at most every 100 ms
        let now = std::time::Instant::now();
        if self
            .last_poll
            .is_some_and(|t| now.duration_since(t).as_millis() < 100)
        {
            return None;
        }
        self.last_poll = Some(now);
        let s = java("poll")?;
        self.last_poll = None;
        let (kind, rest) = s.split_once('\n').unwrap_or((&s, ""));
        match kind {
            "picked" => {
                let (name, path) = rest.split_once('\n')?;
                let field = *self.fields.iter().find(|f| **f == name)?;
                Some(DialogEvent::Picked(field, PathBuf::from(path)))
            }
            // nothing to say; poll again for anything queued behind it
            "cancelled" => self.poll(),
            "notsaved" => Some(DialogEvent::Message(
                tr("Not saved. Use Save to the phone or Share on this screen.").into(),
                false,
            )),
            "open" => Some(DialogEvent::Open(PathBuf::from(rest))),
            "noviewer" => Some(DialogEvent::Message(
                tr("No app on this phone can open this kind of file.").into(),
                true,
            )),
            "saved" => Some(DialogEvent::Message(trf("Saved: {}", &[&rest]), false)),
            "error" => Some(DialogEvent::Message(
                trf("Could not save: {}", &[&rest]),
                true,
            )),
            _ => None,
        }
    }
}

/// Starts the app; called from `android_main` in the `kzsigner-android` library.
pub fn main(app: AndroidApp) {
    ACTIVITY.store(
        app.activity_as_ptr() as usize,
        std::sync::atomic::Ordering::Release,
    );
    info();
    let options = eframe::NativeOptions {
        android_app: Some(app),
        ..Default::default()
    };
    let r = eframe::run_native(
        "kzsigner",
        options,
        Box::new(|cc| {
            i18n::set(i18n::detect());
            // bigger text and touch targets than on the desktop
            cc.egui_ctx.all_styles_mut(|s| {
                s.spacing.interact_size.y = 40.0;
                s.spacing.button_padding = egui::vec2(12.0, 8.0);
            });
            let mut app = App::new(Engine::new(vec![]), Box::<AndroidDialogs>::default());
            // keys kept in the app: a file in the app's private folder, locked by the chip
            let guard: Box<dyn Guard> = Box::new(AndroidGuard);
            match Store::open(&info().files.join("keys.kzs"), guard) {
                Ok(store) => app = app.with_key_store(store),
                Err(e) => eprintln!("kzsigner: key store: {e}"),
            }
            Ok(Box::new(AndroidWindow(app, std::time::Instant::now())))
        }),
    );
    if let Err(e) = r {
        eprintln!("kzsigner: {}", trf("Could not open the window: {}", &[&e]));
    }
}

/// The desktop window's screens. Chosen, saved and shared files come back from the activity
/// while the app is in the background; it is asked for them for a few seconds after the app
/// comes back or is touched, not all the time.
struct AndroidWindow(App, std::time::Instant);

impl eframe::App for AndroidWindow {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if ctx.input(|i| !i.events.is_empty() || i.pointer.any_down()) {
            self.1 = std::time::Instant::now();
        }
        egui::CentralPanel::default().show(ui, |ui| {
            // clear of the status bar
            ui.add_space(24.0);
            self.0.ui(ui);
        });
        if self.1.elapsed() < std::time::Duration::from_secs(5) || self.0.busy() {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
    }
}
