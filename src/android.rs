//! The Android app: the same window as on the desktop, started by Android's NativeActivity.
//! Files come and go through Android's own file chooser and "Save as" (the Storage Access
//! Framework), which only the Java side can reach: `android/java/kz/kzsigner/MainActivity.java`.
//! Rust talks to it through one method, `String call(String request)`.
//!
//! Requests: `pick` (the chooser), `save\n<name>\n<path>` (copy a written file to where the
//! user chooses), `share\n<path>`, `keyboard\n1|0`, `info` (files dir, cache dir, language),
//! `poll` (the next event: `picked\n<path>`, `cancelled`, `open\n<path>`, `saved\n<name>`,
//! `error\n<text>`, or null).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use eframe::egui;
use jni::objects::{JObject, JString, JValue};
use jni::{jni_sig, jni_str};

use crate::Engine;
use crate::gui::{App, DialogEvent, Dialogs};
use crate::i18n::{self, trf};

pub use winit::platform::android::activity::AndroidApp;

/// One request to the Java side; its answer, None for null or when the call failed.
fn java(request: &str) -> Option<String> {
    let ctx = ndk_context::android_context();
    // Safety: android-activity filled in the context with the process's VM and the activity,
    // a global reference that stays valid while the app runs
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) };
    let r = vm.attach_current_thread(|env| -> jni::errors::Result<Option<String>> {
        // a global reference owned by android-activity; JObject never deletes what it wraps
        let activity = unsafe { JObject::from_raw(env, ctx.context().cast()) };
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

/// The app's private folders (files, cache) and the phone's language, asked once.
struct Info {
    cache: PathBuf,
}

static INFO: OnceLock<Info> = OnceLock::new();

fn info() -> &'static Info {
    INFO.get_or_init(|| {
        let s = java("info").unwrap_or_default();
        let mut l = s.lines();
        let files = l.next().unwrap_or("/data/local/tmp").to_string();
        let cache = l.next().unwrap_or(&files).to_string();
        let lang = l.next().unwrap_or("").to_string();
        // i18n keeps the chosen language under XDG_CONFIG_HOME; LANG gives the phone's own
        // Safety: set once, before any other thread reads the environment
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &files);
            std::env::set_var("HOME", &files);
            if !lang.is_empty() {
                std::env::set_var("LANG", &lang);
            }
        }
        Info {
            cache: PathBuf::from(cache),
        }
    })
}

/// Android's file chooser and "Save as", through the activity.
#[derive(Default)]
struct AndroidDialogs {
    /// The file field waiting for the chooser.
    waiting: Option<&'static str>,
    /// Polls left before giving up on the activity (it answers within a frame or two).
    last_poll: Option<std::time::Instant>,
}

impl Dialogs for AndroidDialogs {
    fn open(&mut self, field: &'static str, _start: Option<&Path>) -> Option<PathBuf> {
        self.waiting = Some(field);
        java("pick");
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
        java(&format!("save\n{name}\n{}", path.display()));
    }

    fn reveal(&mut self, path: &Path) {
        java(&format!("share\n{}", path.display()));
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
                let field = self.waiting.take()?;
                Some(DialogEvent::Picked(field, PathBuf::from(rest)))
            }
            "cancelled" => {
                self.waiting = None;
                // nothing to say; poll again for anything queued behind it
                self.poll()
            }
            "open" => Some(DialogEvent::Open(PathBuf::from(rest))),
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
    let options = eframe::NativeOptions {
        android_app: Some(app),
        ..Default::default()
    };
    let r = eframe::run_native(
        "kzsigner",
        options,
        Box::new(|cc| {
            info();
            i18n::set(i18n::detect());
            // bigger text and touch targets than on the desktop
            cc.egui_ctx.all_styles_mut(|s| {
                s.spacing.interact_size.y = 40.0;
                s.spacing.button_padding = egui::vec2(12.0, 8.0);
            });
            let app = App::new(Engine::new(vec![]), Box::<AndroidDialogs>::default());
            Ok(Box::new(AndroidWindow(app)))
        }),
    );
    if let Err(e) = r {
        eprintln!("kzsigner: {}", trf("Could not open the window: {}", &[&e]));
    }
}

/// The desktop window's screens, asking the activity regularly for chosen and shared files.
struct AndroidWindow(App);

impl eframe::App for AndroidWindow {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            // clear of the status bar
            ui.add_space(24.0);
            self.0.ui(ui);
        });
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(250));
    }
}
