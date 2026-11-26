//! The desktop window: the phone app's simple flow (one Sign action, the output decided by the
//! input, no options) on screens made for a window. Behaviour comes from the app layer the
//! phone uses too (`kzsigner-ffi`): what a file is, what signing makes, what a check says, and
//! the key vault. See docs/desktop-plan.md.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use eframe::egui::{self, RichText};
use kzsigner::i18n::{self, Lang};
use kzsigner_ffi::{Checked, Doc, KeyInfo, Nca, Signed, Vault};

use crate::icons::{self, Icon};

mod check;
pub mod chip;
mod files;
pub mod home;
mod sign;
pub mod text;
pub mod ui;

use files::*;
use text::{t, tf};
use ui::Tone;

/// What a file chooser is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pick {
    /// A key file (.p12).
    Key,
    /// A document to sign.
    Document,
    /// A signed file to check.
    Signed,
    /// The document a detached .cms signs.
    Original,
}

/// File choosers and the system's viewer: the system's own, or scripted ones in tests.
pub trait Dialogs {
    fn open(&mut self, what: Pick) -> Option<PathBuf>;
    /// The save location; the system dialog asks before replacing a file.
    fn save(&mut self, suggested: &Path) -> Option<PathBuf>;
    /// Shows a saved file in its folder.
    fn reveal(&mut self, path: &Path) {
        show_in_folder(path);
    }
    /// Opens `path` in the system's viewer for its type (the signer reads what they sign).
    fn view(&mut self, path: &Path) -> Result<(), String> {
        open_with_system(path).map_err(|e| e.to_string())
    }
    /// A folder for files made only to be viewed (a document taken out of a .cms).
    fn view_dir(&self) -> PathBuf {
        std::env::temp_dir().join("kzsigner-view")
    }
}

/// The operating system's file dialogs.
pub struct SystemDialogs;

impl Dialogs for SystemDialogs {
    fn open(&mut self, what: Pick) -> Option<PathBuf> {
        let mut d = rfd::FileDialog::new();
        d = match what {
            Pick::Key => d
                .set_title(t("Choose the key file"))
                .add_filter(t("Signature key"), &["p12", "pfx", "P12", "PFX"]),
            Pick::Document => d.set_title(t("Sign a document")),
            Pick::Signed => d.set_title(t("Check a signature")),
            Pick::Original => d.set_title(t("Choose the document")),
        };
        d.add_filter(t("All files"), &["*"]).pick_file()
    }

    fn save(&mut self, suggested: &Path) -> Option<PathBuf> {
        let mut d = rfd::FileDialog::new();
        if let Some(dir) = suggested.parent().filter(|p| !p.as_os_str().is_empty()) {
            d = d.set_directory(dir);
        }
        if let Some(name) = suggested.file_name() {
            d = d.set_file_name(name.to_string_lossy());
        }
        d.save_file()
    }
}

/// Where kzsigner keeps its keys: `%APPDATA%\kzsigner`, `~/Library/Application
/// Support/kzsigner`, or `$XDG_DATA_HOME/kzsigner` (`~/.local/share/kzsigner`).
pub fn data_dir() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| Path::new(&h).join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".local/share")))
    }?;
    Some(base.join("kzsigner"))
}

/// Opens the window and runs until it is closed. `file`: a document, signed file or key to
/// start with.
pub fn run(nca: Arc<Nca>, file: Option<PathBuf>) -> Result<(), String> {
    i18n::set(i18n::detect());
    let dir = data_dir().ok_or_else(|| t("Can't find the folder for your keys.").to_string())?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("kzsigner")
            .with_app_id("kzsigner")
            .with_icon(egui::IconData {
                rgba: include_bytes!("../../../../assets/kzsigner-64.rgba").to_vec(),
                width: 64,
                height: 64,
            })
            .with_inner_size([1040.0, 700.0])
            .with_min_inner_size([480.0, 520.0])
            .with_drag_and_drop(true),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "kzsigner",
        options,
        Box::new(move |cc| {
            let _ = cc;
            let mut app = App::new(nca, &dir, Box::new(SystemDialogs));
            app.pending_open = file;
            Ok(Box::new(Window(app)))
        }),
    )
    .map_err(|e| tf("Could not open the window: {}", &[&e]))
}

struct Window(App);

impl eframe::App for Window {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.0.ui(ui);
    }
}

/// The screen the window shows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    Home,
    AddKey,
    Keys,
    About,
    Sign,
    Signed,
    Check,
}

/// Work done off the window's thread.
enum Msg {
    KeyAdded(Result<String, kzsigner_ffi::AddKeyError>),
    Signed(u64, Result<Signed, kzsigner_ffi::SignError>),
    Checked(u64, Box<Checked>),
    View(Result<PathBuf, String>),
}

/// The Add key screen.
#[derive(Default)]
pub struct AddForm {
    pub file: Option<PathBuf>,
    p12: Option<Vec<u8>>,
    pub password: String,
    shown: bool,
    pub problem: Option<home::AddProblem>,
    /// The screen Back returns to.
    back: Option<Screen>,
    /// Pick a document right after: the key was added from "Sign a document".
    then_pick: bool,
}

/// A document opened to sign.
pub struct SignState {
    pub path: PathBuf,
    pub name: String,
    bytes: Arc<Vec<u8>>,
    pub doc: Doc,
    pub password: String,
    shown: bool,
    pub problem: Option<sign::SignProblem>,
    choosing_key: bool,
    /// Put the cursor in the password box on the next frame.
    focus: bool,
    /// The signature being made, to drop an answer for a document closed since.
    request: u64,
}

/// A signed file just saved.
pub struct SignedState {
    /// Where it was saved; None when the person closed the save dialog.
    pub path: Option<PathBuf>,
    pub name: String,
    bytes: Vec<u8>,
    pub nca_time_ms: Option<i64>,
    pdf: bool,
    /// Saved next to the original (not where the person chose).
    next_to_original: bool,
    copy_saved: Option<PathBuf>,
}

/// A file being checked.
pub struct CheckState {
    pub path: PathBuf,
    pub name: String,
    bytes: Arc<Vec<u8>>,
    /// The document a detached .cms signs.
    pub original: Option<PathBuf>,
    original_bytes: Option<Arc<Vec<u8>>>,
    pub result: Option<Checked>,
    pub details: bool,
    request: u64,
}

pub struct App {
    nca: Arc<Nca>,
    vault: Result<Arc<Vault>, String>,
    dialogs: Box<dyn Dialogs>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    jobs: usize,
    requests: u64,
    pub screen: Screen,
    pub keys: Vec<KeyInfo>,
    /// The key that signs.
    pub key_id: Option<String>,
    pub add: AddForm,
    pub sign: Option<SignState>,
    pub signed: Option<SignedState>,
    pub check: Option<CheckState>,
    /// The key "Remove" was pressed for, waiting for the confirmation.
    pub confirm_remove: Option<String>,
    /// A message over the screen: (text, tone).
    pub message: Option<(String, Tone)>,
    /// A file to open on the next frame (the command line's).
    pub pending_open: Option<PathBuf>,
    /// The language chosen in the window; None: the computer's.
    pub chosen_lang: Option<Lang>,
    styled: bool,
}

/// Files bigger than this are not read into memory to sign or check.
const TOO_BIG: u64 = 512 << 20;

impl App {
    /// The window's state, with the key vault in `dir`.
    pub fn new(nca: Arc<Nca>, dir: &Path, dialogs: Box<dyn Dialogs>) -> App {
        let chip = Arc::new(chip::FileChip::new(dir.join("chip")));
        let vault = std::fs::create_dir_all(dir)
            .map_err(|e| e.to_string())
            .and_then(|_| {
                Vault::new(dir.join("keys.kzs").to_string_lossy().into_owned(), chip)
                    .map_err(|e| e.to_string())
            });
        let (tx, rx) = channel();
        let mut app = App {
            nca,
            vault,
            dialogs,
            tx,
            rx,
            jobs: 0,
            requests: 0,
            screen: Screen::Home,
            keys: vec![],
            key_id: None,
            add: AddForm::default(),
            sign: None,
            signed: None,
            check: None,
            confirm_remove: None,
            message: None,
            pending_open: None,
            chosen_lang: i18n::saved(),
            styled: false,
        };
        app.reload_keys();
        app
    }

    /// Work is running in the background.
    pub fn busy(&self) -> bool {
        self.jobs > 0
    }

    fn job(&mut self, ctx: &egui::Context, f: impl FnOnce() -> Msg + Send + 'static) {
        self.jobs += 1;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(f());
            ctx.request_repaint();
        });
    }

    fn next_request(&mut self) -> u64 {
        self.requests += 1;
        self.requests
    }

    fn reload_keys(&mut self) {
        self.keys = match &self.vault {
            Ok(v) => v.keys().keys,
            Err(_) => vec![],
        };
        let still = |id: &String| self.keys.iter().any(|k| &k.id == id);
        if !self.key_id.as_ref().is_some_and(still) {
            self.key_id = self
                .keys
                .iter()
                .find(|k| k.cant_sign.is_none())
                .or(self.keys.first())
                .map(|k| k.id.clone());
        }
    }

    /// The key that signs.
    pub fn key(&self) -> Option<&KeyInfo> {
        let id = self.key_id.as_ref()?;
        self.keys.iter().find(|k| &k.id == id)
    }

    /// The whole window, one frame.
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if !self.styled {
            install_fonts(&ctx);
            ui::style(&ctx);
            self.styled = true;
        }
        while let Ok(m) = self.rx.try_recv() {
            self.jobs -= 1;
            self.handle(&ctx, m);
        }
        if let Some(f) = self.pending_open.take() {
            self.open_file(&ctx, f);
        }
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        if let Some(f) = dropped.into_iter().next() {
            self.open_file(&ctx, f);
        }
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.back();
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(egui::Color32::WHITE))
            .show(ui, |ui| {
                self.header(ui);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_space(8.0);
                        let wide = ui.available_width() >= 860.0;
                        let w = match self.screen {
                            Screen::Sign | Screen::Check if wide => 960.0,
                            Screen::Sign | Screen::Check => 600.0,
                            _ => 620.0,
                        };
                        ui::centred(ui, w, |ui| {
                            if let Some((m, tone)) = self.message.clone() {
                                ui::notice(ui, tone, "", &m);
                                if ui::text_button(ui, t("Close")).clicked() {
                                    self.message = None;
                                }
                            }
                            match self.screen {
                                Screen::Home => self.home(ui),
                                Screen::AddKey => self.add_key(ui),
                                Screen::Keys => self.keys_screen(ui),
                                Screen::About => self.about(ui),
                                Screen::Sign => self.sign_screen(ui, wide),
                                Screen::Signed => self.signed_screen(ui),
                                Screen::Check => self.check_screen(ui, wide),
                            }
                            ui.add_space(24.0);
                        });
                    });
            });
        // a file held over the window
        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            let r = ctx.content_rect();
            let p = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::unique("kzsigner-drop"),
            ));
            p.rect_filled(r, 0.0, egui::Color32::from_white_alpha(225));
            p.rect_stroke(
                r.shrink(12.0),
                18.0,
                egui::Stroke::new(3.0, ui::ACCENT),
                egui::StrokeKind::Inside,
            );
            p.text(
                r.center(),
                egui::Align2::CENTER_CENTER,
                t("Drop the file to open it"),
                egui::FontId::proportional(24.0),
                ui::ACCENT,
            );
        }
    }

    /// The top bar: Back (or the name) on the left, the key on the right.
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.set_min_height(48.0);
            if self.screen == Screen::Home || self.screen == Screen::Signed {
                ui.add_space(8.0);
                icons::show(ui, Icon::Logo, 30.0, ui::ACCENT);
                ui.label(RichText::new("kzsigner").size(20.0).strong());
            } else {
                let b = ui.add(
                    egui::Button::new(RichText::new(t("Back")).size(15.0).strong())
                        .frame(false)
                        .min_size(egui::vec2(90.0, 44.0)),
                );
                icons::paint(
                    ui.painter(),
                    egui::Rect::from_center_size(
                        b.rect.left_center() + egui::vec2(4.0, 0.0),
                        egui::Vec2::splat(18.0),
                    ),
                    Icon::Back,
                    ui::TEXT,
                    2.0,
                );
                if b.clicked() {
                    self.back();
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(8.0);
                if matches!(self.screen, Screen::Keys | Screen::About | Screen::AddKey) {
                    return;
                }
                let (label, to) = match self.key() {
                    Some(k) => (k.name.clone(), Screen::Keys),
                    None => (t("Add key").to_string(), Screen::AddKey),
                };
                let b = ui.add(
                    egui::Button::new(RichText::new(&label).size(14.0).strong())
                        .fill(ui::SURFACE)
                        .stroke(egui::Stroke::new(1.0, ui::BORDER))
                        .corner_radius(22.0)
                        .min_size(egui::vec2(0.0, 40.0)),
                );
                let b = b.on_hover_text(t("Your keys"));
                if b.clicked() {
                    if to == Screen::AddKey {
                        self.start_add_key(false);
                    } else {
                        self.confirm_remove = None;
                        self.screen = Screen::Keys;
                    }
                }
            });
        });
        let r = ui.max_rect();
        ui.painter().hline(
            r.x_range(),
            ui.cursor().top(),
            egui::Stroke::new(1.0, ui::LINE),
        );
    }

    /// Back, as the Back button or Esc. False on Home.
    pub fn back(&mut self) -> bool {
        self.message = None;
        self.screen = match self.screen {
            Screen::Home => return false,
            Screen::AddKey => self.add.back.unwrap_or(Screen::Home),
            Screen::About => Screen::Keys,
            Screen::Signed => {
                self.signed = None;
                Screen::Home
            }
            Screen::Sign => {
                self.sign = None;
                Screen::Home
            }
            Screen::Check => {
                self.check = None;
                Screen::Home
            }
            Screen::Keys => Screen::Home,
        };
        true
    }

    /// A dropped file, or one opened with kzsigner: a key goes to Add key, a detached .cms to
    /// Check (or, while a check waits for it, the document it signs), anything else to Sign
    /// (a signed file asks "Add your signature?"). On the Check screen, a file is checked.
    pub fn open_file(&mut self, ctx: &egui::Context, path: PathBuf) {
        let Some((name, bytes)) = self.read(&path) else {
            return;
        };
        let doc = kzsigner_ffi::inspect(name.clone(), bytes.clone());
        if doc.kind == kzsigner_ffi::DocKind::Key || self.screen == Screen::AddKey {
            if self.screen != Screen::AddKey {
                self.start_add_key(false);
            }
            self.set_key_file(path, bytes);
            return;
        }
        if self.screen == Screen::Check {
            let waiting = self.check.as_ref().is_some_and(|c| {
                c.result
                    .as_ref()
                    .is_some_and(|r| r.verdict == kzsigner_ffi::Verdict::NeedsDocument)
            });
            if waiting && doc.kind != kzsigner_ffi::DocKind::Cms {
                self.set_original(ctx, path, bytes);
            } else {
                self.start_check_with(ctx, path, name, bytes);
            }
            return;
        }
        if doc.kind == kzsigner_ffi::DocKind::Cms && doc.output == kzsigner_ffi::Output::Cannot {
            self.start_check_with(ctx, path, name, bytes);
            return;
        }
        self.start_sign_with(path, name, bytes, doc);
    }

    /// The file's name and content, or a message saying why it can't be read.
    fn read(&mut self, path: &Path) -> Option<(String, Vec<u8>)> {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "document".into());
        let r = std::fs::metadata(path).and_then(|m| {
            if m.len() > TOO_BIG {
                Err(std::io::Error::other(t("This file is too big.")))
            } else {
                std::fs::read(path)
            }
        });
        match r {
            Ok(b) => Some((name, b)),
            Err(e) => {
                self.message = Some((tf("Can't read {}: {}", &[&name, &e]), Tone::Bad));
                None
            }
        }
    }

    /// Switches the window's language (None: the computer's) and remembers it.
    pub fn set_language(&mut self, ctx: &egui::Context, lang: Option<Lang>) {
        self.chosen_lang = lang;
        match lang {
            Some(l) => {
                i18n::save(l);
                i18n::set(l);
            }
            None => {
                i18n::forget();
                i18n::set(i18n::detect());
            }
        }
        // a check's details are in the language it was made in
        if let Some(c) = &self.check
            && c.result.is_some()
        {
            self.recheck(ctx);
        }
    }

    fn handle(&mut self, ctx: &egui::Context, m: Msg) {
        match m {
            Msg::KeyAdded(r) => self.key_added(ctx, r),
            Msg::Signed(id, r) => self.signed_answer(id, r),
            Msg::Checked(id, r) => {
                if let Some(c) = &mut self.check
                    && c.request == id
                {
                    c.result = Some(*r);
                }
            }
            Msg::View(r) => {
                if let Err(e) = r.and_then(|f| {
                    check_viewable(&f)?;
                    self.dialogs.view(&f)
                }) {
                    self.message = Some((tf("Could not open the document: {}", &[&e]), Tone::Bad));
                }
            }
        }
    }

    /// Opens `content` (a file named `name`) in the system's viewer, from a private copy when
    /// it is not the file `path` itself.
    fn view(
        &mut self,
        ctx: &egui::Context,
        path: Option<PathBuf>,
        name: String,
        content: Arc<Vec<u8>>,
    ) {
        let dir = self.dialogs.view_dir();
        self.job(ctx, move || {
            let r = match path {
                Some(p) => std::fs::File::open(&p)
                    .map_err(|e| format!("{}: {e}", p.display()))
                    .and_then(|f| for_viewing(&dir, &p, f)),
                None => {
                    let mut c = std::io::Cursor::new(content.as_slice());
                    viewable_name(&name, &mut c)
                        .and_then(|n| write_for_viewing(&dir, &n, content.as_slice()))
                }
            };
            Msg::View(r)
        });
    }
}

/// Noto Sans cut down to Latin and Cyrillic (with Kazakh), and ✔ ✖ ⚠ from Noto Emoji: 51 KB
/// instead of egui's bundled 650 KB of fonts. See assets/README.md.
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::empty();
    for (name, data) in [
        (
            "text",
            &include_bytes!("../../../../assets/NotoSans-subset.ttf")[..],
        ),
        (
            "symbols",
            &include_bytes!("../../../../assets/symbols.ttf")[..],
        ),
    ] {
        fonts
            .font_data
            .insert(name.into(), Arc::new(egui::FontData::from_static(data)));
    }
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .insert(family, vec!["text".into(), "symbols".into()]);
    }
    ctx.set_fonts(fonts);
}
