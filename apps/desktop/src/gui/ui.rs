//! The window's look: the design's colours, and the few widgets every screen uses.

use eframe::egui::{self, Color32, RichText, Stroke, Vec2};

use crate::icons::{self, Icon};

pub const ACCENT: Color32 = Color32::from_rgb(0x1F, 0x5E, 0xDB);
pub const TEXT: Color32 = Color32::from_rgb(0x14, 0x18, 0x1F);
pub const MUTED: Color32 = Color32::from_rgb(0x4A, 0x53, 0x63);
pub const BORDER: Color32 = Color32::from_rgb(0xD5, 0xDA, 0xE3);
pub const LINE: Color32 = Color32::from_rgb(0xE8, 0xEB, 0xF0);
pub const SURFACE: Color32 = Color32::from_rgb(0xF5, 0xF7, 0xFA);
pub const PANE: Color32 = Color32::from_rgb(0xEE, 0xF0, 0xF4);
pub const GREEN: Color32 = Color32::from_rgb(0x1E, 0x7F, 0x4F);

/// A coloured box's background, title and text colours.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    Good,
    Bad,
    Warn,
    Info,
    Grey,
}

impl Tone {
    pub fn colors(self) -> (Color32, Color32, Color32) {
        match self {
            Tone::Good => (
                Color32::from_rgb(0xE3, 0xF4, 0xEA),
                Color32::from_rgb(0x14, 0x5C, 0x38),
                Color32::from_rgb(0x1D, 0x4A, 0x33),
            ),
            Tone::Bad => (
                Color32::from_rgb(0xFD, 0xE8, 0xE6),
                Color32::from_rgb(0x8A, 0x1C, 0x16),
                Color32::from_rgb(0x6E, 0x17, 0x12),
            ),
            Tone::Warn => (
                Color32::from_rgb(0xFF, 0xF4, 0xE0),
                Color32::from_rgb(0x6B, 0x42, 0x00),
                Color32::from_rgb(0x6B, 0x42, 0x00),
            ),
            Tone::Info => (
                Color32::from_rgb(0xEA, 0xF1, 0xFD),
                Color32::from_rgb(0x1D, 0x3F, 0x80),
                Color32::from_rgb(0x1D, 0x3F, 0x80),
            ),
            Tone::Grey => (SURFACE, TEXT, MUTED),
        }
    }
}

/// The light theme of the designs, with larger text than egui's default.
pub fn style(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Light);
    ctx.style_mut_of(egui::Theme::Light, |s| {
        use egui::{FontFamily::Proportional, FontId, TextStyle};
        s.text_styles = [
            (TextStyle::Heading, FontId::new(24.0, Proportional)),
            (TextStyle::Body, FontId::new(15.0, Proportional)),
            (TextStyle::Button, FontId::new(15.0, Proportional)),
            (TextStyle::Small, FontId::new(13.0, Proportional)),
            (
                TextStyle::Monospace,
                FontId::new(14.0, egui::FontFamily::Monospace),
            ),
        ]
        .into();
        s.spacing.item_spacing = egui::vec2(10.0, 10.0);
        s.spacing.button_padding = egui::vec2(16.0, 8.0);
        s.spacing.interact_size.y = 40.0;
        let v = &mut s.visuals;
        v.panel_fill = Color32::WHITE;
        v.window_fill = Color32::WHITE;
        v.override_text_color = Some(TEXT);
        v.selection.bg_fill = ACCENT;
        v.hyperlink_color = ACCENT;
        v.extreme_bg_color = Color32::WHITE;
        for w in [
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
        ] {
            w.corner_radius = 12.into();
        }
        v.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0xA9, 0xB2, 0xC2));
        v.widgets.inactive.weak_bg_fill = Color32::WHITE;
        v.widgets.hovered.weak_bg_fill = SURFACE;
    });
}

pub fn muted(text: impl Into<String>) -> RichText {
    RichText::new(text).color(MUTED)
}

pub fn title(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(26.0).strong());
}

/// The screen's main action: filled, `w` wide.
pub fn main_button(ui: &mut egui::Ui, text: &str, w: f32) -> egui::Response {
    let (fill, color) = if ui.is_enabled() {
        (ACCENT, Color32::WHITE)
    } else {
        (LINE, MUTED)
    };
    let b = egui::Button::new(RichText::new(text).size(17.0).strong().color(color))
        .fill(fill)
        .stroke(Stroke::NONE)
        .corner_radius(14.0);
    ui.add_sized([w, 52.0], b)
}

/// A second action: outlined, as wide as its words.
pub fn second_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let b = egui::Button::new(RichText::new(text).size(15.0).strong())
        .fill(Color32::WHITE)
        .stroke(Stroke::new(1.0, Color32::from_rgb(0xC3, 0xCA, 0xD6)))
        .corner_radius(14.0)
        .min_size(egui::vec2(0.0, 48.0));
    ui.horizontal(|ui| ui.add(b)).inner
}

/// A quiet action: accent text, no frame.
pub fn text_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let b = egui::Button::new(RichText::new(text).size(15.0).strong().color(ACCENT))
        .frame(false)
        .min_size(egui::vec2(0.0, 44.0));
    ui.add(b)
}

/// A rounded box in `tone`, with `title` and `body`.
pub fn notice(ui: &mut egui::Ui, tone: Tone, title: &str, body: &str) {
    let (bg, t, b) = tone.colors();
    egui::Frame::new()
        .fill(bg)
        .corner_radius(14.0)
        .inner_margin(egui::Margin::symmetric(16, 12))
        .show(ui, |ui| {
            plain(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.spacing_mut().item_spacing.y = 4.0;
                if !title.is_empty() {
                    ui.label(RichText::new(title).size(16.0).strong().color(t));
                }
                if !body.is_empty() {
                    ui.label(RichText::new(body).color(b));
                }
            })
        });
}

/// The big coloured verdict box at the top of a check.
pub fn verdict(ui: &mut egui::Ui, tone: Tone, icon: Icon, title: &str, body: &str) {
    let (bg, t, b) = tone.colors();
    egui::Frame::new()
        .fill(bg)
        .corner_radius(20.0)
        .inner_margin(egui::Margin::symmetric(24, 18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                icons::show(ui, icon, 44.0, t);
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 4.0;
                    ui.label(RichText::new(title).size(24.0).strong().color(t));
                    if !body.is_empty() {
                        ui.label(RichText::new(body).size(15.0).color(b));
                    }
                });
            });
        });
}

/// A bordered box.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(16.0)
        .inner_margin(egui::Margin::symmetric(18, 14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            plain(ui, add)
        })
        .inner
}

/// A label over a value, as on the phone's cards.
pub fn field(ui: &mut egui::Ui, label: &str, value: &str, sub: Option<&str>) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        ui.label(muted(label).size(13.0));
        ui.label(RichText::new(value).size(17.0).strong());
        if let Some(s) = sub {
            ui.label(muted(s).size(14.0));
        }
    });
}

/// The password box: hidden text, a show/hide eye, `hint` inside. Returns the text box's
/// response.
pub fn password(
    ui: &mut egui::Ui,
    value: &mut String,
    shown: &mut bool,
    label: &str,
    hint: &str,
) -> egui::Response {
    let l = ui.label(muted(label).size(14.0));
    ui.horizontal(|ui| {
        let w = ui.available_width() - 52.0;
        let r = ui.add(
            egui::TextEdit::singleline(value)
                .password(!*shown)
                .hint_text(hint)
                .desired_width(w)
                .min_size(egui::vec2(w, 44.0))
                .margin(egui::Margin::symmetric(12, 12))
                .font(egui::TextStyle::Body),
        );
        let r = r.labelled_by(l.id);
        let (icon, tip) = if *shown {
            (Icon::EyeOff, super::text::t("Hide password"))
        } else {
            (Icon::Eye, super::text::t("Show password"))
        };
        let e = ui.add_sized([44.0, 44.0], egui::Button::new("").frame(false));
        e.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, tip));
        icons::paint(
            ui.painter(),
            egui::Rect::from_center_size(e.rect.center(), Vec2::splat(22.0)),
            icon,
            MUTED,
            1.8,
        );
        if e.on_hover_text(tip).clicked() {
            *shown = !*shown;
        }
        r
    })
    .inner
}

/// An area of `w` at most, centred in the space left.
pub fn centred<R>(ui: &mut egui::Ui, w: f32, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let avail = ui.available_width();
    let w = w.min(avail);
    let pad = ((avail - w) / 2.0).max(0.0);
    ui.horizontal_top(|ui| {
        ui.add_space(pad);
        ui.vertical(|ui| {
            ui.set_width(w);
            add(ui)
        })
        .inner
    })
    .inner
}

/// A bordered box that is pressed as a whole (a screen reader names it `label`).
pub fn card_button(
    ui: &mut egui::Ui,
    label: &str,
    add: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    let r = egui::Frame::new()
        .stroke(Stroke::new(1.5, BORDER))
        .fill(SURFACE)
        .corner_radius(16.0)
        .inner_margin(egui::Margin::symmetric(18, 16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .response;
    let resp = ui.interact(
        r.rect,
        ui.make_persistent_id(("card", label)),
        egui::Sense::click(),
    );
    resp.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, label));
    if resp.hovered() || resp.has_focus() {
        ui.painter().rect_stroke(
            r.rect,
            16.0,
            Stroke::new(2.0, ACCENT),
            egui::StrokeKind::Inside,
        );
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A row of buttons, or a column of them when the window is narrow.
pub fn actions<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    if ui.available_width() >= 560.0 {
        ui.horizontal_wrapped(add).inner
    } else {
        ui.vertical(add).inner
    }
}

/// Left-aligned, unjustified content (inside `ui.columns`, which justifies).
pub fn plain<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.with_layout(egui::Layout::top_down(egui::Align::Min), add)
        .inner
}
