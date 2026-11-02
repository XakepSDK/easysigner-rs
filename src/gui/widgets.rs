//! The window's building blocks: tones, notes, cards, buttons.

#[allow(unused_imports)]
use super::*;

/// A note under a field: lines of text with a tone each.
#[derive(Clone, Default)]
pub(super) struct Note(pub(super) Vec<(String, Tone)>);

impl Note {
    pub(super) fn error(m: &str) -> Note {
        Note(vec![(m.to_string(), Tone::Bad)])
    }
    pub(super) fn show(&self, ui: &mut egui::Ui) {
        for (t, tone) in &self.0 {
            ui.add(egui::Label::new(tone.text(ui, t)).wrap());
        }
    }
}

/// Text colours that read well on the light and the dark theme.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Tone {
    Plain,
    Strong,
    Good,
    Bad,
    Warn,
    Muted,
}

impl Tone {
    pub(super) fn text(self, ui: &egui::Ui, t: impl Into<String>) -> RichText {
        let r = RichText::new(t);
        match self {
            Tone::Plain => r,
            Tone::Strong => r.strong(),
            _ => r.color(self.color(ui)),
        }
    }

    /// The tone's colour, for text and icons.
    pub(super) fn color(self, ui: &egui::Ui) -> Color32 {
        let dark = ui.visuals().dark_mode;
        let rgb = |l: (u8, u8, u8), d: (u8, u8, u8)| {
            let (r, g, b) = if dark { d } else { l };
            Color32::from_rgb(r, g, b)
        };
        match self {
            Tone::Plain => ui.visuals().text_color(),
            Tone::Strong => ui.visuals().strong_text_color(),
            Tone::Good => rgb((0x1a, 0x7f, 0x37), (0x4a, 0xc2, 0x6b)),
            Tone::Bad => rgb((0xc6, 0x28, 0x28), (0xff, 0x7b, 0x72)),
            Tone::Warn => rgb((0x8a, 0x5a, 0x00), (0xe3, 0xb3, 0x41)),
            Tone::Muted => rgb((0x5d, 0x66, 0x73), (0x9a, 0xa4, 0xb0)),
        }
    }
}

/// The accent colour for icons and lines (the theme's link colour, which reads well on its
/// background; filled buttons use the selection colour).
pub(super) fn accent(ui: &egui::Ui) -> Color32 {
    ui.visuals().hyperlink_color
}

/// A small button with an eye (crossed out while the password is hidden).
pub(super) fn eye_button(ui: &mut egui::Ui, open: bool, hint: &str) -> egui::Response {
    let h = ui.spacing().interact_size.y.max(22.0);
    let r = ui
        .add_sized([h + 8.0, h], egui::Button::new(""))
        .on_hover_text(hint);
    r.widget_info(|| egui::WidgetInfo::selected(egui::Role::Button, true, open, hint));
    let color = ui.style().interact(&r).fg_stroke.color;
    let rect = egui::Rect::from_center_size(r.rect.center(), egui::Vec2::splat(h * 0.8));
    let icon = if open { Icon::Eye } else { Icon::EyeOff };
    icons::paint(ui.painter(), rect, icon, color, 2.0);
    r
}

/// A rounded panel around a group of fields.
pub(super) fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let v = ui.visuals();
    egui::Frame::new()
        .fill(v.faint_bg_color)
        .stroke(v.widgets.noninteractive.bg_stroke)
        .corner_radius(10.0)
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 6.0;
            add(ui)
        })
        .inner
}

/// A coloured box for a verdict or an opened key.
pub(super) fn banner<R>(ui: &mut egui::Ui, tone: Tone, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let dark = ui.visuals().dark_mode;
    let (fill, stroke) = match (tone, dark) {
        (Tone::Good, false) => ((0xea, 0xf5, 0xee), (0xb9, 0xdc, 0xc6)),
        (Tone::Good, true) => ((0x16, 0x2e, 0x20), (0x2c, 0x5a, 0x3e)),
        (Tone::Bad, false) => ((0xfc, 0xec, 0xea), (0xef, 0xc3, 0xbc)),
        (Tone::Bad, true) => ((0x3a, 0x1d, 0x1a), (0x6e, 0x33, 0x2b)),
        (_, false) => ((0xfd, 0xf5, 0xe1), (0xe8, 0xd3, 0x9a)),
        (_, true) => ((0x36, 0x2c, 0x12), (0x66, 0x55, 0x22)),
    };
    let c = |(r, g, b): (u8, u8, u8)| Color32::from_rgb(r, g, b);
    egui::Frame::new()
        .fill(c(fill))
        .stroke(egui::Stroke::new(1.0, c(stroke)))
        .corner_radius(10.0)
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// A row of a screen's actions: side by side, or on a phone one under another at full width.
/// `add` gets the text size and the least size for each button.
pub(super) fn action_row(
    ui: &mut egui::Ui,
    narrow: bool,
    add: impl FnOnce(&mut egui::Ui, f32, egui::Vec2),
) {
    if narrow {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 10.0;
            let w = ui.available_width();
            add(ui, 17.0, egui::vec2(w, 52.0))
        });
    } else {
        ui.horizontal(|ui| add(ui, 15.0, egui::vec2(0.0, 38.0)));
    }
}

/// A warning line, with the warning sign.
pub(super) fn warning(ui: &mut egui::Ui, text: &str) {
    ui.horizontal_top(|ui| {
        icons::show(ui, Icon::Warning, 18.0, Tone::Warn.color(ui));
        ui.add(egui::Label::new(Tone::Warn.text(ui, text)).wrap());
    });
}

/// A step's heading inside a card.
pub(super) fn step(ui: &mut egui::Ui, title: &str) {
    ui.label(Tone::Muted.text(ui, title).strong().size(13.5));
}

/// The main action of a screen.
pub(super) fn primary_button(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).size(16.0).strong())
        .min_size(egui::vec2(120.0, 38.0))
}

/// A big clickable choice with an icon, a title and a line of explanation.
pub(super) fn choice_card(
    ui: &mut egui::Ui,
    id: &str,
    title: &str,
    text: &str,
    first: bool,
    (icon, color): (Icon, Color32),
) -> egui::Response {
    let v = ui.visuals().clone();
    let id = ui.scope_id().with(id);
    let hovered = ui.ctx().read_response(id).is_some_and(|r| r.hovered());
    let stroke = if hovered || first {
        egui::Stroke::new(2.0, v.selection.bg_fill)
    } else {
        v.widgets.noninteractive.bg_stroke
    };
    let inner = egui::Frame::new()
        .fill(v.faint_bg_color)
        .stroke(stroke)
        .corner_radius(14.0)
        .inner_margin(18.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_min_height(96.0);
            ui.horizontal_top(|ui| {
                icons::badge(ui, icon, 52.0, color, color.gamma_multiply(0.14));
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.add(
                        egui::Label::new(RichText::new(title).size(19.0).strong())
                            .selectable(false),
                    );
                    ui.add_space(2.0);
                    ui.add(
                        egui::Label::new(Tone::Muted.text(ui, text).size(14.0))
                            .wrap()
                            .selectable(false),
                    );
                });
            });
        });
    let r = ui.interact(inner.response.rect, id, egui::Sense::click());
    r.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, title));
    if r.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    r
}

/// A chosen file: its name large, its folder small.
pub(super) fn file_title(ui: &mut egui::Ui, f: &Path) {
    file_title_with(ui, f, Icon::File);
}

pub(super) fn file_title_with(ui: &mut egui::Ui, f: &Path, icon: Icon) {
    let name = f
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| f.display().to_string());
    ui.horizontal(|ui| {
        icons::show(ui, icon, 24.0, Tone::Muted.color(ui));
        ui.add(egui::Label::new(RichText::new(name).size(16.0).strong()).truncate());
    });
}
