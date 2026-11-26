//! Drawing PDF pages (the stamp and the "Who signed" page): text in the bundled font and
//! lines. Positions are in millimetres from the page's top left.

use std::collections::BTreeMap;

use super::font::Font;

pub const MM: f64 = 72.0 / 25.4;
pub const A4: (f64, f64) = (210.0, 297.0);

fn f(v: f64) -> String {
    let s = format!("{v:.3}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s == "-0" { "0".into() } else { s.into() }
}

/// One page being drawn.
pub struct Page {
    /// Size in mm.
    pub w: f64,
    pub h: f64,
    pub ops: String,
}

impl Page {
    /// An empty A4 page, upright.
    pub fn a4() -> Page {
        let (w, h) = A4;
        Page {
            w,
            h,
            ops: String::new(),
        }
    }

    fn y(&self, top_mm: f64) -> f64 {
        (self.h - top_mm) * MM
    }

    pub fn line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, grey: f64) {
        let (a, b, c, d) = (x1 * MM, self.y(y1), x2 * MM, self.y(y2));
        self.ops.push_str(&format!(
            "q {} G 0.2 w {} {} m {} {} l S Q\n",
            f(grey),
            f(a),
            f(b),
            f(c),
            f(d)
        ));
    }
}

/// Writes text in the bundled font, keeping track of the glyphs used.
pub struct Writer {
    pub font: Font,
    pub used: BTreeMap<u16, char>,
}

/// Line height for a font size, in mm.
pub fn leading(size: f64) -> f64 {
    size * 1.25 / MM
}

impl Writer {
    pub fn new() -> Writer {
        Writer {
            font: Font::noto(),
            used: BTreeMap::new(),
        }
    }

    pub fn width(&self, s: &str, size: f64) -> f64 {
        self.font.text_width(s, size) / MM
    }

    /// One line of text with its baseline at `y` mm; `grey` 0 is black.
    pub fn text(&mut self, p: &mut Page, x: f64, y: f64, size: f64, grey: f64, s: &str) {
        let mut hex = String::new();
        for (g, c) in self.font.shape(s) {
            self.used.insert(g, c);
            hex.push_str(&format!("{g:04X}"));
        }
        p.ops.push_str(&format!(
            "BT {} g /F1 {} Tf {} {} Td <{hex}> Tj ET\n",
            f(grey),
            f(size),
            f(x * MM),
            f(p.y(y))
        ));
    }

    /// One line of text in colour `rgb` ("r g b", 0 to 1).
    pub fn text_rgb(&mut self, p: &mut Page, x: f64, y: f64, size: f64, rgb: &str, s: &str) {
        let mut hex = String::new();
        for (g, c) in self.font.shape(s) {
            self.used.insert(g, c);
            hex.push_str(&format!("{g:04X}"));
        }
        p.ops.push_str(&format!(
            "BT {rgb} rg /F1 {} Tf {} {} Td <{hex}> Tj ET\n",
            f(size),
            f(x * MM),
            f(p.y(y))
        ));
    }

    /// Splits `s` into lines no wider than `w` mm (keeping its own line breaks).
    pub fn wrap(&self, s: &str, size: f64, w: f64) -> Vec<String> {
        let mut lines = Vec::new();
        for para in s.split('\n') {
            let mut cur = String::new();
            for word in para.split(' ') {
                let cand = if cur.is_empty() {
                    word.to_string()
                } else {
                    format!("{cur} {word}")
                };
                if self.width(&cand, size) <= w || cur.is_empty() {
                    cur = cand;
                } else {
                    lines.push(std::mem::take(&mut cur));
                    cur = word.to_string();
                }
                // a word wider than the line (a hash, a long name): break it by characters
                while self.width(&cur, size) > w && cur.chars().count() > 1 {
                    let mut head = String::new();
                    for c in cur.chars() {
                        if self.width(&format!("{head}{c}"), size) > w {
                            break;
                        }
                        head.push(c);
                    }
                    if head.is_empty() {
                        break;
                    }
                    cur = cur[head.len()..].to_string();
                    lines.push(head);
                }
            }
            lines.push(cur);
        }
        lines
    }

    /// Wrapped text from `y` (top of the first line); returns the y below it.
    #[allow(clippy::too_many_arguments)]
    pub fn para(
        &mut self,
        p: &mut Page,
        x: f64,
        y: f64,
        w: f64,
        size: f64,
        grey: f64,
        s: &str,
    ) -> f64 {
        let lh = leading(size);
        let mut y = y;
        for l in self.wrap(s, size, w) {
            y += lh;
            self.text(p, x, y - lh * 0.25, size, grey, &l);
        }
        y
    }
}

impl Default for Writer {
    fn default() -> Self {
        Writer::new()
    }
}
