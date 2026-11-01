//! Drawing pages for the document card: text in the bundled font, lines, boxes, QR codes and
//! imported pages. Positions are in millimetres from the page's top left, as in ddc.

use std::collections::BTreeMap;

use qrcodegen::QrCode;

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
    /// Form XObjects drawn on the page: (resource name, object id).
    pub xobjects: Vec<(String, lopdf::ObjectId)>,
    /// Whether the semi-transparent graphics state is used.
    pub alpha: bool,
}

impl Page {
    pub fn new(landscape: bool) -> Page {
        let (w, h) = if landscape { (A4.1, A4.0) } else { A4 };
        Page {
            w,
            h,
            ops: String::new(),
            xobjects: Vec::new(),
            alpha: false,
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

    pub fn rect(&mut self, x: f64, y: f64, w: f64, h: f64, grey: f64) {
        self.ops.push_str(&format!(
            "q {} G 0.3 w {} {} {} {} re S Q\n",
            f(grey),
            f(x * MM),
            f(self.y(y + h)),
            f(w * MM),
            f(h * MM)
        ));
    }

    /// A QR code `size` mm wide with its top left at (x, y), with the quiet zone inside.
    pub fn qr(&mut self, x: f64, y: f64, size: f64, q: &QrCode) {
        let n = q.size();
        let m = size / f64::from(n + 8);
        let mut s = String::from("q 0 g\n");
        for row in 0..n {
            let mut col = 0;
            while col < n {
                if q.get_module(col, row) {
                    let start = col;
                    while col < n && q.get_module(col, row) {
                        col += 1;
                    }
                    let top = y + f64::from(row + 4) * m;
                    s.push_str(&format!(
                        "{} {} {} {} re\n",
                        f((x + f64::from(start + 4) * m) * MM),
                        f(self.y(top + m)),
                        f(f64::from(col - start) * m * MM),
                        f(m * MM)
                    ));
                } else {
                    col += 1;
                }
            }
        }
        s.push_str("f Q\n");
        self.ops.push_str(&s);
    }

    /// Draws form XObject `name` (registered with `id`) scaled into the box.
    #[allow(clippy::too_many_arguments)]
    pub fn form(
        &mut self,
        name: &str,
        id: lopdf::ObjectId,
        x: f64,
        y: f64,
        w: f64,
        h: f64,
        bbox: (f64, f64),
    ) {
        let (sx, sy) = (w * MM / bbox.0, h * MM / bbox.1);
        self.ops.push_str(&format!(
            "q {} 0 0 {} {} {} cm /{name} Do Q\n",
            f(sx),
            f(sy),
            f(x * MM),
            f(self.y(y + h))
        ));
        self.xobjects.push((name.to_string(), id));
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

    /// Text centred on `cx`, rotated by `deg` degrees, semi-transparent (a watermark).
    pub fn watermark(&mut self, p: &mut Page, cx: f64, cy: f64, size: f64, deg: f64, s: &str) {
        let mut hex = String::new();
        for (g, c) in self.font.shape(s) {
            self.used.insert(g, c);
            hex.push_str(&format!("{g:04X}"));
        }
        let w = self.font.text_width(s, size);
        let (sin, cos) = deg.to_radians().sin_cos();
        // start so that the middle of the text lands on the centre
        let (dx, dy) = (-w / 2.0, -size * 0.35);
        let (ox, oy) = (cx * MM + dx * cos - dy * sin, p.y(cy) + dx * sin + dy * cos);
        p.alpha = true;
        p.ops.push_str(&format!(
            "q /GS1 gs BT 0.6 g /F1 {} Tf {} {} {} {} {} {} Tm <{hex}> Tj ET Q\n",
            f(size),
            f(cos),
            f(sin),
            f(-sin),
            f(cos),
            f(ox),
            f(oy)
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
