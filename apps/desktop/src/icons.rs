//! Line icons for the window, drawn with egui's painter from SVG path data on a 24×24 grid
//! (the shapes of the kzsigner designs), so no icon font or image is needed.

use eframe::egui::{self, Color32, Pos2, Rect, Stroke, Vec2, pos2};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icon {
    Logo,
    File,
    FileCheck,
    Pen,
    ShieldCheck,
    Share,
    Key,
    Back,
    Forward,
    Close,
    Check,
    XCircle,
    Warning,
    Eye,
    EyeOff,
    Download,
    Folder,
    Open,
}

enum Part {
    Path(&'static str),
    Circle(f32, f32, f32),
}
use Part::{Circle, Path};

const PAGE: &str = "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z";
const FOLD: &str = "M14 3v5h5";
const EYE: &str = "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z";

fn parts(i: Icon) -> &'static [Part] {
    match i {
        Icon::Logo => &[
            Path(PAGE),
            Path(FOLD),
            Path("M8 16c1.5-2 2.5-2 3.5 0s2 2 3.5 0"),
        ],
        Icon::File => &[Path(PAGE), Path(FOLD)],
        Icon::FileCheck => &[Path(PAGE), Path(FOLD), Path("M9 14l2 2 4-4")],
        Icon::Pen => &[
            Path("M12 20h9"),
            Path("M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"),
        ],
        Icon::ShieldCheck => &[
            Path("M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"),
            Path("M9 12l2 2 4-4"),
        ],
        Icon::Share => &[
            Circle(18.0, 5.0, 3.0),
            Circle(6.0, 12.0, 3.0),
            Circle(18.0, 19.0, 3.0),
            Path("M8.6 13.5l6.8 4"),
            Path("M15.4 6.5l-6.8 4"),
        ],
        Icon::Key => &[
            Circle(8.0, 15.0, 4.0),
            Path("M11 12l9-9"),
            Path("M17 6l3 3"),
        ],
        Icon::Back => &[Path("M15 18l-6-6 6-6")],
        Icon::Forward => &[Path("M9 18l6-6-6-6")],
        Icon::Close => &[Path("M18 6L6 18"), Path("M6 6l12 12")],
        Icon::Check => &[Path("M20 6L9 17l-5-5")],
        Icon::XCircle => &[
            Circle(12.0, 12.0, 9.0),
            Path("M15 9l-6 6"),
            Path("M9 9l6 6"),
        ],
        Icon::Warning => &[
            Path("M12 9v4"),
            Path("M12 17h.01"),
            Path("M10.3 3.9L2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"),
        ],
        Icon::Eye => &[Path(EYE), Circle(12.0, 12.0, 3.0)],
        Icon::EyeOff => &[Path(EYE), Circle(12.0, 12.0, 3.0), Path("M4 4l16 16")],
        Icon::Download => &[
            Path("M12 3v12"),
            Path("M7 10l5 5 5-5"),
            Path("M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"),
        ],
        Icon::Folder => &[Path(
            "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z",
        )],
        Icon::Open => &[
            Path("M14 4h6v6"),
            Path("M20 4l-9 9"),
            Path("M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4"),
        ],
    }
}

/// Paints `icon` into `rect` (a square) with lines of `width` (on the 24-unit grid).
pub fn paint(p: &egui::Painter, rect: Rect, icon: Icon, color: Color32, width: f32) {
    let scale = rect.width().min(rect.height()) / 24.0;
    let at = |x: f32, y: f32| rect.center() + Vec2::new(x - 12.0, y - 12.0) * scale;
    let stroke = Stroke::new(width * scale, color);
    for part in parts(icon) {
        match part {
            Circle(x, y, r) => {
                p.circle_stroke(at(*x, *y), r * scale, stroke);
            }
            Path(d) => {
                for (points, closed) in flatten(d) {
                    let pts: Vec<Pos2> = points.iter().map(|q| at(q.x, q.y)).collect();
                    let len: f32 = pts.windows(2).map(|w| w[0].distance(w[1])).sum();
                    if len < stroke.width * 0.5 {
                        // a dot ("h.01"): round, as stroke-linecap round draws it
                        p.circle_filled(pts[0], stroke.width * 0.6, color);
                    } else if closed {
                        p.add(egui::Shape::closed_line(pts, stroke));
                    } else {
                        p.add(egui::Shape::line(pts, stroke));
                        // round caps and joins, as in the designs
                    }
                }
            }
        }
    }
}

/// An icon `size` points square, as a widget that takes no clicks.
pub fn show(ui: &mut egui::Ui, icon: Icon, size: f32, color: Color32) -> egui::Response {
    let (rect, r) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    if ui.is_rect_visible(rect) {
        paint(ui.painter(), rect, icon, color, 1.9);
    }
    r
}

/// An icon in a tinted circle, as on the start screen.
pub fn badge(ui: &mut egui::Ui, icon: Icon, size: f32, color: Color32, tint: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), size / 2.0, tint);
    let inner = Rect::from_center_size(rect.center(), Vec2::splat(size * 0.54));
    paint(ui.painter(), inner, icon, color, 1.8);
}

/// A button with an icon before its text, at least `min` big. `filled`: the screen's main
/// action, in the accent colour.
pub fn button(
    ui: &mut egui::Ui,
    icon: Icon,
    text: &str,
    text_size: f32,
    min: Vec2,
    filled: bool,
) -> egui::Response {
    let rich = egui::RichText::new(text).size(text_size).strong();
    let galley = egui::WidgetText::from(rich).into_galley(
        ui,
        Some(egui::TextWrapMode::Extend),
        f32::INFINITY,
        egui::TextStyle::Button,
    );
    let size = text_size + 4.0;
    let pad = ui.spacing().button_padding;
    let gap = 8.0;
    let content = size + gap + galley.size().x;
    let w = (pad.x * 2.0 + content).max(min.x);
    let h = (pad.y * 2.0 + galley.size().y.max(size)).max(min.y);
    let (rect, r) = ui.allocate_exact_size(egui::vec2(w, h), egui::Sense::click());
    r.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, ui.is_enabled(), text));
    if ui.is_rect_visible(rect) {
        let v = ui.style().interact(&r);
        let (fill, color) = if filled {
            let accent = ui.visuals().selection.bg_fill;
            let fill = if r.hovered() {
                accent.gamma_multiply(0.88)
            } else {
                accent
            };
            (fill, Color32::WHITE)
        } else {
            (v.weak_bg_fill, v.text_color())
        };
        let stroke = if filled { Stroke::NONE } else { v.bg_stroke };
        ui.painter()
            .rect(rect, 8.0, fill, stroke, egui::StrokeKind::Inside);
        let left = rect.center().x - content / 2.0;
        let irect =
            Rect::from_min_size(pos2(left, rect.center().y - size / 2.0), Vec2::splat(size));
        paint(ui.painter(), irect, icon, color, 2.0);
        let tpos = pos2(left + size + gap, rect.center().y - galley.size().y / 2.0);
        ui.painter().galley(tpos, galley, color);
    }
    if r.hovered() && ui.is_enabled() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    r
}

// ------------------------------------------------------------------ SVG paths

/// The subpaths of SVG path data as points (curves and arcs flattened), with whether each is
/// closed. Handles M L H V C S Q T A Z, absolute and relative.
pub fn flatten(d: &str) -> Vec<(Vec<Pos2>, bool)> {
    let mut out: Vec<(Vec<Pos2>, bool)> = Vec::new();
    let mut nums = Numbers {
        s: d.as_bytes(),
        i: 0,
    };
    let (mut cur, mut start) = (pos2(0.0, 0.0), pos2(0.0, 0.0));
    let mut last_ctrl: Option<Pos2> = None;
    let mut pts: Vec<Pos2> = Vec::new();
    let mut cmd = b'M';
    let finish = |pts: &mut Vec<Pos2>, out: &mut Vec<(Vec<Pos2>, bool)>, closed: bool| {
        if !pts.is_empty() {
            out.push((std::mem::take(pts), closed));
        }
    };
    loop {
        nums.skip();
        let Some(&c) = nums.s.get(nums.i) else { break };
        if c.is_ascii_alphabetic() {
            cmd = c;
            nums.i += 1;
        } else if cmd == b'M' {
            cmd = b'L'; // more pairs after a moveto are linetos
        } else if cmd == b'm' {
            cmd = b'l';
        }
        let rel = cmd.is_ascii_lowercase();
        let base = if rel { cur } else { pos2(0.0, 0.0) };
        let pt = |nums: &mut Numbers| -> Option<Pos2> {
            Some(pos2(base.x + nums.next()?, base.y + nums.next()?))
        };
        let ctrl = last_ctrl.take();
        if pts.is_empty() && !matches!(cmd, b'M' | b'm' | b'Z' | b'z') {
            pts.push(cur); // drawing on after a Z starts where it closed
        }
        match cmd.to_ascii_uppercase() {
            b'M' => {
                finish(&mut pts, &mut out, false);
                let Some(p) = pt(&mut nums) else { break };
                cur = p;
                start = p;
                pts.push(p);
            }
            b'L' => {
                let Some(p) = pt(&mut nums) else { break };
                cur = p;
                pts.push(p);
            }
            b'H' => {
                let Some(x) = nums.next() else { break };
                cur.x = if rel { cur.x + x } else { x };
                pts.push(cur);
            }
            b'V' => {
                let Some(y) = nums.next() else { break };
                cur.y = if rel { cur.y + y } else { y };
                pts.push(cur);
            }
            b'C' | b'S' => {
                let c1 = if cmd.eq_ignore_ascii_case(&b'C') {
                    let Some(p) = pt(&mut nums) else { break };
                    p
                } else {
                    // the reflection of the last curve's second control point
                    ctrl.map_or(cur, |c| cur + (cur - c))
                };
                let (Some(c2), Some(end)) = (pt(&mut nums), pt(&mut nums)) else {
                    break;
                };
                cubic(&mut pts, cur, c1, c2, end);
                last_ctrl = Some(c2);
                cur = end;
            }
            b'Q' | b'T' => {
                let c = if cmd.eq_ignore_ascii_case(&b'Q') {
                    let Some(p) = pt(&mut nums) else { break };
                    p
                } else {
                    ctrl.map_or(cur, |c| cur + (cur - c))
                };
                let Some(end) = pt(&mut nums) else { break };
                let (c1, c2) = (cur + (c - cur) * (2.0 / 3.0), end + (c - end) * (2.0 / 3.0));
                cubic(&mut pts, cur, c1, c2, end);
                last_ctrl = Some(c);
                cur = end;
            }
            b'A' => {
                let (Some(rx), Some(ry), Some(rot), Some(large), Some(sweep)) = (
                    nums.next(),
                    nums.next(),
                    nums.next(),
                    nums.flag(),
                    nums.flag(),
                ) else {
                    break;
                };
                let Some(end) = pt(&mut nums) else { break };
                arc(&mut pts, cur, end, rx, ry, rot, large, sweep);
                cur = end;
            }
            b'Z' => {
                cur = start;
                finish(&mut pts, &mut out, true);
            }
            _ => break,
        }
    }
    finish(&mut pts, &mut out, false);
    out
}

struct Numbers<'a> {
    s: &'a [u8],
    i: usize,
}

impl Numbers<'_> {
    fn skip(&mut self) {
        while self
            .s
            .get(self.i)
            .is_some_and(|c| c.is_ascii_whitespace() || *c == b',')
        {
            self.i += 1;
        }
    }

    fn next(&mut self) -> Option<f32> {
        self.skip();
        let start = self.i;
        let mut dot = false;
        if matches!(self.s.get(self.i), Some(b'-' | b'+')) {
            self.i += 1;
        }
        while let Some(&c) = self.s.get(self.i) {
            if c.is_ascii_digit() {
                self.i += 1;
            } else if c == b'.' && !dot {
                dot = true;
                self.i += 1;
            } else {
                break;
            }
        }
        std::str::from_utf8(&self.s[start..self.i])
            .ok()?
            .parse()
            .ok()
    }

    /// An arc flag: a single 0 or 1, which may run into the next number ("a2 2 0 011 1").
    fn flag(&mut self) -> Option<bool> {
        self.skip();
        let c = *self.s.get(self.i)?;
        self.i += 1;
        match c {
            b'0' => Some(false),
            b'1' => Some(true),
            _ => None,
        }
    }
}

fn cubic(pts: &mut Vec<Pos2>, p0: Pos2, c1: Pos2, c2: Pos2, p1: Pos2) {
    if pts.is_empty() {
        pts.push(p0);
    }
    const N: usize = 12;
    for k in 1..=N {
        let t = k as f32 / N as f32;
        let u = 1.0 - t;
        let v = p0.to_vec2() * (u * u * u)
            + c1.to_vec2() * (3.0 * u * u * t)
            + c2.to_vec2() * (3.0 * u * t * t)
            + p1.to_vec2() * (t * t * t);
        pts.push(v.to_pos2());
    }
}

/// An elliptical arc by the SVG endpoint rules (SVG 1.1 F.6.5).
#[allow(clippy::too_many_arguments)]
fn arc(
    pts: &mut Vec<Pos2>,
    p0: Pos2,
    p1: Pos2,
    rx: f32,
    ry: f32,
    rot_deg: f32,
    large: bool,
    sweep: bool,
) {
    if pts.is_empty() {
        pts.push(p0);
    }
    let (mut rx, mut ry) = (rx.abs(), ry.abs());
    if rx == 0.0 || ry == 0.0 || p0 == p1 {
        pts.push(p1);
        return;
    }
    let (s, c) = rot_deg.to_radians().sin_cos();
    let d = (p0 - p1) / 2.0;
    let (x1, y1) = (c * d.x + s * d.y, -s * d.x + c * d.y);
    let lambda = (x1 * x1) / (rx * rx) + (y1 * y1) / (ry * ry);
    if lambda > 1.0 {
        rx *= lambda.sqrt();
        ry *= lambda.sqrt();
    }
    let num = rx * rx * ry * ry - rx * rx * y1 * y1 - ry * ry * x1 * x1;
    let den = rx * rx * y1 * y1 + ry * ry * x1 * x1;
    let mut k = (num / den).max(0.0).sqrt();
    if large == sweep {
        k = -k;
    }
    let (cx1, cy1) = (k * rx * y1 / ry, -k * ry * x1 / rx);
    let mid = (p0.to_vec2() + p1.to_vec2()) / 2.0;
    let center = pos2(c * cx1 - s * cy1 + mid.x, s * cx1 + c * cy1 + mid.y);
    let angle = |ux: f32, uy: f32| uy.atan2(ux);
    let t0 = angle((x1 - cx1) / rx, (y1 - cy1) / ry);
    let mut dt = angle((-x1 - cx1) / rx, (-y1 - cy1) / ry) - t0;
    let tau = std::f32::consts::TAU;
    if sweep && dt < 0.0 {
        dt += tau;
    } else if !sweep && dt > 0.0 {
        dt -= tau;
    }
    let n = ((dt.abs() / tau * 32.0).ceil() as usize).max(2);
    for k in 1..=n {
        let t = t0 + dt * k as f32 / n as f32;
        let (st, ct) = t.sin_cos();
        let (x, y) = (rx * ct, ry * st);
        pts.push(pos2(center.x + c * x - s * y, center.y + s * x + c * y));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_flatten() {
        // the page outline: one closed subpath that ends where it began
        let p = flatten(PAGE);
        assert_eq!(p.len(), 1);
        assert!(p[0].1);
        let first = p[0].0[0];
        assert!(first.distance(pos2(14.0, 3.0)) < 1e-4);
        // a quarter arc of radius 2 around (7,5), from (7,3) to (5,5)
        let a = flatten("M7 3a2 2 0 0 0-2 2");
        let (o, r) = (pos2(7.0, 5.0), 2.0);
        assert!(
            a[0].0.iter().all(|q| (q.distance(o) - r).abs() < 1e-2),
            "{a:?}"
        );
        assert!(
            a[0].0.iter().any(|q| q.distance(pos2(5.586, 3.586)) < 0.25),
            "{a:?}"
        );
        // relative lines and a dot
        assert_eq!(
            flatten("M9 12l2 2 4-4")[0].0.last(),
            Some(&pos2(15.0, 10.0))
        );
        assert_eq!(flatten("M12 17h.01")[0].0.len(), 2);
        // S reflects the previous control point
        let w = flatten("M8 16c1.5-2 2.5-2 3.5 0s2 2 3.5 0");
        assert!(w[0].0.last().unwrap().distance(pos2(15.0, 16.0)) < 1e-4);
        // every icon has something to draw
        for i in [
            Icon::Logo,
            Icon::Warning,
            Icon::Eye,
            Icon::Folder,
            Icon::Open,
        ] {
            for part in parts(i) {
                if let Path(d) = part {
                    assert!(!flatten(d).is_empty(), "{i:?} {d}");
                }
            }
        }
    }
}
