//! The "Who signed" page: the first signer adds an A4 page at the end of the PDF, with a note
//! in Kazakh, Russian and English that the signatures are inside the file, and room for 20
//! signers' boxes in two columns. Each box is that signature's widget appearance, so the
//! first signature covers the page itself and every later one covers its own box.
//!
//! A later signer's box goes into the first free spot below every signature box already on
//! the page (other apps' too, wherever they put theirs), never over one. With all 20 taken,
//! one note says the rest are inside the file; after that, signatures are invisible. A PDF
//! that was signed elsewhere first, without this page, gets an invisible signature: nothing
//! is drawn over its content.

use std::collections::BTreeMap;

use lopdf::{Dictionary, Document, Object, ObjectId, Stream};

use super::import::rect;
use super::layout::{A4, MM, Page, Writer, leading};
use super::stamp::{Drawn, widget_rects};
use crate::cert::{self, Cert};
use crate::report::SignerReport;
use crate::{Error, Result};

/// What the page says about the document.
#[derive(Clone, Debug, Default)]
pub struct WhoSigned {
    /// The document's file name, as the page names it.
    pub document: String,
}

/// The page's own key in its dictionary, so later signers find it.
const MARK: &[u8] = b"KZSG_WhoSigned";

/// Margins, mm from the page's top left.
const M: f64 = 15.0;
const GRID_TOP: f64 = 62.0;
const ROW: f64 = 18.5;
const BOX_W: f64 = 88.0;
const BOX_H: f64 = 16.5;
const GAP: f64 = 4.0;
pub const SPOTS: usize = 20;
/// The note after the 20th box.
const NOTE_TOP: f64 = GRID_TOP + (SPOTS / 2) as f64 * ROW;
const NOTE_H: f64 = 6.0;
const FOOTER_TOP: f64 = 270.0;

const HEADER: &str = "ЭЦҚ-МЕН ҚОЛ ҚОЙЫЛДЫ · ПОДПИСАНО ЭЦП · SIGNED ELECTRONICALLY";
const NCA: &str = "(ҰКО / НУЦ / NCA)";
const NOTE: &str = "Басқа қолдар файлдың ішінде · Остальные подписи внутри файла · More signatures are inside the file";

/// Spot `i` (from 0; `SPOTS` is the note): left, top, width, height in mm.
fn spot(i: usize) -> (f64, f64, f64, f64) {
    if i >= SPOTS {
        return (M, NOTE_TOP, A4.0 - 2.0 * M, NOTE_H);
    }
    let (row, col) = (i / 2, i % 2);
    (
        M + col as f64 * (BOX_W + GAP),
        GRID_TOP + row as f64 * ROW,
        BOX_W,
        BOX_H,
    )
}

/// The spot in PDF space (points from the bottom left) on a page `h` points high.
fn spot_rect(i: usize, h: f64) -> [f64; 4] {
    let (x, y, w, sh) = spot(i);
    [x * MM, h - (y + sh) * MM, (x + w) * MM, h - y * MM]
}

fn overlaps(a: &[f64; 4], b: &[f64; 4]) -> bool {
    a[0] < b[2] && b[0] < a[2] && a[1] < b[3] && b[1] < a[3]
}

/// The page that holds the boxes, if the PDF has one: (number from 1, id).
pub fn find(doc: &Document, pages: &BTreeMap<u32, ObjectId>) -> Option<(u32, ObjectId)> {
    pages.iter().rev().find_map(|(&n, &id)| {
        let p = doc.get_dictionary(id).ok()?;
        p.get(MARK).ok().map(|_| (n, id))
    })
}

/// Whether the PDF in `data` ends with a Who signed page.
pub fn ends_with_page(data: &[u8]) -> bool {
    Document::load_mem(data).is_ok_and(|d| {
        let pages = d.get_pages();
        find(&d, &pages).is_some_and(|(n, _)| n as usize == pages.len())
    })
}

/// Draws the signer's box (or the page with it, for the first signer). None: the signature
/// is invisible (the page is full, or the PDF was signed elsewhere first without one).
#[allow(clippy::too_many_arguments)]
pub fn draw(
    doc: &Document,
    pages: &BTreeMap<u32, ObjectId>,
    ws: &WhoSigned,
    c: &Cert,
    at: i64,
    nca_time: bool,
    first: bool,
    alloc: &mut dyn FnMut() -> ObjectId,
) -> Result<Option<Drawn>> {
    if first {
        return new_page(doc, pages, ws, c, at, nca_time, alloc).map(Some);
    }
    let Some((_, page_id)) = find(doc, pages) else {
        return Ok(None);
    };
    let page = doc
        .get_dictionary(page_id)
        .map_err(|e| Error::new(format!("{e}")))?;
    let h = rect(page.get(b"MediaBox").ok()).map_or(A4.1 * MM, |r| r[3] - r[1]);
    let taken = widget_rects(doc, page);
    // other apps' boxes (anything not exactly in a spot): the new box goes below them all
    let is_spot = |t: &[f64; 4]| {
        (0..=SPOTS).any(|i| {
            let s = spot_rect(i, h);
            (0..4).all(|k| (s[k] - t[k]).abs() < 1.0)
        })
    };
    let lowest_other = taken
        .iter()
        .filter(|t| !is_spot(t))
        .map(|t| t[1])
        .fold(f64::INFINITY, f64::min);
    // and after every box already there, clear of all of them
    let last = (0..=SPOTS)
        .rev()
        .find(|&i| taken.iter().any(|t| overlaps(&spot_rect(i, h), t)));
    let start = last.map_or(0, |i| i + 1);
    let Some(i) = (start..=SPOTS).find(|&i| {
        let r = spot_rect(i, h);
        r[3] <= lowest_other && !taken.iter().any(|t| overlaps(&r, t))
    }) else {
        return Ok(None);
    };
    let mut objects = Vec::new();
    let appearance = if i < SPOTS {
        signer_box(c, at, nca_time, alloc, &mut objects)
    } else {
        note_box(alloc, &mut objects)
    };
    Ok(Some(Drawn {
        page: page_id,
        rect: spot_rect(i, h),
        appearance,
        objects,
        new_page: None,
    }))
}

/// The page itself, with the first signer's box in spot 0.
fn new_page(
    doc: &Document,
    pages: &BTreeMap<u32, ObjectId>,
    ws: &WhoSigned,
    c: &Cert,
    at: i64,
    nca_time: bool,
    alloc: &mut dyn FnMut() -> ObjectId,
) -> Result<Drawn> {
    let bad = |e: lopdf::Error| Error::new(format!("{e}"));
    let n = pages.len();
    let mut objects = Vec::new();
    let mut p = Page::new(false);
    let mut w = Writer::new();
    let width = A4.0 - 2.0 * M;
    w.text(
        &mut p,
        M,
        M + leading(13.0) * 0.75,
        13.0,
        0.0,
        "Кім қол қойды · Кто подписал · Who signed",
    );
    let name: String = if ws.document.chars().count() > 80 {
        ws.document.chars().take(77).chain("...".chars()).collect()
    } else {
        ws.document.clone()
    };
    let (kk, ru, en) = if n == 1 {
        (
            "(1-бет)".to_string(),
            "(стр. 1)".to_string(),
            "page 1".to_string(),
        )
    } else {
        (
            format!("(1–{n} беттер)"),
            format!("(стр. 1–{n})"),
            format!("pages 1–{n}"),
        )
    };
    let mut y = M + 7.0;
    for t in [
        format!(
            "{name} {kk} төмендегі адамдардың ЭЦҚ-сымен қол қойылған. Бұл белгілер тек сурет. Қолтаңбалар PDF файлдың ішінде: файлды ЭЦҚ қолданбасында тексеріңіз. Басылған көшірме қол қойылған құжат емес."
        ),
        format!(
            "{name} {ru} подписан ЭЦП лицами, указанными ниже. Эти отметки только изображение. Подписи находятся внутри PDF-файла: проверьте файл в программе для ЭЦП. Распечатка не является подписанным документом."
        ),
        format!(
            "{name}, {en}, is signed electronically by the people below. These boxes are only pictures. The signatures are inside the PDF file: check the file in an e-signature app. A printout is not a signed document."
        ),
    ] {
        y = w.para(&mut p, M, y, width, 7.2, 0.25, &t) + 2.0;
    }
    if y > GRID_TOP {
        return Err(Error::new(
            "internal: the Who signed page's text is too long",
        ));
    }
    p.line(M, FOOTER_TOP, A4.0 - M, FOOTER_TOP, 0.7);
    let mut fy = FOOTER_TOP + 1.0;
    for t in [
        "Бұл бетті kzsigner жасады, тегін ЭЦҚ қолданбасы.",
        "Страница создана в kzsigner, бесплатном приложении для ЭЦП.",
        "This page was made by kzsigner, a free e-signature app.",
    ] {
        fy = w.para(&mut p, M, fy, width * 0.65, 6.0, 0.4, t);
    }
    let apps = "Android · iOS · Windows / macOS / Linux";
    let aw = w.width(apps, 6.0);
    w.text(
        &mut p,
        A4.0 - M - aw,
        FOOTER_TOP + 1.0 + leading(6.0) * 0.75,
        6.0,
        0.4,
        apps,
    );

    let font = w.font.embed(&w.used, &mut |o| {
        let id = alloc();
        objects.push((id, o));
        id
    });
    let mut content = Stream::new(Dictionary::new(), p.ops.into_bytes());
    let _ = content.compress();
    let content_id = alloc();
    objects.push((content_id, Object::Stream(content)));

    // the page joins the end of the page tree, at its root
    let root = doc.catalog().map_err(bad)?;
    let pages_id = root
        .get(b"Pages")
        .and_then(Object::as_reference)
        .map_err(bad)?;
    let mut tree = doc.get_dictionary(pages_id).map_err(bad)?.clone();
    let page_id = alloc();
    let mut kids = tree
        .get(b"Kids")
        .ok()
        .and_then(|k| doc.dereference(k).ok())
        .and_then(|(_, k)| k.as_array().ok().cloned())
        .unwrap_or_default();
    kids.push(page_id.into());
    tree.set("Kids", Object::Array(kids));
    let count = tree
        .get(b"Count")
        .and_then(Object::as_i64)
        .unwrap_or(n as i64);
    tree.set("Count", count + 1);
    objects.push((pages_id, tree.into()));

    let h = A4.1 * MM;
    let page = Dictionary::from_iter([
        ("Type", Object::from("Page")),
        ("Parent", pages_id.into()),
        (
            "MediaBox",
            Object::Array(vec![
                0.into(),
                0.into(),
                Object::Real((A4.0 * MM) as f32),
                Object::Real(h as f32),
            ]),
        ),
        (
            "Resources",
            Dictionary::from_iter([(
                "Font",
                Object::from(Dictionary::from_iter([("F1", Object::Reference(font))])),
            )])
            .into(),
        ),
        ("Contents", content_id.into()),
        ("KZSG_WhoSigned", true.into()),
    ]);
    let appearance = signer_box(c, at, nca_time, alloc, &mut objects);
    Ok(Drawn {
        page: page_id,
        rect: spot_rect(0, h),
        appearance,
        objects,
        new_page: Some(page),
    })
}

/// "ИВАНОВ АЛИБЕК" → "Иванов Алибек".
fn title_case(s: &str) -> String {
    s.split(' ')
        .map(|w| {
            let w = w.to_lowercase();
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().chain(c).collect(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A form XObject `w` x `h` mm drawn by `draw`.
fn form(
    w: f64,
    h: f64,
    draw: impl FnOnce(&mut Page, &mut Writer),
    alloc: &mut dyn FnMut() -> ObjectId,
    objects: &mut Vec<(ObjectId, Object)>,
) -> ObjectId {
    let mut p = Page {
        w,
        h,
        ops: String::new(),
        xobjects: Vec::new(),
        alpha: false,
    };
    let mut wr = Writer::new();
    draw(&mut p, &mut wr);
    let font = wr.font.embed(&wr.used, &mut |o| {
        let id = alloc();
        objects.push((id, o));
        id
    });
    let mut s = Stream::new(
        Dictionary::from_iter([
            ("Type", Object::from("XObject")),
            ("Subtype", "Form".into()),
            (
                "BBox",
                Object::Array(vec![
                    0.into(),
                    0.into(),
                    Object::Real((w * MM) as f32),
                    Object::Real((h * MM) as f32),
                ]),
            ),
            (
                "Resources",
                Dictionary::from_iter([(
                    "Font",
                    Object::from(Dictionary::from_iter([("F1", Object::Reference(font))])),
                )])
                .into(),
            ),
        ]),
        p.ops.into_bytes(),
    );
    let _ = s.compress();
    let id = alloc();
    objects.push((id, Object::Stream(s)));
    id
}

/// One signer's box: who, for whom, when.
fn signer_box(
    c: &Cert,
    at: i64,
    nca_time: bool,
    alloc: &mut dyn FnMut() -> ObjectId,
    objects: &mut Vec<(ObjectId, Object)>,
) -> ObjectId {
    let mut sr = SignerReport::default();
    cert::describe(&mut sr, c);
    let detail = match (sr.get("O"), sr.get("BIN"), sr.get("IIN")) {
        (Some(o), Some(b), _) => format!("{o} · BIN {b}"),
        (Some(o), None, _) => o.to_string(),
        (None, _, Some(i)) => format!("IIN {i}"),
        _ => String::new(),
    };
    let time = chrono::DateTime::from_timestamp_millis(at + 5 * 3600 * 1000)
        .unwrap_or_default()
        .format("%d.%m.%Y %H:%M")
        .to_string();
    let when = if nca_time {
        format!("{time} {NCA}")
    } else {
        time
    };
    let name = title_case(&sr.name());
    form(
        BOX_W,
        BOX_H,
        |p, w| {
            // a blue frame; the page shows through
            p.ops.push_str(&format!(
                "q 0.12 0.35 0.86 RG 0.8 w 0.4 0.4 {:.2} {:.2} re S Q\n",
                BOX_W * MM - 0.8,
                BOX_H * MM - 0.8
            ));
            let inner = BOX_W - 5.0;
            let mut y = 2.0;
            for l in w.wrap(HEADER, 5.4, inner).into_iter().take(2) {
                y += leading(5.4);
                w.text_rgb(p, 2.5, y - leading(5.4) * 0.25, 5.4, "0.12 0.35 0.86", &l);
            }
            for (size, grey, s) in [
                (8.0, 0.0, name.as_str()),
                (6.2, 0.3, &detail),
                (6.2, 0.3, &when),
            ] {
                if s.is_empty() {
                    continue;
                }
                if let Some(l) = w.wrap(s, size, inner).into_iter().next() {
                    y += leading(size);
                    if y > BOX_H - 1.0 {
                        break;
                    }
                    w.text(p, 2.5, y - leading(size) * 0.25, size, grey, &l);
                }
            }
        },
        alloc,
        objects,
    )
}

/// The note after the 20th box.
fn note_box(
    alloc: &mut dyn FnMut() -> ObjectId,
    objects: &mut Vec<(ObjectId, Object)>,
) -> ObjectId {
    let w = A4.0 - 2.0 * M;
    form(
        w,
        NOTE_H,
        |p, wr| {
            let lines = wr.wrap(NOTE, 6.2, w - 4.0);
            if let Some(l) = lines.first() {
                wr.text(p, 2.0, NOTE_H / 2.0 + 1.0, 6.2, 0.3, l);
            }
        },
        alloc,
        objects,
    )
}
