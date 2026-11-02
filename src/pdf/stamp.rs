//! A visible signature (PAdES): a stamp on a page of the signed PDF saying who signed it and
//! when, drawn as the signature widget's appearance. It is part of what the signature covers.

use lopdf::{Dictionary, Document, Object, ObjectId, Stream};

use super::import::{inherited, rect};
use super::layout::{MM, Page, Writer, leading};
use crate::cert::{self, Cert};
use crate::i18n::{Lang, tr, trf};
use crate::report::SignerReport;
use crate::{Error, Result};

/// Where a page's stamp goes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Corner {
    #[default]
    BottomRight,
    BottomLeft,
    TopRight,
    TopLeft,
}

impl Corner {
    pub fn parse(s: &str) -> Option<Corner> {
        Some(match s.to_ascii_lowercase().as_str() {
            "br" | "bottom-right" => Corner::BottomRight,
            "bl" | "bottom-left" => Corner::BottomLeft,
            "tr" | "top-right" => Corner::TopRight,
            "tl" | "top-left" => Corner::TopLeft,
            _ => return None,
        })
    }
}

/// How the stamp looks and where it goes.
#[derive(Clone, Debug, Default)]
pub struct Stamp {
    /// Page number from 1; None for the last page.
    pub page: Option<usize>,
    pub corner: Corner,
    /// The language of its texts.
    pub lang: Option<Lang>,
    /// A logo shown on its left: a JPEG or PNG file's bytes.
    pub logo: Option<Vec<u8>>,
}

/// Width of the stamp, mm.
const W: f64 = 82.0;
const PAD: f64 = 2.5;
/// Distance from the page's edges, mm.
const MARGIN: f64 = 10.0;
const LOGO: f64 = 18.0;

/// The stamp's texts: header, IIN, BIN, certificate, "valid until {}", "signed {}".
fn texts(lang: Lang) -> [&'static str; 6] {
    match lang {
        Lang::Ru => [
            "ПОДПИСАНО ЭЛЕКТРОННОЙ ЦИФРОВОЙ ПОДПИСЬЮ",
            "ИИН",
            "БИН",
            "Сертификат",
            "действителен до {}",
            "Подписано {}",
        ],
        Lang::Kk => [
            "ЭЛЕКТРОНДЫҚ ЦИФРЛЫҚ ҚОЛТАҢБАМЕН ҚОЛ ҚОЙЫЛДЫ",
            "ЖСН",
            "БСН",
            "Сертификат",
            "{} дейін жарамды",
            "Қол қойылды {}",
        ],
        Lang::En => [
            "SIGNED WITH AN ELECTRONIC DIGITAL SIGNATURE",
            "IIN",
            "BIN",
            "Certificate",
            "valid until {}",
            "Signed {}",
        ],
    }
}

/// A stamp drawn for a page: its widget rectangle and appearance, and the objects to add.
pub struct Drawn {
    pub page: ObjectId,
    pub rect: [f64; 4],
    pub appearance: ObjectId,
    pub objects: Vec<(ObjectId, Object)>,
}

/// Draws the stamp for `c`, signing at `at` (ms), onto the page `stamp` names, beside any
/// stamps already there; `alloc` gives new object ids.
pub fn draw(
    doc: &Document,
    pages: &std::collections::BTreeMap<u32, ObjectId>,
    stamp: &Stamp,
    c: &Cert,
    at: i64,
    alloc: &mut dyn FnMut() -> ObjectId,
) -> Result<Drawn> {
    let n = stamp.page.unwrap_or(pages.len());
    let page_id = *pages
        .get(&(n as u32))
        .ok_or_else(|| Error::new(trf("This PDF has no page {}.", &[&n])))?;
    let page = doc
        .get_dictionary(page_id)
        .map_err(|e| Error::new(trf("This PDF could not be read: {}", &[&e])))?;
    let bx = rect(inherited(doc, page, b"CropBox"))
        .or_else(|| rect(inherited(doc, page, b"MediaBox")))
        .unwrap_or([0.0, 0.0, 595.28, 841.89]);
    let rot = inherited(doc, page, b"Rotate")
        .and_then(|r| r.as_i64().ok())
        .unwrap_or(0)
        .rem_euclid(360);

    // the appearance, upright, in mm
    let lang = stamp.lang.unwrap_or(Lang::Ru);
    let t = texts(lang);
    let mut sr = SignerReport::default();
    cert::describe(&mut sr, c);
    let logo = stamp.logo.as_deref().map(image).transpose()?;
    let text_x = if logo.is_some() {
        PAD + LOGO + PAD
    } else {
        PAD
    };
    let text_w = W - text_x - PAD;
    let mut lines: Vec<(f64, f64, String)> = vec![(6.0, 0.3, t[0].into()), (9.0, 0.0, sr.name())];
    if let Some(iin) = sr.get("IIN") {
        lines.push((7.0, 0.0, format!("{} {iin}", t[1])));
    }
    if let Some(o) = sr.get("O") {
        let bin = sr
            .get("BIN")
            .map(|b| format!(", {} {b}", t[2]))
            .unwrap_or_default();
        lines.push((7.0, 0.0, format!("{o}{bin}")));
    }
    let until = chrono::DateTime::from_timestamp_millis(c.not_after + 5 * 3600 * 1000)
        .unwrap_or_default()
        .format("%d.%m.%Y")
        .to_string();
    lines.push((
        6.0,
        0.3,
        format!(
            "{} {}, {}",
            t[3],
            short_serial(&c.serial_hex()),
            t[4].replace("{}", &until)
        ),
    ));
    lines.push((6.0, 0.3, t[5].replace("{}", &super::card::astana(at))));
    let mut w = Writer::new();
    let mut height = PAD;
    let mut wrapped = Vec::new();
    for (size, grey, s) in &lines {
        for l in w.wrap(s, *size, text_w) {
            height += leading(*size);
            wrapped.push((*size, *grey, l));
        }
    }
    height = (height + PAD).max(if logo.is_some() {
        LOGO + 2.0 * PAD
    } else {
        0.0
    });
    let mut p = Page {
        w: W,
        h: height,
        ops: String::new(),
        xobjects: Vec::new(),
        alpha: false,
    };
    // a blue frame; the page shows through, so the stamp hides nothing
    p.ops.push_str(&format!(
        "q 0.12 0.35 0.65 RG 0.8 w 0.4 0.4 {} {} re S Q\n",
        num(W * MM - 0.8),
        num(height * MM - 0.8)
    ));
    let mut y = PAD;
    for (size, grey, l) in &wrapped {
        let lh = leading(*size);
        y += lh;
        w.text(&mut p, text_x, y - lh * 0.25, *size, *grey, l);
    }
    let mut objects = Vec::new();
    let mut resources = Dictionary::new();
    if let Some((img, smask, iw, ih)) = logo {
        let smask = smask.map(|s| {
            let id = alloc();
            objects.push((id, Object::Stream(s)));
            id
        });
        let mut img = img;
        if let Some(s) = smask {
            img.dict.set("SMask", s);
        }
        let id = alloc();
        objects.push((id, Object::Stream(img)));
        // fit the logo into its square, centred
        let scale = (LOGO / iw).min(LOGO / ih);
        let (lw, lh) = (iw * scale, ih * scale);
        let (lx, ly) = (PAD + (LOGO - lw) / 2.0, (height - lh) / 2.0);
        p.ops.push_str(&format!(
            "q {} 0 0 {} {} {} cm /Im1 Do Q\n",
            num(lw * MM),
            num(lh * MM),
            num(lx * MM),
            num(ly * MM)
        ));
        resources.set(
            "XObject",
            Dictionary::from_iter([("Im1", Object::Reference(id))]),
        );
    }
    let font = w.font.embed(&w.used, &mut |o| {
        let id = alloc();
        objects.push((id, o));
        id
    });
    resources.set(
        "Font",
        Dictionary::from_iter([("F1", Object::Reference(font))]),
    );

    // where it goes on the page as shown (rotation applied), then in the page's own space
    let [x0, y0, x1, y1] = bx;
    let (pw, ph) = if rot == 90 || rot == 270 {
        (y1 - y0, x1 - x0)
    } else {
        (x1 - x0, y1 - y0)
    };
    let (sw, sh) = (W * MM, height * MM);
    let m = MARGIN * MM;
    if sw + 2.0 * m > pw || sh + 2.0 * m > ph {
        return Err(Error::new(tr("The page is too small for the stamp.")));
    }
    let (dx, mut dy) = match stamp.corner {
        Corner::BottomRight => (pw - m - sw, m),
        Corner::BottomLeft => (m, m),
        Corner::TopRight => (pw - m - sw, ph - m - sh),
        Corner::TopLeft => (m, ph - m - sh),
    };
    // stamps already on the page, as shown: the new one goes above (or below) them
    let from_user = |x: f64, y: f64| -> (f64, f64) {
        match rot {
            90 => (y - y0, x1 - x),
            180 => (x1 - x, y1 - y),
            270 => (y1 - y, x - x0),
            _ => (x - x0, y - y0),
        }
    };
    let taken: Vec<[f64; 4]> = widget_rects(doc, page)
        .into_iter()
        .map(|[a, b, c, d]| {
            let (p, q) = from_user(a, b);
            let (r, s) = from_user(c, d);
            [p.min(r), q.min(s), p.max(r), q.max(s)]
        })
        .collect();
    let step = if matches!(stamp.corner, Corner::TopRight | Corner::TopLeft) {
        -1.0
    } else {
        1.0
    };
    while let Some(r) = taken
        .iter()
        .find(|r| dx < r[2] && dx + sw > r[0] && dy < r[3] && dy + sh > r[1])
    {
        dy = if step > 0.0 {
            r[3] + m / 2.0
        } else {
            r[1] - m / 2.0 - sh
        };
        if dy < m || dy + sh > ph - m {
            return Err(Error::new(tr(
                "There is no free room for one more stamp in that corner of the page.",
            )));
        }
    }
    let to_user = |x: f64, y: f64| -> (f64, f64) {
        match rot {
            90 => (x1 - y, y0 + x),
            180 => (x1 - x, y1 - y),
            270 => (x0 + y, y1 - x),
            _ => (x0 + x, y0 + y),
        }
    };
    let (ax, ay) = to_user(dx, dy);
    let (bx2, by2) = to_user(dx + sw, dy + sh);
    let rect = [ax.min(bx2), ay.min(by2), ax.max(bx2), ay.max(by2)];
    // the appearance turned so that it reads upright on the rotated page
    let matrix: [f64; 4] = match rot {
        90 => [0.0, 1.0, -1.0, 0.0],
        180 => [-1.0, 0.0, 0.0, -1.0],
        270 => [0.0, -1.0, 1.0, 0.0],
        _ => [1.0, 0.0, 0.0, 1.0],
    };
    let mut form = Stream::new(
        Dictionary::from_iter([
            ("Type", Object::from("XObject")),
            ("Subtype", "Form".into()),
            (
                "BBox",
                Object::Array(vec![
                    0.into(),
                    0.into(),
                    Object::Real(sw as f32),
                    Object::Real(sh as f32),
                ]),
            ),
            (
                "Matrix",
                Object::Array(
                    matrix
                        .iter()
                        .map(|&v| Object::Integer(v as i64))
                        .chain([0.into(), 0.into()])
                        .collect(),
                ),
            ),
            ("Resources", resources.into()),
        ]),
        p.ops.into_bytes(),
    );
    let _ = form.compress();
    let appearance = alloc();
    objects.push((appearance, Object::Stream(form)));
    Ok(Drawn {
        page: page_id,
        rect,
        appearance,
        objects,
    })
}

/// The rectangles of the signature widgets already on `page` that show something.
fn widget_rects(doc: &Document, page: &Dictionary) -> Vec<[f64; 4]> {
    let Some(annots) = page
        .get(b"Annots")
        .ok()
        .and_then(|a| doc.dereference(a).ok())
        .and_then(|(_, a)| a.as_array().ok())
    else {
        return Vec::new();
    };
    annots
        .iter()
        .filter_map(|a| doc.dereference(a).ok()?.1.as_dict().ok())
        .filter(|d| d.get(b"FT").ok().and_then(|f| f.as_name().ok()) == Some(b"Sig".as_slice()))
        .filter_map(|d| {
            rect(
                d.get(b"Rect")
                    .ok()
                    .and_then(|r| doc.dereference(r).ok().map(|(_, o)| o)),
            )
        })
        .filter(|r| r[2] - r[0] > 1.0 && r[3] - r[1] > 1.0)
        .collect()
}

/// A long serial number shortened for the stamp: its start and end.
fn short_serial(s: &str) -> String {
    if s.len() <= 16 {
        return s.to_string();
    }
    format!("{}…{}", &s[..8], &s[s.len() - 6..])
}

fn num(v: f64) -> String {
    let s = format!("{v:.3}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

// ------------------------------------------------------------------ the logo

/// An image XObject from a JPEG or PNG: (image, soft mask for transparency, width, height).
fn image(data: &[u8]) -> Result<(Stream, Option<Stream>, f64, f64)> {
    if data.starts_with(&[0xff, 0xd8]) {
        jpeg(data)
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        png(data)
    } else {
        Err(Error::new(tr("The logo must be a JPEG or PNG image.")))
    }
}

fn bad_logo() -> Error {
    Error::new(tr("The logo image could not be read."))
}

fn image_dict(w: u32, h: u32, color: &str) -> Dictionary {
    Dictionary::from_iter([
        ("Type", Object::from("XObject")),
        ("Subtype", "Image".into()),
        ("Width", i64::from(w).into()),
        ("Height", i64::from(h).into()),
        ("ColorSpace", color.into()),
        ("BitsPerComponent", 8.into()),
    ])
}

/// A JPEG as is (DCTDecode); its size and colours from the frame header.
fn jpeg(data: &[u8]) -> Result<(Stream, Option<Stream>, f64, f64)> {
    let mut i = 2;
    let mut adobe = false;
    while i + 9 < data.len() {
        if data[i] != 0xff {
            return Err(bad_logo());
        }
        let marker = data[i + 1];
        let len = usize::from(u16::from_be_bytes([data[i + 2], data[i + 3]]));
        // start of frame: baseline, extended or progressive
        // APP14 "Adobe": its CMYK is stored inverted
        if marker == 0xee && data.get(i + 4..i + 9) == Some(b"Adobe".as_slice()) {
            adobe = true;
        }
        if matches!(marker, 0xc0..=0xc2) {
            if data[i + 4] != 8 {
                return Err(Error::new(tr(
                    "This JPEG logo is not supported (use 8 bits per channel), or use a PNG.",
                )));
            }
            let h = u32::from(u16::from_be_bytes([data[i + 5], data[i + 6]]));
            let w = u32::from(u16::from_be_bytes([data[i + 7], data[i + 8]]));
            let color = match data[i + 9] {
                1 => "DeviceGray",
                3 => "DeviceRGB",
                4 => "DeviceCMYK",
                _ => return Err(bad_logo()),
            };
            if w == 0 || h == 0 {
                return Err(bad_logo());
            }
            let mut d = image_dict(w, h, color);
            d.set("Filter", "DCTDecode");
            if adobe && color == "DeviceCMYK" {
                d.set(
                    "Decode",
                    Object::Array([1, 0, 1, 0, 1, 0, 1, 0].map(Object::from).to_vec()),
                );
            }
            return Ok((
                Stream::new(d, data.to_vec()),
                None,
                f64::from(w),
                f64::from(h),
            ));
        }
        i += 2 + len;
    }
    Err(bad_logo())
}

/// A PNG (not interlaced; 8 bits per channel, or a palette): its pixels, and the transparency
/// as a soft mask.
fn png(data: &[u8]) -> Result<(Stream, Option<Stream>, f64, f64)> {
    use std::io::{Read, Write};
    let mut i = 8;
    let (mut w, mut h, mut kind, mut bits) = (0u32, 0u32, 0u8, 8u8);
    let (mut idat, mut palette, mut trns) = (Vec::new(), Vec::new(), Vec::new());
    while i + 8 <= data.len() {
        let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let ty = &data[i + 4..i + 8];
        let body = data.get(i + 8..i + 8 + len).ok_or_else(bad_logo)?;
        match ty {
            b"IHDR" if len >= 13 => {
                w = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                h = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                (bits, kind) = (body[8], body[9]);
                let ok = match kind {
                    0 | 2 | 4 | 6 => bits == 8,
                    3 => matches!(bits, 1 | 2 | 4 | 8),
                    _ => false,
                };
                if !ok || body[12] != 0 {
                    return Err(Error::new(tr(
                        "This PNG logo is not supported (use 8 bits per channel or a palette, not interlaced), or use a JPEG.",
                    )));
                }
            }
            b"PLTE" => palette = body.to_vec(),
            b"tRNS" => trns = body.to_vec(),
            b"IDAT" => idat.extend_from_slice(body),
            b"IEND" => break,
            _ => {}
        }
        i += 12 + len;
    }
    if w == 0 || h == 0 || w > 4096 || h > 4096 || idat.is_empty() {
        return Err(bad_logo());
    }
    let channels: usize = match kind {
        0 | 3 => 1,
        2 => 3,
        4 => 2,
        _ => 4,
    };
    let (color, colors) = if kind == 0 || kind == 4 {
        ("DeviceGray", 1)
    } else {
        ("DeviceRGB", 3)
    };
    if kind == 0 || kind == 2 {
        // the compressed rows go into the PDF as they are, with PNG's own row filters
        let mut d = image_dict(w, h, color);
        d.set("Filter", "FlateDecode");
        d.set(
            "DecodeParms",
            Dictionary::from_iter([
                ("Predictor", Object::Integer(15)),
                ("Colors", Object::Integer(colors)),
                ("BitsPerComponent", Object::Integer(8)),
                ("Columns", Object::Integer(i64::from(w))),
            ]),
        );
        return Ok((Stream::new(d, idat), None, f64::from(w), f64::from(h)));
    }
    // with transparency or a palette: the colours and the alpha channel apart
    let stride = (w as usize * channels * usize::from(bits)).div_ceil(8);
    let mut raw = Vec::new();
    flate2::read::ZlibDecoder::new(idat.as_slice())
        .take((stride as u64 + 1) * u64::from(h) + 1)
        .read_to_end(&mut raw)
        .map_err(|_| bad_logo())?;
    let bpp = (channels * usize::from(bits) / 8).max(1);
    let rows = unfilter(&raw, stride, h as usize, bpp).ok_or_else(bad_logo)?;
    let (mut rgb, mut alpha) = (Vec::new(), Vec::new());
    if kind == 3 {
        if palette.is_empty() {
            return Err(bad_logo());
        }
        let per_byte = 8 / usize::from(bits);
        let mask = ((1u16 << bits) - 1) as u8;
        for row in rows.chunks_exact(stride) {
            for x in 0..w as usize {
                let byte = row[x / per_byte];
                let shift = 8 - usize::from(bits) * (x % per_byte + 1);
                let i = usize::from((byte >> shift) & mask);
                rgb.extend_from_slice(palette.get(i * 3..i * 3 + 3).ok_or_else(bad_logo)?);
                alpha.push(trns.get(i).copied().unwrap_or(255));
            }
        }
    } else {
        for px in rows.chunks_exact(channels) {
            rgb.extend_from_slice(&px[..channels - 1]);
            alpha.push(px[channels - 1]);
        }
    }
    let color = if kind == 3 { "DeviceRGB" } else { color };
    let deflate = |b: &[u8]| -> Result<Vec<u8>> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b).map_err(|_| bad_logo())?;
        e.finish().map_err(|_| bad_logo())
    };
    let mut d = image_dict(w, h, color);
    d.set("Filter", "FlateDecode");
    let mut m = image_dict(w, h, "DeviceGray");
    m.set("Filter", "FlateDecode");
    Ok((
        Stream::new(d, deflate(&rgb)?),
        Some(Stream::new(m, deflate(&alpha)?)),
        f64::from(w),
        f64::from(h),
    ))
}

/// PNG rows with their filters undone.
fn unfilter(raw: &[u8], stride: usize, rows: usize, bpp: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; stride * rows];
    for r in 0..rows {
        let line = raw.get(r * (stride + 1)..(r + 1) * (stride + 1))?;
        let (filter, src) = (line[0], &line[1..]);
        for x in 0..stride {
            let a = if x >= bpp {
                out[r * stride + x - bpp]
            } else {
                0
            };
            let b = if r > 0 { out[(r - 1) * stride + x] } else { 0 };
            let c = if r > 0 && x >= bpp {
                out[(r - 1) * stride + x - bpp]
            } else {
                0
            };
            let pred = match filter {
                0 => 0,
                1 => a,
                2 => b,
                3 => ((u16::from(a) + u16::from(b)) / 2) as u8,
                4 => {
                    let p = i16::from(a) + i16::from(b) - i16::from(c);
                    let (pa, pb, pc) = (
                        (p - i16::from(a)).abs(),
                        (p - i16::from(b)).abs(),
                        (p - i16::from(c)).abs(),
                    );
                    if pa <= pb && pa <= pc {
                        a
                    } else if pb <= pc {
                        b
                    } else {
                        c
                    }
                }
                _ => return None,
            };
            out[r * stride + x] = src[x].wrapping_add(pred);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corners_and_serials() {
        assert_eq!(Corner::parse("TL"), Some(Corner::TopLeft));
        assert_eq!(Corner::parse("bottom-right"), Some(Corner::BottomRight));
        assert_eq!(Corner::parse("middle"), None);
        assert_eq!(short_serial("1234"), "1234");
        assert_eq!(
            short_serial("0123456789abcdef0123456789"),
            "01234567…456789"
        );
    }

    #[test]
    fn png_rows_unfiltered() {
        // two grey+alpha pixels per row; row 0 with Sub, row 1 with Up
        let raw = [1, 10, 20, 5, 5, 2, 1, 1, 1, 1];
        let out = unfilter(&raw, 4, 2, 2).unwrap();
        assert_eq!(out, [10, 20, 15, 25, 11, 21, 16, 26]);
    }
}
