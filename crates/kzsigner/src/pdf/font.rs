//! The bundled Noto Sans (Latin, Cyrillic, Kazakh) embedded in a PDF as a Type0 /
//! CIDFontType2 font (Identity-H), with a ToUnicode map so the text can be searched and copied.

use std::collections::BTreeMap;

use lopdf::{Dictionary, Object, ObjectId, Stream};
use skrifa::instance::{LocationRef, Size};
use skrifa::metrics::{GlyphMetrics, Metrics};
use skrifa::{FontRef, GlyphId, MetadataProvider};

pub static NOTO_SANS: &[u8] = include_bytes!("../../../../assets/NotoSans-subset.ttf");

pub struct Font {
    font: FontRef<'static>,
    /// Font-wide metrics in font units.
    metrics: Metrics,
}

impl Font {
    pub fn noto() -> Font {
        #[allow(clippy::expect_used)] // the font is compiled in and tested
        let font = FontRef::new(NOTO_SANS).expect("the bundled font is a valid TrueType font");
        let metrics = font.metrics(Size::unscaled(), LocationRef::default());
        Font { font, metrics }
    }

    fn glyph_metrics(&self) -> GlyphMetrics<'static> {
        self.font
            .glyph_metrics(Size::unscaled(), LocationRef::default())
    }

    /// `v` font units in 1/1000 of the font size, as PDF measures are.
    fn per_1000(&self, v: f32) -> i64 {
        (f64::from(v) * 1000.0 / f64::from(self.metrics.units_per_em.max(1))).trunc() as i64
    }

    /// Advance width in font units.
    fn advance(&self, g: u16) -> f32 {
        self.glyph_metrics()
            .advance_width(GlyphId::from(g))
            .unwrap_or(0.0)
    }

    /// Advance width in 1/1000 of the font size, as PDF widths are.
    pub fn width_1000(&self, g: u16) -> i64 {
        self.per_1000(self.advance(g))
    }

    fn glyph(&self, c: char) -> Option<u16> {
        let g = self.font.charmap().map(c)?.to_u32();
        u16::try_from(g).ok().filter(|&g| g != 0)
    }

    /// Glyphs for `s`: characters the font lacks become `?`.
    pub fn shape(&self, s: &str) -> Vec<(u16, char)> {
        let q = self.glyph('?').unwrap_or(0);
        s.chars()
            .map(|c| match self.glyph(c) {
                Some(g) => (g, c),
                None => (q, '?'),
            })
            .collect()
    }

    pub fn text_width(&self, s: &str, size: f64) -> f64 {
        self.shape(s)
            .iter()
            .map(|(g, _)| self.width_1000(*g) as f64)
            .sum::<f64>()
            * size
            / 1000.0
    }

    /// The font objects, added with `add`; returns the Type0 font's id. `used`: the glyphs
    /// shown, with their characters.
    pub fn embed(
        &self,
        used: &BTreeMap<u16, char>,
        add: &mut dyn FnMut(Object) -> ObjectId,
    ) -> ObjectId {
        let mut file = Stream::new(
            Dictionary::from_iter([("Length1", Object::Integer(NOTO_SANS.len() as i64))]),
            NOTO_SANS.to_vec(),
        );
        let _ = file.compress();
        let file = add(Object::Stream(file));
        let name = "KZSIGN+NotoSans";
        let m = &self.metrics;
        let bb = m.bounds.unwrap_or_default();
        let desc = add(Object::Dictionary(Dictionary::from_iter([
            ("Type", Object::from("FontDescriptor")),
            ("FontName", name.into()),
            ("Flags", 32.into()),
            (
                "FontBBox",
                Object::Array(
                    [bb.x_min, bb.y_min, bb.x_max, bb.y_max]
                        .iter()
                        .map(|&v| self.per_1000(v).into())
                        .collect(),
                ),
            ),
            ("ItalicAngle", 0.into()),
            ("Ascent", self.per_1000(m.ascent).into()),
            ("Descent", self.per_1000(m.descent).into()),
            (
                "CapHeight",
                self.per_1000(m.cap_height.unwrap_or(714.0)).into(),
            ),
            ("StemV", 80.into()),
            ("FontFile2", file.into()),
        ])));
        let mut w = Vec::new();
        for g in used.keys() {
            w.push(Object::Integer(i64::from(*g)));
            w.push(Object::Array(vec![self.width_1000(*g).into()]));
        }
        let cid = add(Object::Dictionary(Dictionary::from_iter([
            ("Type", Object::from("Font")),
            ("Subtype", "CIDFontType2".into()),
            ("BaseFont", name.into()),
            (
                "CIDSystemInfo",
                Object::Dictionary(Dictionary::from_iter([
                    ("Registry", Object::string_literal("Adobe")),
                    ("Ordering", Object::string_literal("Identity")),
                    ("Supplement", 0.into()),
                ])),
            ),
            ("FontDescriptor", desc.into()),
            ("W", Object::Array(w)),
            ("CIDToGIDMap", "Identity".into()),
        ])));
        let to_unicode = add(Object::Stream(Stream::new(
            Dictionary::new(),
            to_unicode(used),
        )));
        add(Object::Dictionary(Dictionary::from_iter([
            ("Type", Object::from("Font")),
            ("Subtype", "Type0".into()),
            ("BaseFont", name.into()),
            ("Encoding", "Identity-H".into()),
            ("DescendantFonts", Object::Array(vec![cid.into()])),
            ("ToUnicode", to_unicode.into()),
        ])))
    }
}

fn to_unicode(used: &BTreeMap<u16, char>) -> Vec<u8> {
    let mut s = String::from(
        "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
         /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
         /CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n\
         1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
    );
    let pairs: Vec<_> = used.iter().collect();
    for chunk in pairs.chunks(100) {
        s.push_str(&format!("{} beginbfchar\n", chunk.len()));
        for (g, c) in chunk {
            let mut units = [0u16; 2];
            let hex: String = c
                .encode_utf16(&mut units)
                .iter()
                .map(|u| format!("{u:04X}"))
                .collect();
            s.push_str(&format!("<{g:04X}> <{hex}>\n"));
        }
        s.push_str("endbfchar\n");
    }
    s.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
    s.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_font_has_kazakh_letters() {
        let f = Font::noto();
        for (c, (_, got)) in "AzАяӘәҒғҚқҢңӨөҰұҮүҺһІі№"
            .chars()
            .zip(f.shape("AzАяӘәҒғҚқҢңӨөҰұҮүҺһІі№"))
        {
            assert_eq!(c, got);
        }
        assert!(f.text_width("Қазақстан", 10.0) > 30.0);
        assert_eq!(f.shape("✈")[0].1, '?');
    }

    #[test]
    fn widths() {
        let f = Font::noto();
        let a = f.shape("A")[0].0;
        let adv = f.advance(a) as i64;
        let upem = i64::from(f.metrics.units_per_em);
        assert_eq!(upem, 1000);
        assert_eq!(f.width_1000(a), adv * 1000 / upem);
        assert!(f.width_1000(a) > 100 && f.width_1000(a) < 1000);
        let w = f.width_1000(a) as f64;
        assert_eq!(f.text_width("AA", 12.0), 2.0 * w * 12.0 / 1000.0);
    }

    #[test]
    fn embedded_objects() {
        let f = Font::noto();
        let used: BTreeMap<u16, char> = f.shape("Aә😀").into_iter().collect();
        let mut objs = Vec::new();
        let id = f.embed(&used, &mut |o| {
            objs.push(o);
            (objs.len() as u32, 0)
        });
        assert_eq!(id, (objs.len() as u32, 0), "the Type0 font comes last");
        let top = objs.last().unwrap().as_dict().unwrap();
        assert_eq!(top.get(b"Subtype").unwrap().as_name().unwrap(), b"Type0");

        let cmap = String::from_utf8(to_unicode(&used)).unwrap();
        let ga = f.shape("A")[0].0;
        assert!(cmap.contains(&format!("<{ga:04X}> <0041>\n")), "{cmap}");
        let many: BTreeMap<u16, char> = (1..=150u16).map(|g| (g, 'x')).collect();
        let cmap = String::from_utf8(to_unicode(&many)).unwrap();
        assert!(cmap.contains("100 beginbfchar\n") && cmap.contains("50 beginbfchar\n"));
        assert!(cmap.contains("<0096> <0078>\n"));
        let pair: BTreeMap<u16, char> = [(7u16, '😀')].into_iter().collect();
        assert!(
            String::from_utf8(to_unicode(&pair))
                .unwrap()
                .contains("<0007> <D83DDE00>\n")
        );
    }
}
