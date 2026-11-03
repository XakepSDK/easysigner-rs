//! The bundled Noto Sans (Latin, Cyrillic, Kazakh) embedded in a PDF as a Type0 /
//! CIDFontType2 font (Identity-H), with a ToUnicode map so the text can be searched and copied.

use std::collections::BTreeMap;

use lopdf::{Dictionary, Object, ObjectId, Stream};

pub static NOTO_SANS: &[u8] = include_bytes!("../../assets/NotoSans-subset.ttf");

pub struct Font {
    face: ttf_parser::Face<'static>,
}

impl Font {
    pub fn noto() -> Font {
        Font {
            face: ttf_parser::Face::parse(NOTO_SANS, 0)
                .expect("the bundled font is a valid TrueType font"),
        }
    }

    fn per_1000(&self, v: i32) -> i64 {
        i64::from(v) * 1000 / i64::from(self.face.units_per_em().max(1))
    }

    /// Advance width in 1/1000 of the font size, as PDF widths are.
    pub fn width_1000(&self, g: u16) -> i64 {
        let adv = self
            .face
            .glyph_hor_advance(ttf_parser::GlyphId(g))
            .unwrap_or(0);
        self.per_1000(i32::from(adv))
    }

    /// Glyphs for `s`: characters the font lacks become `?`.
    pub fn shape(&self, s: &str) -> Vec<(u16, char)> {
        let q = self.face.glyph_index('?').map_or(0, |g| g.0);
        s.chars()
            .map(|c| match self.face.glyph_index(c) {
                Some(g) if g.0 != 0 => (g.0, c),
                _ => (q, '?'),
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
        let bb = self.face.global_bounding_box();
        let desc = add(Object::Dictionary(Dictionary::from_iter([
            ("Type", Object::from("FontDescriptor")),
            ("FontName", name.into()),
            ("Flags", 32.into()),
            (
                "FontBBox",
                Object::Array(
                    [bb.x_min, bb.y_min, bb.x_max, bb.y_max]
                        .iter()
                        .map(|&v| self.per_1000(i32::from(v)).into())
                        .collect(),
                ),
            ),
            ("ItalicAngle", 0.into()),
            (
                "Ascent",
                self.per_1000(i32::from(self.face.ascender())).into(),
            ),
            (
                "Descent",
                self.per_1000(i32::from(self.face.descender())).into(),
            ),
            (
                "CapHeight",
                self.per_1000(i32::from(self.face.capital_height().unwrap_or(714)))
                    .into(),
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
        let adv = f.face.glyph_hor_advance(ttf_parser::GlyphId(a)).unwrap();
        let upem = f.face.units_per_em();
        assert_eq!(f.width_1000(a), i64::from(adv) * 1000 / i64::from(upem));
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
