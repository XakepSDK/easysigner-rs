//! Copies the pages of a PDF into another as form XObjects, to show them inside the card.

use std::collections::HashMap;

use lopdf::{Dictionary, Document, Object, ObjectId, Stream};

use crate::{Error, Result};

/// One imported page: its form XObject and its size as displayed (points, rotation applied).
pub struct Imported {
    pub id: ObjectId,
    pub w: f64,
    pub h: f64,
}

/// A page attribute, looked up through the page tree (MediaBox, CropBox, Resources and
/// Rotate are inherited).
pub(super) fn inherited<'a>(
    src: &'a Document,
    page: &'a Dictionary,
    key: &[u8],
) -> Option<&'a Object> {
    let mut d = page;
    for _ in 0..32 {
        if let Ok(v) = d.get(key) {
            return src.dereference(v).ok().map(|(_, o)| o);
        }
        let parent = d.get(b"Parent").ok()?.as_reference().ok()?;
        d = src.get_dictionary(parent).ok()?;
    }
    None
}

pub(super) fn rect(o: Option<&Object>) -> Option<[f64; 4]> {
    let a = o?.as_array().ok()?;
    let v: Vec<f64> = a
        .iter()
        .filter_map(|x| x.as_float().ok().map(f64::from))
        .collect();
    (v.len() == 4).then(|| {
        [
            v[0].min(v[2]),
            v[1].min(v[3]),
            v[0].max(v[2]),
            v[1].max(v[3]),
        ]
    })
}

const MAX_DEPTH: usize = 256;

pub fn import_pages(src: &Document, dst: &mut Document) -> Result<Vec<Imported>> {
    let mut map = HashMap::new();
    let mut out = Vec::new();
    for (_, page_id) in src.get_pages() {
        let page = src
            .get_dictionary(page_id)
            .map_err(|e| Error::new(format!("damaged page: {e}")))?;
        let bx = rect(inherited(src, page, b"CropBox"))
            .or_else(|| rect(inherited(src, page, b"MediaBox")))
            .unwrap_or([0.0, 0.0, 595.28, 841.89]);
        let rot = inherited(src, page, b"Rotate")
            .and_then(|r| r.as_i64().ok())
            .unwrap_or(0)
            .rem_euclid(360);
        let [x0, y0, x1, y1] = bx;
        let (w, h) = (x1 - x0, y1 - y0);
        // a matrix that shows the page upright with its corner at the origin
        let (m, size) = match rot {
            90 => ([0.0, -1.0, 1.0, 0.0, -y0, x1], (h, w)),
            180 => ([-1.0, 0.0, 0.0, -1.0, x1, y1], (w, h)),
            270 => ([0.0, 1.0, -1.0, 0.0, y1, -x0], (h, w)),
            _ => ([1.0, 0.0, 0.0, 1.0, -x0, -y0], (w, h)),
        };
        let resources = inherited(src, page, b"Resources")
            .map(|r| copy(src, dst, r, &mut map, 0))
            .unwrap_or_else(|| Object::Dictionary(Dictionary::new()));
        let content = src.get_page_content(page_id);
        let dict = Dictionary::from_iter([
            ("Type", Object::from("XObject")),
            ("Subtype", "Form".into()),
            (
                "BBox",
                Object::Array(bx.iter().map(|&v| Object::Real(v as f32)).collect()),
            ),
            (
                "Matrix",
                Object::Array(m.iter().map(|&v| Object::Real(v as f32)).collect()),
            ),
            ("Resources", resources),
        ]);
        let mut s = Stream::new(dict, content);
        let _ = s.compress();
        let id = dst.add_object(s);
        out.push(Imported {
            id,
            w: size.0,
            h: size.1,
        });
    }
    Ok(out)
}

/// Copies `o` and everything it references from `src` into `dst`.
fn copy(
    src: &Document,
    dst: &mut Document,
    o: &Object,
    map: &mut HashMap<ObjectId, ObjectId>,
    depth: usize,
) -> Object {
    // a chain of references or nested objects that deep is not a real page's resources, and
    // following it could run out of stack
    if depth > MAX_DEPTH {
        return Object::Null;
    }
    let depth = depth + 1;
    match o {
        Object::Reference(id) => {
            if let Some(n) = map.get(id) {
                return Object::Reference(*n);
            }
            let n = dst.new_object_id();
            map.insert(*id, n);
            let target = src.get_object(*id).cloned().unwrap_or(Object::Null);
            let c = copy(src, dst, &target, map, depth);
            dst.objects.insert(n, c);
            Object::Reference(n)
        }
        Object::Array(a) => {
            Object::Array(a.iter().map(|x| copy(src, dst, x, map, depth)).collect())
        }
        Object::Dictionary(d) => Object::Dictionary(copy_dict(src, dst, d, map, depth)),
        Object::Stream(s) => {
            let mut c = Stream::new(copy_dict(src, dst, &s.dict, map, depth), s.content.clone());
            c.allows_compression = false;
            Object::Stream(c)
        }
        other => other.clone(),
    }
}

fn copy_dict(
    src: &Document,
    dst: &mut Document,
    d: &Dictionary,
    map: &mut HashMap<ObjectId, ObjectId>,
    depth: usize,
) -> Dictionary {
    let mut out = Dictionary::new();
    for (k, v) in d {
        // links back into the page tree would pull in the whole document
        if k == b"Parent" || k == b"P" {
            continue;
        }
        out.set(k.clone(), copy(src, dst, v, map, depth));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A document with one page per rotation, the box and rotation set on the page tree.
    fn pages(rotations: &[i64]) -> Document {
        let mut d = Document::with_version("1.7");
        let tree = d.new_object_id();
        let font = d.add_object(Dictionary::from_iter([
            ("Type", Object::from("Font")),
            ("Parent", Object::Reference(tree)),
            ("P", Object::Reference(tree)),
        ]));
        let mut kids = Vec::new();
        for &r in rotations {
            let mut p = Dictionary::from_iter([
                ("Type", Object::from("Page")),
                ("Parent", Object::Reference(tree)),
            ]);
            if r != 0 {
                p.set("Rotate", r);
            }
            kids.push(Object::Reference(d.add_object(p)));
        }
        let n = kids.len() as i64;
        d.objects.insert(
            tree,
            Object::Dictionary(Dictionary::from_iter([
                ("Type", Object::from("Pages")),
                ("Kids", Object::Array(kids)),
                ("Count", n.into()),
                (
                    "MediaBox",
                    Object::Array(vec![110.into(), 20.into(), 10.into(), 220.into()]),
                ),
                (
                    "Resources",
                    Object::Dictionary(Dictionary::from_iter([(
                        "Font",
                        Object::Dictionary(Dictionary::from_iter([
                            ("F1", Object::Reference(font)),
                            ("F2", Object::Reference(font)),
                        ])),
                    )])),
                ),
            ])),
        );
        let cat = d.add_object(Dictionary::from_iter([
            ("Type", Object::from("Catalog")),
            ("Pages", Object::Reference(tree)),
        ]));
        d.trailer.set("Root", cat);
        d
    }

    fn matrix(dst: &Document, id: ObjectId) -> Vec<f32> {
        let s = dst.get_object(id).unwrap().as_stream().unwrap();
        let m = s.dict.get(b"Matrix").unwrap().as_array().unwrap();
        m.iter().map(|v| v.as_float().unwrap()).collect()
    }

    #[test]
    fn rotated_pages_stand_upright() {
        let src = pages(&[0, 90, 180, 270, -90, 450]);
        let mut dst = Document::with_version("1.7");
        let got = import_pages(&src, &mut dst).unwrap();
        let sizes: Vec<_> = got.iter().map(|i| (i.w, i.h)).collect();
        assert_eq!(
            sizes,
            [
                (100.0, 200.0),
                (200.0, 100.0),
                (100.0, 200.0),
                (200.0, 100.0),
                (200.0, 100.0),
                (200.0, 100.0)
            ]
        );
        let m: Vec<_> = got.iter().map(|i| matrix(&dst, i.id)).collect();
        assert_eq!(m[0], [1.0, 0.0, 0.0, 1.0, -10.0, -20.0]);
        assert_eq!(m[1], [0.0, -1.0, 1.0, 0.0, -20.0, 110.0]);
        assert_eq!(m[2], [-1.0, 0.0, 0.0, -1.0, 110.0, 220.0]);
        assert_eq!(m[3], [0.0, 1.0, -1.0, 0.0, 220.0, -10.0]);
        assert_eq!(m[4], m[3], "-90 turns like 270");
        assert_eq!(m[5], m[1], "450 turns like 90");
        let bbox = dst.get_object(got[0].id).unwrap().as_stream().unwrap();
        let bbox: Vec<f32> = bbox
            .dict
            .get(b"BBox")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_float().unwrap())
            .collect();
        assert_eq!(bbox, [10.0, 20.0, 110.0, 220.0]);
    }

    #[test]
    fn resources_come_without_the_page_tree() {
        let src = pages(&[0, 0]);
        let mut dst = Document::with_version("1.7");
        let got = import_pages(&src, &mut dst).unwrap();
        let s = dst.get_object(got[0].id).unwrap().as_stream().unwrap();
        let fonts = s.dict.get(b"Resources").unwrap().as_dict().unwrap();
        let fonts = fonts.get(b"Font").unwrap().as_dict().unwrap();
        let f1 = fonts.get(b"F1").unwrap().as_reference().unwrap();
        assert_eq!(
            fonts.get(b"F2").unwrap().as_reference().unwrap(),
            f1,
            "copied once"
        );
        let f = dst.get_dictionary(f1).unwrap();
        assert!(f.has(b"Type") && !f.has(b"Parent") && !f.has(b"P"));
        // the second page shares the same copy, and only the font came along
        let s2 = dst.get_object(got[1].id).unwrap().as_stream().unwrap();
        let f2 = s2.dict.get(b"Resources").unwrap().as_dict().unwrap();
        let f2 = f2.get(b"Font").unwrap().as_dict().unwrap();
        assert_eq!(f2.get(b"F1").unwrap().as_reference().unwrap(), f1);
        assert_eq!(dst.objects.len(), 3);
    }

    #[test]
    fn inherited_attributes() {
        let src = pages(&[90]);
        let (_, id) = src.get_pages().into_iter().next().unwrap();
        let page = src.get_dictionary(id).unwrap();
        assert_eq!(
            inherited(&src, page, b"Rotate").unwrap().as_i64().unwrap(),
            90
        );
        assert!(
            inherited(&src, page, b"MediaBox").is_some(),
            "from the parent"
        );
        assert!(inherited(&src, page, b"CropBox").is_none());
    }

    #[test]
    fn copies_stop_deep_down() {
        let src = Document::with_version("1.7");
        let mut dst = Document::with_version("1.7");
        let mut map = HashMap::new();
        let mut o = Object::Integer(1);
        for _ in 1..MAX_DEPTH {
            o = Object::Array(vec![o]);
        }
        let deep = |mut o: &Object| {
            let mut n = 0;
            while let Object::Array(a) = o {
                o = &a[0];
                n += 1;
            }
            (n, o.clone())
        };
        let c = copy(&src, &mut dst, &Object::Array(vec![o.clone()]), &mut map, 0);
        assert_eq!(deep(&c), (MAX_DEPTH, Object::Integer(1)));
        let c = copy(
            &src,
            &mut dst,
            &Object::Array(vec![Object::Array(vec![o])]),
            &mut map,
            0,
        );
        assert_eq!(deep(&c), (MAX_DEPTH + 1, Object::Null));
    }
}
