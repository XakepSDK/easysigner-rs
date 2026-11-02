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
