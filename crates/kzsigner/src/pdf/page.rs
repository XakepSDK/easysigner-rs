//! Page attributes read through the page tree.

use lopdf::{Dictionary, Document, Object};

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
}
