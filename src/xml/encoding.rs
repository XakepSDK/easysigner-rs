//! The text encodings an XML document may declare: UTF-8, and the single-byte ones Kazakh
//! systems use (windows-1251, KZ-1048) and Latin-1. Decoding and encoding back give the same
//! bytes, so the signed document keeps its encoding.

use crate::i18n::{tr, trf};
use crate::{Error, Result};

/// A document's encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    /// A single-byte encoding: the characters of bytes 0x80..=0xFF.
    Single(&'static [u16; 128]),
}

/// windows-1251 (Cyrillic). The undefined byte 0x98 stands for U+0098, so it round-trips.
static CP1251: [u16; 128] = [
    0x0402, 0x0403, 0x201a, 0x0453, 0x201e, 0x2026, 0x2020, 0x2021, 0x20ac, 0x2030, 0x0409, 0x2039,
    0x040a, 0x040c, 0x040b, 0x040f, 0x0452, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
    0x0098, 0x2122, 0x0459, 0x203a, 0x045a, 0x045c, 0x045b, 0x045f, 0x00a0, 0x040e, 0x045e, 0x0408,
    0x00a4, 0x0490, 0x00a6, 0x00a7, 0x0401, 0x00a9, 0x0404, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x0407,
    0x00b0, 0x00b1, 0x0406, 0x0456, 0x0491, 0x00b5, 0x00b6, 0x00b7, 0x0451, 0x2116, 0x0454, 0x00bb,
    0x0458, 0x0405, 0x0455, 0x0457, 0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417,
    0x0418, 0x0419, 0x041a, 0x041b, 0x041c, 0x041d, 0x041e, 0x041f, 0x0420, 0x0421, 0x0422, 0x0423,
    0x0424, 0x0425, 0x0426, 0x0427, 0x0428, 0x0429, 0x042a, 0x042b, 0x042c, 0x042d, 0x042e, 0x042f,
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, 0x0438, 0x0439, 0x043a, 0x043b,
    0x043c, 0x043d, 0x043e, 0x043f, 0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,
    0x0448, 0x0449, 0x044a, 0x044b, 0x044c, 0x044d, 0x044e, 0x044f,
];

/// KZ-1048 (RK1048, СТ РК 1048-2002): windows-1251 with the Kazakh letters.
static KZ1048: [u16; 128] = [
    0x0402, 0x0403, 0x201a, 0x0453, 0x201e, 0x2026, 0x2020, 0x2021, 0x20ac, 0x2030, 0x0409, 0x2039,
    0x040a, 0x049a, 0x04ba, 0x040f, 0x0452, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014,
    0x0098, 0x2122, 0x0459, 0x203a, 0x045a, 0x049b, 0x04bb, 0x045f, 0x00a0, 0x04b0, 0x04b1, 0x04d8,
    0x00a4, 0x04e8, 0x00a6, 0x00a7, 0x0401, 0x00a9, 0x0492, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x04ae,
    0x00b0, 0x00b1, 0x0406, 0x0456, 0x04e9, 0x00b5, 0x00b6, 0x00b7, 0x0451, 0x2116, 0x0493, 0x00bb,
    0x04d9, 0x04a2, 0x04a3, 0x04af, 0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417,
    0x0418, 0x0419, 0x041a, 0x041b, 0x041c, 0x041d, 0x041e, 0x041f, 0x0420, 0x0421, 0x0422, 0x0423,
    0x0424, 0x0425, 0x0426, 0x0427, 0x0428, 0x0429, 0x042a, 0x042b, 0x042c, 0x042d, 0x042e, 0x042f,
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437, 0x0438, 0x0439, 0x043a, 0x043b,
    0x043c, 0x043d, 0x043e, 0x043f, 0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,
    0x0448, 0x0449, 0x044a, 0x044b, 0x044c, 0x044d, 0x044e, 0x044f,
];

static LATIN1: [u16; 128] = [
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, 0x0088, 0x0089, 0x008a, 0x008b,
    0x008c, 0x008d, 0x008e, 0x008f, 0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
    0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f, 0x00a0, 0x00a1, 0x00a2, 0x00a3,
    0x00a4, 0x00a5, 0x00a6, 0x00a7, 0x00a8, 0x00a9, 0x00aa, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af,
    0x00b0, 0x00b1, 0x00b2, 0x00b3, 0x00b4, 0x00b5, 0x00b6, 0x00b7, 0x00b8, 0x00b9, 0x00ba, 0x00bb,
    0x00bc, 0x00bd, 0x00be, 0x00bf, 0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,
    0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf, 0x00d0, 0x00d1, 0x00d2, 0x00d3,
    0x00d4, 0x00d5, 0x00d6, 0x00d7, 0x00d8, 0x00d9, 0x00da, 0x00db, 0x00dc, 0x00dd, 0x00de, 0x00df,
    0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5, 0x00e6, 0x00e7, 0x00e8, 0x00e9, 0x00ea, 0x00eb,
    0x00ec, 0x00ed, 0x00ee, 0x00ef, 0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7,
    0x00f8, 0x00f9, 0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff,
];

/// The encoding `input` declares (or its byte order mark): the document as text, and how to
/// write text back the same way.
pub fn decode(input: &[u8]) -> Result<(String, Encoding, &'static [u8])> {
    if let Some(rest) = input.strip_prefix(b"\xef\xbb\xbf") {
        return utf8(rest).map(|t| (t, Encoding::Utf8, &b"\xef\xbb\xbf"[..]));
    }
    if input.starts_with(b"\xff\xfe") || input.starts_with(b"\xfe\xff") {
        return Err(unsupported("UTF-16"));
    }
    let name = declared(input).unwrap_or_default().to_ascii_lowercase();
    let enc = match name.as_str() {
        "" | "utf-8" | "utf8" | "us-ascii" | "ascii" => Encoding::Utf8,
        "windows-1251" | "cp1251" | "cp-1251" | "x-cp1251" => Encoding::Single(&CP1251),
        "kz-1048" | "kz1048" | "rk1048" | "strk1048-2002" => Encoding::Single(&KZ1048),
        "iso-8859-1" | "latin1" | "latin-1" | "iso8859-1" => Encoding::Single(&LATIN1),
        other => return Err(unsupported(other)),
    };
    let text = match enc {
        Encoding::Utf8 => utf8(input)?,
        Encoding::Single(t) => input
            .iter()
            .map(|&b| {
                if b < 0x80 {
                    char::from(b)
                } else {
                    char::from_u32(u32::from(t[usize::from(b - 0x80)])).unwrap_or('\u{fffd}')
                }
            })
            .collect(),
    };
    Ok((text, enc, &[]))
}

/// `text` in `enc`. A character the encoding lacks becomes a character reference, which
/// reads back the same in text and attribute values (a signature adds only ASCII names, and the
/// document's own text was decoded from `enc`, so nothing else needs one).
pub fn encode(text: &str, enc: Encoding) -> Result<Vec<u8>> {
    let Encoding::Single(t) = enc else {
        return Ok(text.as_bytes().to_vec());
    };
    let mut back = std::collections::HashMap::with_capacity(128);
    for (i, &u) in t.iter().enumerate() {
        back.entry(u32::from(u)).or_insert(0x80 + i as u8);
    }
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        match back.get(&(c as u32)) {
            _ if (c as u32) < 0x80 => out.push(c as u8),
            Some(&b) => out.push(b),
            None => out.extend_from_slice(format!("&#x{:X};", c as u32).as_bytes()),
        }
    }
    Ok(out)
}

fn utf8(b: &[u8]) -> Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| {
        Error::new(tr(
            "This XML document is not valid UTF-8: name its encoding in the XML declaration (windows-1251, KZ-1048 or ISO-8859-1), or save it as UTF-8.",
        ))
    })
}

fn unsupported(what: &str) -> Error {
    Error::new(trf(
        "This XML document's encoding is not supported ({}): use UTF-8, windows-1251, KZ-1048 or ISO-8859-1.",
        &[&what],
    ))
}

/// The encoding named in the XML declaration, if any.
fn declared(input: &[u8]) -> Option<String> {
    let head = &input[..input.len().min(256)];
    if !head.starts_with(b"<?xml") {
        return None;
    }
    let end = head.windows(2).position(|w| w == b"?>")?;
    let decl = std::str::from_utf8(&head[..end]).ok()?;
    let i = decl.find("encoding")? + "encoding".len();
    let rest = decl[i..].trim_start().strip_prefix('=')?.trim_start();
    let q = rest.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = &rest[1..];
    Some(rest[..rest.find(q)?].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_round_trip() {
        let all: Vec<u8> = (0u8..=255).filter(|b| *b >= 0x20 || *b == b'\n').collect();
        for name in ["windows-1251", "KZ-1048", "ISO-8859-1"] {
            let mut doc = format!("<?xml version=\"1.0\" encoding=\"{name}\"?>").into_bytes();
            doc.extend_from_slice(&all);
            let (text, enc, bom) = decode(&doc).unwrap();
            assert!(bom.is_empty() && enc != Encoding::Utf8);
            assert_eq!(encode(&text, enc).unwrap(), doc, "{name}");
        }
        // Kazakh letters in KZ-1048
        let doc = b"<?xml version='1.0' encoding='kz-1048'?><a>\xd8\xe0</a>";
        let (text, ..) = decode(doc).unwrap();
        assert!(text.contains("Ша"));
        assert!(decode(b"<?xml version=\"1.0\" encoding=\"koi8-r\"?><a/>").is_err());
        assert!(decode(b"\xff\xfe<\x00").is_err());
        // a character the encoding lacks is written as a reference
        assert_eq!(
            encode("<a>Ұ</a>", enc_of("windows-1251")).unwrap(),
            b"<a>&#x4B0;</a>"
        );
        // invalid UTF-8 is refused
        assert!(decode(b"<a>\xc4</a>").is_err());
    }

    fn enc_of(name: &str) -> Encoding {
        decode(format!("<?xml version=\"1.0\" encoding=\"{name}\"?><a/>").as_bytes())
            .unwrap()
            .1
    }
}
