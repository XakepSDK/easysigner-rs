//! A small ASN.1 reader (DER and the BER that Kalkan and NCALayer write: indefinite lengths,
//! constructed strings) and a DER writer. Elements keep their raw bytes, so signed structures
//! can be re-hashed and copied exactly as they were.

use crate::{Error, Result};

pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const ENUMERATED: u8 = 0x0a;
pub const UTF8_STRING: u8 = 0x0c;
pub const PRINTABLE_STRING: u8 = 0x13;
pub const T61_STRING: u8 = 0x14;
pub const IA5_STRING: u8 = 0x16;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const UNIVERSAL_STRING: u8 = 0x1c;
pub const BMP_STRING: u8 = 0x1e;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

/// Context-specific tags: `[n]` constructed and primitive.
pub const fn ctx(n: u8) -> u8 {
    0xa0 | n
}
pub const fn ctx_prim(n: u8) -> u8 {
    0x80 | n
}

fn bad(what: &str) -> Error {
    Error::new(format!("malformed ASN.1: {what}"))
}

/// One element: its tag byte, its content, and its complete encoding.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The content octets (for an indefinite length: everything between header and end mark).
    pub content: &'a [u8],
    /// The whole element as encoded, header included.
    pub raw: &'a [u8],
}

/// How deep indefinite-length elements and constructed strings may nest (real files use a few
/// levels); deeper input is refused instead of exhausting the stack.
const MAX_DEPTH: usize = 64;

/// An element with no content, returned for children that are not there (see [`Items`]).
static MISSING: Tlv<'static> = Tlv {
    tag: 0,
    content: &[],
    raw: &[],
};

/// The children of a constructed element. Indexing past the end gives an empty element of tag
/// 0 instead of panicking, so reading a field that a malformed file lacks fails with an
/// ASN.1 error (wrong tag, empty content) rather than aborting the program.
#[derive(Clone, Debug, Default)]
pub struct Items<'a>(Vec<Tlv<'a>>);

impl<'a> std::ops::Deref for Items<'a> {
    type Target = [Tlv<'a>];
    fn deref(&self) -> &[Tlv<'a>] {
        &self.0
    }
}

impl<'a> std::ops::Index<usize> for Items<'a> {
    type Output = Tlv<'a>;
    fn index(&self, i: usize) -> &Tlv<'a> {
        self.0.get(i).unwrap_or(&MISSING)
    }
}

impl<'a> std::ops::Index<std::ops::RangeFrom<usize>> for Items<'a> {
    type Output = [Tlv<'a>];
    fn index(&self, r: std::ops::RangeFrom<usize>) -> &[Tlv<'a>] {
        self.0.get(r).unwrap_or(&[])
    }
}

impl<'a> IntoIterator for Items<'a> {
    type Item = Tlv<'a>;
    type IntoIter = std::vec::IntoIter<Tlv<'a>>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, 'b> IntoIterator for &'b Items<'a> {
    type Item = &'b Tlv<'a>;
    type IntoIter = std::slice::Iter<'b, Tlv<'a>>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// Reads one element from the start of `data`; returns it and the remaining bytes.
pub fn read(data: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    read_at(data, 0)
}

fn read_at(data: &[u8], depth: usize) -> Result<(Tlv<'_>, &[u8])> {
    if depth > MAX_DEPTH {
        return Err(bad("nested too deeply"));
    }
    if data.len() < 2 {
        return Err(bad("truncated"));
    }
    let tag = data[0];
    if tag & 0x1f == 0x1f {
        return Err(bad("high tag numbers are not supported"));
    }
    let first = data[1];
    let (len, hdr) = if first < 0x80 {
        (Some(first as usize), 2)
    } else if first == 0x80 {
        if tag & 0x20 == 0 {
            return Err(bad("indefinite length on a primitive element"));
        }
        (None, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n > 4 || data.len() < 2 + n {
            return Err(bad("bad length"));
        }
        let mut l = 0usize;
        for &b in &data[2..2 + n] {
            l = (l << 8) | b as usize;
        }
        (Some(l), 2 + n)
    };
    match len {
        Some(l) => {
            if data.len() - hdr < l {
                return Err(bad("truncated"));
            }
            let raw = &data[..hdr + l];
            Ok((
                Tlv {
                    tag,
                    content: &raw[hdr..],
                    raw,
                },
                &data[hdr + l..],
            ))
        }
        None => {
            // children up to the end-of-contents mark 00 00
            let mut rest = &data[hdr..];
            loop {
                if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                    break;
                }
                let (_, r) = read_at(rest, depth + 1)?;
                rest = r;
            }
            let inner = data.len() - hdr - rest.len();
            let raw = &data[..hdr + inner + 2];
            Ok((
                Tlv {
                    tag,
                    content: &data[hdr..hdr + inner],
                    raw,
                },
                &rest[2..],
            ))
        }
    }
}

/// Parses `data` as exactly one element.
pub fn parse(data: &[u8]) -> Result<Tlv<'_>> {
    let (t, rest) = read(data)?;
    if !rest.is_empty() {
        return Err(bad("trailing data"));
    }
    Ok(t)
}

impl<'a> Tlv<'a> {
    pub fn constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }

    pub fn children(&self) -> Result<Items<'a>> {
        let mut out = Vec::new();
        let mut rest = self.content;
        while !rest.is_empty() {
            let (t, r) = read(rest)?;
            out.push(t);
            rest = r;
        }
        Ok(Items(out))
    }

    pub fn expect(self, tag: u8) -> Result<Tlv<'a>> {
        if self.tag != tag {
            return Err(bad(&format!(
                "expected tag {tag:#04x}, found {:#04x}",
                self.tag
            )));
        }
        Ok(self)
    }

    /// The children of a SEQUENCE (or other constructed element with tag `tag`).
    pub fn items(self, tag: u8) -> Result<Items<'a>> {
        self.expect(tag)?.children()
    }

    /// The single element inside an EXPLICIT tag.
    pub fn inner(&self) -> Result<Tlv<'a>> {
        parse(self.content)
    }

    /// The first element inside an EXPLICIT tag, tolerating what follows it.
    pub fn inner_any(&self) -> Result<Tlv<'a>> {
        Ok(read(self.content)?.0)
    }

    /// The octets of a string type; a constructed (BER) string is joined from its pieces.
    pub fn octets(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.octets_into(&mut out, 0)?;
        Ok(out)
    }

    fn octets_into(&self, out: &mut Vec<u8>, depth: usize) -> Result<()> {
        if !self.constructed() {
            out.extend(self.content);
            return Ok(());
        }
        if depth > MAX_DEPTH {
            return Err(bad("nested too deeply"));
        }
        for c in self.children()? {
            c.octets_into(out, depth + 1)?;
        }
        Ok(())
    }

    pub fn oid(&self) -> Result<String> {
        oid_to_string(self.expect(OID)?.content)
    }

    /// INTEGER content bytes without leading zero padding (big-endian, unsigned view).
    pub fn uint(&self) -> Result<&'a [u8]> {
        let mut c = self.expect(INTEGER)?.content;
        if c.is_empty() {
            return Err(bad("empty INTEGER"));
        }
        while c.len() > 1 && c[0] == 0 {
            c = &c[1..];
        }
        Ok(c)
    }

    pub fn small_int(&self) -> Result<i64> {
        let c = self.content;
        if !(self.tag == INTEGER || self.tag == ENUMERATED) || c.is_empty() || c.len() > 8 {
            return Err(bad("expected a small INTEGER"));
        }
        let mut v: i64 = if c[0] & 0x80 != 0 { -1 } else { 0 };
        for &b in c {
            v = (v << 8) | b as i64;
        }
        Ok(v)
    }

    pub fn boolean(&self) -> Result<bool> {
        let c = self.expect(BOOLEAN)?.content;
        if c.len() != 1 {
            return Err(bad("bad BOOLEAN"));
        }
        Ok(c[0] != 0)
    }

    /// BIT STRING contents without the unused-bits byte.
    pub fn bits(&self) -> Result<&'a [u8]> {
        let c = self.expect(BIT_STRING)?.content;
        if c.is_empty() {
            return Err(bad("empty BIT STRING"));
        }
        Ok(&c[1..])
    }

    /// The text of a string element (directory strings, IA5, BMP ...), or None.
    pub fn text(&self) -> Option<String> {
        let c = self.octets().ok()?;
        Some(match self.tag & 0x1f {
            0x0c | 0x13 | 0x16 | 0x1a | 0x12 => String::from_utf8_lossy(&c).into_owned(),
            0x14 => c.iter().map(|&b| b as char).collect(),
            0x1e => {
                let u: Vec<u16> = c
                    .chunks(2)
                    .map(|p| u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)]))
                    .collect();
                String::from_utf16_lossy(&u)
            }
            0x1c => c
                .chunks(4)
                .filter(|&p| p.len() == 4)
                .map(|p| u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
                .map(|u| char::from_u32(u).unwrap_or('\u{fffd}'))
                .collect(),
            _ => return None,
        })
    }

    /// UTCTime or GeneralizedTime as milliseconds since 1970.
    pub fn time(&self) -> Result<i64> {
        crate::time::parse_asn1(self.tag, self.content)
    }

    /// The same element with DER's tag replaced (e.g. `[0] IMPLICIT SET` read as a SET).
    pub fn retagged(&self, tag: u8) -> Vec<u8> {
        let mut v = self.raw.to_vec();
        v[0] = tag;
        v
    }
}

// ------------------------------------------------------------------ OIDs

pub fn oid_to_string(c: &[u8]) -> Result<String> {
    if c.is_empty() {
        return Err(bad("empty OID"));
    }
    if c[c.len() - 1] & 0x80 != 0 {
        return Err(bad("unterminated OID"));
    }
    let mut parts: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    for &b in c {
        if v >> 57 != 0 {
            return Err(bad("OID arc too large"));
        }
        v = (v << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            parts.push(v);
            v = 0;
        }
    }
    let first = parts[0];
    let (a, b) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    let mut s = format!("{a}.{b}");
    for p in &parts[1..] {
        s.push('.');
        s.push_str(&p.to_string());
    }
    Ok(s)
}

pub fn oid_content(s: &str) -> Vec<u8> {
    let n: Vec<u64> = s
        .split('.')
        .map(|p| p.parse().expect("valid OID"))
        .collect();
    let mut out = Vec::new();
    let mut arcs = vec![n[0] * 40 + n[1]];
    arcs.extend(&n[2..]);
    for a in arcs {
        let mut tmp = vec![(a & 0x7f) as u8];
        let mut x = a >> 7;
        while x > 0 {
            tmp.push((x & 0x7f) as u8 | 0x80);
            x >>= 7;
        }
        tmp.reverse();
        out.extend(tmp);
    }
    out
}

// ------------------------------------------------------------------ DER writer

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let l = content.len();
    if l < 0x80 {
        out.push(l as u8);
    } else {
        let b = (l as u64).to_be_bytes();
        let skip = b.iter().take_while(|&&x| x == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend(&b[skip..]);
    }
    out.extend(content);
    out
}

pub fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

/// A DER SET OF: elements sorted by their encodings.
pub fn set_of(mut parts: Vec<Vec<u8>>) -> Vec<u8> {
    sorted_set(SET, &mut parts)
}

/// A DER SET OF under any tag (e.g. `[0] IMPLICIT`).
pub fn sorted_set(tag: u8, parts: &mut [Vec<u8>]) -> Vec<u8> {
    parts.sort();
    tlv(tag, &parts.concat())
}

pub fn oid(s: &str) -> Vec<u8> {
    tlv(OID, &oid_content(s))
}

pub fn null() -> Vec<u8> {
    vec![NULL, 0]
}

pub fn octets(b: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, b)
}

pub fn boolean(v: bool) -> Vec<u8> {
    vec![BOOLEAN, 1, if v { 0xff } else { 0 }]
}

/// INTEGER from unsigned big-endian bytes.
pub fn uint(be: &[u8]) -> Vec<u8> {
    let mut b = be;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    let mut c = Vec::with_capacity(b.len() + 1);
    if b.is_empty() || b[0] & 0x80 != 0 {
        c.push(0);
    }
    c.extend(b);
    tlv(INTEGER, &c)
}

pub fn small_int(v: u64) -> Vec<u8> {
    uint(&v.to_be_bytes())
}

pub fn bit_string(b: &[u8]) -> Vec<u8> {
    let mut c = vec![0];
    c.extend(b);
    tlv(BIT_STRING, &c)
}

/// AlgorithmIdentifier with NULL parameters, as NCALayer writes digest and signature algorithms.
pub fn alg_null(oid_str: &str) -> Vec<u8> {
    seq(&[&oid(oid_str), &null()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_round_trip() {
        for s in [
            "1.2.840.113549.1.7.2",
            "1.2.398.3.10.1.1.2.3.2",
            "2.5.4.3",
            "2.16.840.1.101.3.4.2.1",
        ] {
            assert_eq!(oid_to_string(&oid_content(s)).unwrap(), s);
        }
    }

    #[test]
    fn indefinite_lengths() {
        // SEQUENCE (indef) { OCTET STRING constructed (indef) { "ab", "c" } }
        let data = [
            0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0, 0, 0, 0,
        ];
        let t = parse(&data).unwrap();
        let k = t.children().unwrap();
        assert_eq!(k.len(), 1);
        assert_eq!(k[0].octets().unwrap(), b"abc");
    }

    #[test]
    fn integers() {
        assert_eq!(uint(&[0x80]), vec![2, 2, 0, 0x80]);
        assert_eq!(uint(&[0, 0, 5]), vec![2, 1, 5]);
        assert_eq!(parse(&small_int(1024)).unwrap().small_int().unwrap(), 1024);
    }

    #[test]
    fn lengths_and_tags() {
        assert_eq!(
            (ctx(0), ctx(3), ctx_prim(0), ctx_prim(2)),
            (0xa0, 0xa3, 0x80, 0x82)
        );
        for n in [0, 1, 127, 128, 255, 256, 70_000] {
            let d = octets(&vec![7u8; n]);
            let (t, rest) = read(&d).unwrap();
            assert!(
                rest.is_empty() && t.content.len() == n && t.raw == d.as_slice(),
                "{n}"
            );
            assert!(read(&d[..d.len() - 1]).is_err(), "{n}: truncated");
        }
        assert!(
            read(&[0x04, 0x85, 1, 0, 0, 0, 0]).is_err(),
            "5 length bytes"
        );
        assert!(read(&[0x04, 0x82, 1]).is_err(), "length bytes missing");
        assert!(read(&[0x04]).is_err());
        assert!(read(&[0x1f, 0x01, 0x00]).is_err(), "high tag number");
        assert!(read(&[0x04, 0x80, 0, 0]).is_err(), "indefinite primitive");
        // an indefinite element's raw bytes run to its end mark, and the rest follows
        let data = [0x30, 0x80, 0x05, 0x00, 0, 0, 0x05, 0x00];
        let (t, rest) = read(&data).unwrap();
        assert_eq!(t.raw, &data[..6]);
        assert_eq!(t.content, &data[2..4]);
        assert_eq!(rest, &data[6..]);
        // the elements of a sequence, by reference
        let s = seq(&[&null(), &null(), &boolean(false)]);
        let t = parse(&s).unwrap();
        let k = t.children().unwrap();
        assert_eq!((&k).into_iter().count(), 3);
        assert!(!k[2].boolean().unwrap() && parse(&boolean(true)).unwrap().boolean().unwrap());
        assert_eq!(k[2].retagged(0x81), vec![0x81, 1, 0]);
    }

    /// Nesting is limited, but not below the limit: indefinite lengths (each a parsing level)
    /// and constructed strings (each a joining level).
    #[test]
    fn nesting_limits() {
        let indefinite = |n: usize| {
            let mut d = [0x30, 0x80].repeat(n);
            d.extend(null());
            d.extend([0, 0].repeat(n));
            d
        };
        // the innermost element is read at depth n
        assert!(parse(&indefinite(MAX_DEPTH)).is_ok());
        assert!(parse(&indefinite(MAX_DEPTH + 1)).is_err());
        let constructed = |n: usize| {
            let mut d = octets(b"x");
            for _ in 0..n {
                d = tlv(0x24, &d);
            }
            d
        };
        assert_eq!(
            parse(&constructed(MAX_DEPTH + 1))
                .unwrap()
                .octets()
                .unwrap(),
            b"x"
        );
        assert!(
            parse(&constructed(MAX_DEPTH + 2))
                .unwrap()
                .octets()
                .is_err()
        );
    }

    #[test]
    fn length_forms() {
        // four length bytes are allowed, five are not, even for a short value
        let (t, _) = read(&[0x04, 0x84, 0, 0, 0, 1, 7]).unwrap();
        assert_eq!(t.content, &[7]);
        assert!(read(&[0x04, 0x85, 0, 0, 0, 0, 1, 7]).is_err());
        // a long-form length of zero, with nothing after it
        let (t, rest) = read(&[0x04, 0x81, 0]).unwrap();
        assert!(t.content.is_empty() && rest.is_empty());
        assert!(read(&[0x04, 0x81]).is_err());
        assert!(read(&[0x04, 0x82, 0]).is_err());
    }

    #[test]
    fn integer_values() {
        let int = |c: &[u8]| tlv(INTEGER, c);
        assert_eq!(parse(&int(&[0, 0])).unwrap().uint().unwrap(), &[0]);
        assert_eq!(parse(&int(&[0])).unwrap().uint().unwrap(), &[0]);
        assert_eq!(parse(&int(&[0, 0x80])).unwrap().uint().unwrap(), &[0x80]);
        assert!(parse(&int(&[])).unwrap().uint().is_err());
        let small = |c: &[u8]| parse(&int(c)).unwrap().small_int();
        assert_eq!(small(&[0xff]).unwrap(), -1);
        assert_eq!(small(&[0x80]).unwrap(), -128);
        assert_eq!(small(&[0x01, 0x00]).unwrap(), 256);
        assert_eq!(small(&[0x7f; 8]).unwrap(), 0x7f7f_7f7f_7f7f_7f7f);
        assert!(small(&[1; 9]).is_err() && small(&[]).is_err());
        assert_eq!(
            parse(&tlv(ENUMERATED, &[2])).unwrap().small_int().unwrap(),
            2
        );
        assert!(parse(&octets(&[2])).unwrap().small_int().is_err());
    }

    #[test]
    fn string_types() {
        let text = |tag: u8, c: &[u8]| parse(&tlv(tag, c)).unwrap().text();
        assert_eq!(text(0x0c, "Әл".as_bytes()).unwrap(), "Әл");
        assert_eq!(text(0x14, &[b'a', 0xe9]).unwrap(), "aé");
        assert_eq!(text(BMP_STRING, &[0x04, 0xd8, 0, b'a']).unwrap(), "Әa");
        assert_eq!(
            text(UNIVERSAL_STRING, &[0, 0, 0x04, 0xd8, 0, 0, 0, b'b']).unwrap(),
            "Әb"
        );
        assert!(text(OCTET_STRING, b"x").is_none());
    }

    #[test]
    fn oid_first_arcs() {
        for s in ["0.39", "1.0", "1.39", "2.0", "2.999.1"] {
            assert_eq!(oid_to_string(&oid_content(s)).unwrap(), s);
        }
    }
}
