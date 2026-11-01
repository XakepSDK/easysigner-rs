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

/// Reads one element from the start of `data`; returns it and the remaining bytes.
pub fn read(data: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
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
            Ok((Tlv { tag, content: &raw[hdr..], raw }, &data[hdr + l..]))
        }
        None => {
            // children up to the end-of-contents mark 00 00
            let mut rest = &data[hdr..];
            loop {
                if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                    break;
                }
                let (_, r) = read(rest)?;
                rest = r;
            }
            let inner = data.len() - hdr - rest.len();
            let raw = &data[..hdr + inner + 2];
            Ok((Tlv { tag, content: &data[hdr..hdr + inner], raw }, &rest[2..]))
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

    pub fn children(&self) -> Result<Vec<Tlv<'a>>> {
        let mut out = Vec::new();
        let mut rest = self.content;
        while !rest.is_empty() {
            let (t, r) = read(rest)?;
            out.push(t);
            rest = r;
        }
        Ok(out)
    }

    pub fn expect(self, tag: u8) -> Result<Tlv<'a>> {
        if self.tag != tag {
            return Err(bad(&format!("expected tag {tag:#04x}, found {:#04x}", self.tag)));
        }
        Ok(self)
    }

    /// The children of a SEQUENCE (or other constructed element with tag `tag`).
    pub fn items(self, tag: u8) -> Result<Vec<Tlv<'a>>> {
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
        if !self.constructed() {
            return Ok(self.content.to_vec());
        }
        let mut out = Vec::new();
        for c in self.children()? {
            out.extend(c.octets()?);
        }
        Ok(out)
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
                let u: Vec<u16> =
                    c.chunks(2).map(|p| u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)])).collect();
                String::from_utf16_lossy(&u)
            }
            0x1c => c
                .chunks(4)
                .filter_map(|p| {
                    (p.len() == 4).then(|| u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
                })
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
    let mut parts: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    for &b in c {
        v = (v << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            parts.push(v);
            v = 0;
        }
    }
    let first = parts[0];
    let (a, b) = if first < 40 { (0, first) } else if first < 80 { (1, first - 40) } else { (2, first - 80) };
    let mut s = format!("{a}.{b}");
    for p in &parts[1..] {
        s.push('.');
        s.push_str(&p.to_string());
    }
    Ok(s)
}

pub fn oid_content(s: &str) -> Vec<u8> {
    let n: Vec<u64> = s.split('.').map(|p| p.parse().expect("valid OID")).collect();
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
        for s in ["1.2.840.113549.1.7.2", "1.2.398.3.10.1.1.2.3.2", "2.5.4.3", "2.16.840.1.101.3.4.2.1"] {
            assert_eq!(oid_to_string(&oid_content(s)).unwrap(), s);
        }
    }

    #[test]
    fn indefinite_lengths() {
        // SEQUENCE (indef) { OCTET STRING constructed (indef) { "ab", "c" } }
        let data = [0x30, 0x80, 0x24, 0x80, 0x04, 0x02, b'a', b'b', 0x04, 0x01, b'c', 0, 0, 0, 0];
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
}
