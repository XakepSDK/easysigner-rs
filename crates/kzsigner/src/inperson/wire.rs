//! The messages, as bytes: a format byte, a kind byte, then the fields in order, each byte
//! string with a 4-byte length in front. The format fixes the fields and the algorithms; a
//! phone that gets a newer format than it knows says to update the app.

use crate::i18n::tr;
use crate::{Error, Result, Server};

/// The message format this app speaks.
pub const FORMAT: u8 = 1;

/// The biggest message taken: a PDF and some.
const MAX: usize = 256 * 1024 * 1024;

/// What the lawyer asks one signer to sign, signed by the lawyer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    /// The document, for this whole signing session.
    pub doc_id: [u8; 32],
    /// Which signature this is: how many the PDF had before it.
    pub slot: u32,
    /// The hash to sign: of what the new signature's byte range covers.
    pub digest: Vec<u8>,
    /// The document's name, as the lawyer's app shows it.
    pub title: String,
    /// The lawyer's certificate (DER).
    pub lawyer_cert: Vec<u8>,
    /// Whose signature this is for: the hash of the signer's certificate.
    pub signer_cert_hash: Vec<u8>,
    /// The session it was made for (see [`super::Channel::transcript`]).
    pub transcript: Vec<u8>,
    /// The signature should carry an NCA timestamp.
    pub timestamp: bool,
    /// Signing may start until then (ms since 1970, UTC); it limits nothing after that.
    pub expires: i64,
}

/// The lawyer's answer to a signature, signed by the lawyer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    pub doc_id: [u8; 32],
    pub slot: u32,
    pub signer_cert_hash: Vec<u8>,
    pub accepted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Msg {
    /// Signer: my certificate.
    Hello { cert: Vec<u8> },
    /// Lawyer: please sign; `terms` is an encoded [`Terms`], `cms` the lawyer's detached
    /// signature over it.
    Request { terms: Vec<u8>, cms: Vec<u8> },
    /// Signer: show me the file first.
    Read,
    /// Lawyer: the file, the first `master_len` bytes being the document as signed so far,
    /// then the new revision with the signature's value left empty.
    File { master_len: u64, pdf: Vec<u8> },
    /// Signer: pass this on to an NCA server, `body` empty for a GET.
    Net {
        server: Server,
        url: String,
        body: Vec<u8>,
    },
    /// Lawyer: the server's answer, or why there is none.
    NetAnswer {
        answer: std::result::Result<Vec<u8>, String>,
    },
    /// Signer: my signature (a CMS over the digest).
    Signature { cms: Vec<u8> },
    /// Signer: I won't sign.
    Cancel,
    /// Lawyer: accepted or not; `ack` an encoded [`Ack`], `cms` the lawyer's signature.
    Ack { ack: Vec<u8>, cms: Vec<u8> },
    /// Lawyer: the signed document, everyone's signatures in it.
    Final { pdf: Vec<u8> },
    /// Lawyer: nothing more to do for you now (signed, the document not finished yet).
    Done,
    /// Either side: stopping, and why.
    Refuse { why: String },
}

pub(crate) struct W(Vec<u8>);

impl W {
    pub(crate) fn new(kind: u8) -> W {
        W(vec![FORMAT, kind])
    }
    pub(crate) fn bytes(mut self, b: &[u8]) -> W {
        self.0.extend((b.len() as u32).to_be_bytes());
        self.0.extend(b);
        self
    }
    pub(crate) fn u8(mut self, v: u8) -> W {
        self.0.push(v);
        self
    }
    pub(crate) fn u32(mut self, v: u32) -> W {
        self.0.extend(v.to_be_bytes());
        self
    }
    pub(crate) fn u64(mut self, v: u64) -> W {
        self.0.extend(v.to_be_bytes());
        self
    }
    pub(crate) fn done(self) -> Vec<u8> {
        self.0
    }
}

pub(crate) struct R<'a>(&'a [u8]);

fn broken() -> Error {
    Error::new(tr("The other phone sent a message this app can't read."))
}

impl<'a> R<'a> {
    /// A reader past the format and kind bytes; the kind.
    pub(crate) fn new(b: &'a [u8]) -> Result<(R<'a>, u8)> {
        match b {
            [FORMAT, kind, rest @ ..] => Ok((R(rest), *kind)),
            [f, ..] if *f > FORMAT => Err(Error::new(tr(
                "The other phone has a newer version of the app; update this one to sign with it.",
            ))),
            _ => Err(broken()),
        }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(broken());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    pub(crate) fn text(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?).map_err(|_| broken())
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub(crate) fn id(&mut self) -> Result<[u8; 32]> {
        self.bytes()?.try_into().map_err(|_| broken())
    }
    pub(crate) fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(broken()),
        }
    }
    /// Nothing may follow the last field.
    pub(crate) fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(broken())
        }
    }
}

const TERMS: u8 = 0x40;
const ACK: u8 = 0x41;

impl Terms {
    pub fn encode(&self) -> Vec<u8> {
        W::new(TERMS)
            .bytes(&self.doc_id)
            .u32(self.slot)
            .bytes(&self.digest)
            .bytes(self.title.as_bytes())
            .bytes(&self.lawyer_cert)
            .bytes(&self.signer_cert_hash)
            .bytes(&self.transcript)
            .u8(self.timestamp as u8)
            .u64(self.expires as u64)
            .done()
    }
    pub fn parse(b: &[u8]) -> Result<Terms> {
        let (mut r, kind) = R::new(b)?;
        if kind != TERMS {
            return Err(broken());
        }
        let t = Terms {
            doc_id: r.id()?,
            slot: r.u32()?,
            digest: r.bytes()?,
            title: r.text()?,
            lawyer_cert: r.bytes()?,
            signer_cert_hash: r.bytes()?,
            transcript: r.bytes()?,
            timestamp: r.bool()?,
            expires: r.u64()? as i64,
        };
        r.end()?;
        Ok(t)
    }
}

impl Ack {
    pub fn encode(&self) -> Vec<u8> {
        W::new(ACK)
            .bytes(&self.doc_id)
            .u32(self.slot)
            .bytes(&self.signer_cert_hash)
            .u8(self.accepted as u8)
            .done()
    }
    pub fn parse(b: &[u8]) -> Result<Ack> {
        let (mut r, kind) = R::new(b)?;
        if kind != ACK {
            return Err(broken());
        }
        let a = Ack {
            doc_id: r.id()?,
            slot: r.u32()?,
            signer_cert_hash: r.bytes()?,
            accepted: r.bool()?,
        };
        r.end()?;
        Ok(a)
    }
}

fn server_code(s: Server) -> u8 {
    match s {
        Server::Timestamp => 0,
        Server::Ocsp => 1,
        Server::RevocationList => 2,
    }
}

impl Msg {
    pub(crate) fn encode(&self) -> Vec<u8> {
        match self {
            Msg::Hello { cert } => W::new(1).bytes(cert),
            Msg::Request { terms, cms } => W::new(2).bytes(terms).bytes(cms),
            Msg::Read => W::new(3),
            Msg::File { master_len, pdf } => W::new(4).u64(*master_len).bytes(pdf),
            Msg::Net { server, url, body } => W::new(5)
                .u8(server_code(*server))
                .bytes(url.as_bytes())
                .bytes(body),
            Msg::NetAnswer { answer } => match answer {
                Ok(b) => W::new(6).u8(1).bytes(b),
                Err(e) => W::new(6).u8(0).bytes(e.as_bytes()),
            },
            Msg::Signature { cms } => W::new(7).bytes(cms),
            Msg::Cancel => W::new(8),
            Msg::Ack { ack, cms } => W::new(9).bytes(ack).bytes(cms),
            Msg::Final { pdf } => W::new(10).bytes(pdf),
            Msg::Done => W::new(11),
            Msg::Refuse { why } => W::new(12).bytes(why.as_bytes()),
        }
        .done()
    }

    pub(crate) fn parse(b: &[u8]) -> Result<Msg> {
        if b.len() > MAX {
            return Err(broken());
        }
        let (mut r, kind) = R::new(b)?;
        let m = match kind {
            1 => Msg::Hello { cert: r.bytes()? },
            2 => Msg::Request {
                terms: r.bytes()?,
                cms: r.bytes()?,
            },
            3 => Msg::Read,
            4 => Msg::File {
                master_len: r.u64()?,
                pdf: r.bytes()?,
            },
            5 => Msg::Net {
                server: match r.u8()? {
                    0 => Server::Timestamp,
                    1 => Server::Ocsp,
                    2 => Server::RevocationList,
                    _ => return Err(broken()),
                },
                url: r.text()?,
                body: r.bytes()?,
            },
            6 => Msg::NetAnswer {
                answer: if r.bool()? {
                    Ok(r.bytes()?)
                } else {
                    Err(r.text()?)
                },
            },
            7 => Msg::Signature { cms: r.bytes()? },
            8 => Msg::Cancel,
            9 => Msg::Ack {
                ack: r.bytes()?,
                cms: r.bytes()?,
            },
            10 => Msg::Final { pdf: r.bytes()? },
            11 => Msg::Done,
            12 => Msg::Refuse { why: r.text()? },
            _ => return Err(broken()),
        };
        r.end()?;
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        let all = [
            Msg::Hello { cert: vec![1, 2] },
            Msg::Request {
                terms: vec![3],
                cms: vec![],
            },
            Msg::Read,
            Msg::File {
                master_len: 7,
                pdf: vec![9; 10],
            },
            Msg::Net {
                server: Server::Ocsp,
                url: "http://ocsp.pki.gov.kz/".into(),
                body: vec![1],
            },
            Msg::NetAnswer {
                answer: Ok(vec![2]),
            },
            Msg::NetAnswer {
                answer: Err("down".into()),
            },
            Msg::Signature { cms: vec![5] },
            Msg::Cancel,
            Msg::Ack {
                ack: vec![1],
                cms: vec![2],
            },
            Msg::Final { pdf: vec![3] },
            Msg::Done,
            Msg::Refuse { why: "no".into() },
        ];
        for m in all {
            assert_eq!(Msg::parse(&m.encode()).unwrap(), m);
        }
        let t = Terms {
            doc_id: [7; 32],
            slot: 2,
            digest: vec![1; 32],
            title: "Договор".into(),
            lawyer_cert: vec![3; 5],
            signer_cert_hash: vec![4; 32],
            transcript: vec![5; 32],
            timestamp: true,
            expires: 1_800_000_000_000,
        };
        assert_eq!(Terms::parse(&t.encode()).unwrap(), t);
        let a = Ack {
            doc_id: [1; 32],
            slot: 0,
            signer_cert_hash: vec![2; 32],
            accepted: false,
        };
        assert_eq!(Ack::parse(&a.encode()).unwrap(), a);
        // terms are not an ack, and nothing may trail
        assert!(Ack::parse(&t.encode()).is_err());
        let mut long = a.encode();
        long.push(0);
        assert!(Ack::parse(&long).is_err());
    }

    #[test]
    fn a_newer_format_says_to_update() {
        let mut m = Msg::Read.encode();
        m[0] = FORMAT + 1;
        let e = Msg::parse(&m).unwrap_err().to_string();
        assert!(e.contains("newer version"), "{e}");
        assert!(Msg::parse(&[FORMAT, 99]).is_err());
        assert!(Msg::parse(&[]).is_err());
    }
}
