//! Signing one PDF in person, phone to phone: the lawyer's app holds the document and shows a QR
//! code; each signer scans it in turn, signs with their own key on their own phone, and the
//! lawyer accepts or rejects the signature by name and IIN. See docs/in-person-signing.md.
//!
//! The connection: [`session`] has the QR code's one-time key and the ISO/IEC 18013-5 session
//! encryption, over TCP on the same Wi-Fi (or one phone's hotspot); the rest of this module runs
//! over any [`Channel`]. [`pipe`] is an in-memory one, for tests.
//!
//! Strictly one signer at a time: the lawyer's app prepares the next revision of the PDF for
//! the signer's certificate, the signer signs its hash, and only an accepted signature is
//! appended. A signer without internet reaches NCA's OCSP and TSA through the lawyer's phone;
//! the requests are made and their answers checked on the signer's phone (nonces, the
//! timestamp's hash of the signature), so the lawyer can only pass them on or drop them.

mod lawyer;
pub mod session;
mod signer;
mod wire;

pub use lawyer::{Candidate, Lawyer, Served, Signed, relay_host};
pub use signer::{Copy, Offer, Outcome, Request, Signer};
pub use wire::{Ack, FORMAT, Terms};

use std::sync::mpsc;

use crate::cert::Cert;
use crate::i18n::tr;
use crate::{Error, Result, gost};

/// One end of a connection between the two phones: whole messages, in order. The apps give
/// one over the ISO/IEC 18013-5 session (already encrypted and bound to the QR).
pub trait Channel: Send {
    fn send(&mut self, msg: &[u8]) -> Result<()>;
    /// The next message; an error once the connection is gone.
    fn recv(&mut self) -> Result<Vec<u8>>;
    /// A hash of the session's transcript (18013-5's SessionTranscript), the same on both
    /// ends of one session and different for every QR: the lawyer signs it into each request,
    /// so a request can't be replayed into another session.
    fn transcript(&self) -> [u8; 32];
}

/// An in-memory connection: two ends, as two phones in one session would have.
pub fn pipe() -> (Pipe, Pipe) {
    let (a_tx, b_rx) = mpsc::channel();
    let (b_tx, a_rx) = mpsc::channel();
    let mut t = [0u8; 32];
    crate::random(&mut t).expect("the system's random numbers");
    (
        Pipe {
            tx: a_tx,
            rx: a_rx,
            transcript: t,
        },
        Pipe {
            tx: b_tx,
            rx: b_rx,
            transcript: t,
        },
    )
}

/// One end of a [`pipe`].
#[derive(Debug)]
pub struct Pipe {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    transcript: [u8; 32],
}

impl Channel for Pipe {
    fn send(&mut self, msg: &[u8]) -> Result<()> {
        self.tx.send(msg.to_vec()).map_err(|_| lost())
    }
    fn recv(&mut self) -> Result<Vec<u8>> {
        self.rx.recv().map_err(|_| lost())
    }
    fn transcript(&self) -> [u8; 32] {
        self.transcript
    }
}

fn lost() -> Error {
    Error::new(tr("The connection to the other phone was lost."))
}

/// The digest a certificate's key signs, under format 1: GOST 34.10-2015 keys only (GOST
/// 2004 signatures are only checked, never made; RSA is not used here).
pub(crate) fn digest_for(c: &Cert) -> Result<&'static str> {
    match gost::by_key(&c.key_alg()) {
        Some(s) if s.key_oid == gost::KEY_GOST2015_256 || s.key_oid == gost::KEY_GOST2015_512 => {
            Ok(s.digest_oid)
        }
        _ => Err(Error::new(tr(
            "Signing in person needs a GOST 34.10-2015 key.",
        ))),
    }
}

/// How a certificate is named in requests and acks: its GOST 34.11-2015 (256) hash.
pub(crate) fn cert_hash(der: &[u8]) -> Vec<u8> {
    gost::hash(gost::H_GOST2015_256, der).expect("a fixed, known hash")
}
