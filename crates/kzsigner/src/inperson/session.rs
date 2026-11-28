//! The connection between the two phones, as ISO/IEC 18013-5 (the mobile driving licence and
//! the EU wallet's in-person standard) builds it: the lawyer's phone shows a QR code with a
//! one-time P-256 key and where to reach it; the signer's phone connects, sends its own one-time
//! key, and both derive the session keys from the two (ECDH, then HKDF-SHA-256 over the
//! session's transcript, "SKReader" and "SKDevice"); every message after that is AES-256-GCM
//! with 18013-5's nonces (an 8-byte sender id, then a 4-byte counter from 1).
//!
//! The scheme and the key names are 18013-5's; the messages are this app's own (the session
//! carries [`super::Channel`] messages, not CBOR mdoc requests). The transport is any byte
//! stream: TCP on the same Wi-Fi network (or the lawyer's hotspot), or a socket the app made
//! over Wi-Fi Aware.
//!
//! Who is who: the lawyer's phone plays 18013-5's mdoc (it shows the QR), the signer's its
//! reader. Only the lawyer's phone is authenticated by the session (its key is in the QR the
//! signer scanned with their own eyes on it); the signer is whoever holds the certificate they
//! sign with.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::Channel;
use crate::i18n::tr;
use crate::{Error, Result};

/// What a QR code starts with.
const SCHEME: &str = "KZSIGN1:";
/// The QR's own format.
const QR_FORMAT: u8 = 1;
/// The largest message on the wire: a PDF and some.
const MAX_FRAME: usize = 256 * 1024 * 1024;
/// How long connecting to an address in the QR may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// Where the lawyer's phone can be reached, as the QR says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hint {
    /// TCP to "address:port" on the same network.
    Tcp(String),
    /// A Wi-Fi Aware service, by name (the app connects and hands over the socket).
    Aware(String),
}

/// What the QR holds: the lawyer's one-time key and where to reach the phone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Engagement {
    /// The lawyer's one-time public key (SEC1, compressed).
    pub key: Vec<u8>,
    pub hints: Vec<Hint>,
    /// The QR's bytes as scanned: they go into the transcript.
    raw: Vec<u8>,
}

impl Engagement {
    fn encode(key: &[u8], hints: &[Hint]) -> Vec<u8> {
        let mut b = vec![QR_FORMAT, key.len() as u8];
        b.extend(key);
        b.push(hints.len() as u8);
        for h in hints {
            let (kind, s) = match h {
                Hint::Tcp(s) => (1u8, s),
                Hint::Aware(s) => (2u8, s),
            };
            b.push(kind);
            b.push(s.len().min(255) as u8);
            b.extend(&s.as_bytes()[..s.len().min(255)]);
        }
        b
    }

    /// The QR code's text.
    pub fn qr(&self) -> String {
        format!(
            "{SCHEME}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.raw)
        )
    }

    /// Reads a scanned QR code; an error when it is not this app's.
    pub fn parse(qr: &str) -> Result<Engagement> {
        let bad = || {
            Error::new(tr(
                "This QR code is not a signing invitation from kzsigner.",
            ))
        };
        let b64 = qr.trim().strip_prefix(SCHEME).ok_or_else(bad)?;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| bad())?;
        let mut r = &raw[..];
        let mut take = |n: usize| -> Result<&[u8]> {
            if r.len() < n {
                return Err(bad());
            }
            let (a, b) = r.split_at(n);
            r = b;
            Ok(a)
        };
        if take(1)?[0] != QR_FORMAT {
            return Err(Error::new(tr(
                "The other phone has a newer version of the app; update this one to sign with it.",
            )));
        }
        let n = take(1)?[0] as usize;
        let key = take(n)?.to_vec();
        PublicKey::from_sec1_bytes(&key).map_err(|_| bad())?;
        let count = take(1)?[0];
        let mut hints = Vec::new();
        for _ in 0..count {
            let kind = take(1)?[0];
            let n = take(1)?[0] as usize;
            let s = String::from_utf8(take(n)?.to_vec()).map_err(|_| bad())?;
            match kind {
                1 => hints.push(Hint::Tcp(s)),
                2 => hints.push(Hint::Aware(s)),
                _ => {} // a newer way to connect: this app uses the others
            }
        }
        Ok(Engagement { key, hints, raw })
    }
}

/// The lawyer's side of one QR code: its one-time key. One invitation serves one signer.
pub struct Invitation {
    secret: SecretKey,
    pub engagement: Engagement,
}

impl Invitation {
    /// A new one-time key, reachable as `hints` say.
    pub fn new(hints: Vec<Hint>) -> Result<Invitation> {
        let secret = loop {
            let mut b = Zeroizing::new([0u8; 32]);
            crate::random(&mut b[..])?;
            if let Ok(k) = SecretKey::from_slice(&b[..]) {
                break k;
            }
        };
        let key = secret.public_key().to_sec1_point(true).as_bytes().to_vec();
        let raw = Engagement::encode(&key, &hints);
        Ok(Invitation {
            secret,
            engagement: Engagement { key, hints, raw },
        })
    }

    /// The session over `stream`, once the signer's phone sent its key.
    pub fn accept<S: Read + Write + Send>(self, mut stream: S) -> Result<Secure<S>> {
        let peer = read_frame(&mut stream, 65)?;
        let peer_key = parse_key(&peer)?;
        Secure::new(
            stream,
            &self.secret,
            &peer_key,
            &self.engagement.raw,
            &peer,
            Role::Mdoc,
        )
    }
}

/// The signer's side: connects to the phone that showed `qr` over `stream`.
pub fn join<S: Read + Write + Send>(qr: &Engagement, mut stream: S) -> Result<Secure<S>> {
    let secret = Invitation::new(vec![])?.secret;
    let mine = secret.public_key().to_sec1_point(true).as_bytes().to_vec();
    write_frame(&mut stream, &mine)?;
    let lawyer = parse_key(&qr.key)?;
    Secure::new(stream, &secret, &lawyer, &qr.raw, &mine, Role::Reader)
}

/// The signer's side over TCP: tries each address in the QR.
pub fn join_tcp(qr: &Engagement) -> Result<Secure<TcpStream>> {
    let mut last = None;
    #[allow(unused_assignments)]
    for h in &qr.hints {
        let Hint::Tcp(a) = h else { continue };
        let Ok(addrs) = a.to_socket_addrs() else {
            continue;
        };
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(s) => {
                    s.set_nodelay(true).ok();
                    return join(qr, s);
                }
                Err(e) => last = Some(e),
            }
        }
    }
    let _ = last;
    Err(Error::new(tr(
        "Can't reach the lawyer's phone: both phones must be on the same Wi-Fi.",
    )))
}

/// A TCP port on the lawyer's phone that waits for one signer at a time.
pub struct Door {
    listener: TcpListener,
    stop: Arc<AtomicBool>,
}

impl Door {
    /// Opens a port on every network of the phone (the system picks the number).
    pub fn open() -> Result<Door> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .map_err(|e| Error::new(format!("could not open a port: {e}")))?;
        listener.set_nonblocking(true).ok();
        Ok(Door {
            listener,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Stops [`Door::wait`] from another thread.
    pub fn stopper(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    /// The next phone to connect; None once stopped.
    pub fn wait(&self) -> Result<Option<(TcpStream, SocketAddr)>> {
        self.stop.store(false, Ordering::SeqCst);
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return Ok(None);
            }
            match self.listener.accept() {
                Ok((s, a)) => {
                    s.set_nonblocking(false).ok();
                    s.set_nodelay(true).ok();
                    return Ok(Some((s, a)));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(Error::new(format!("could not accept: {e}"))),
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The lawyer's phone (shows the QR).
    Mdoc,
    /// The signer's phone (scans it).
    Reader,
}

/// The encrypted session: a [`Channel`] over `S`.
pub struct Secure<S> {
    stream: S,
    send_key: Aes256Gcm,
    recv_key: Aes256Gcm,
    send_id: [u8; 8],
    recv_id: [u8; 8],
    sent: u32,
    received: u32,
    transcript: [u8; 32],
}

impl<S: Read + Write + Send> Secure<S> {
    fn new(
        stream: S,
        mine: &SecretKey,
        theirs: &PublicKey,
        qr: &[u8],
        reader_key: &[u8],
        role: Role,
    ) -> Result<Secure<S>> {
        let shared = p256::ecdh::diffie_hellman(mine.to_nonzero_scalar(), theirs.as_affine());
        // the transcript: the QR as scanned and the reader's key, as 18013-5's
        // SessionTranscript holds the engagement and the reader's key
        let mut h = Sha256::new();
        h.update((qr.len() as u32).to_be_bytes());
        h.update(qr);
        h.update(reader_key);
        let transcript: [u8; 32] = h.finalize().into();
        let derive = |info: &[u8]| -> Result<Aes256Gcm> {
            let hk = hkdf::Hkdf::<Sha256>::new(Some(&transcript), shared.raw_secret_bytes());
            let mut k = Zeroizing::new([0u8; 32]);
            hk.expand(info, &mut k[..])
                .map_err(|_| Error::new("internal: session key"))?;
            Aes256Gcm::new_from_slice(&k[..]).map_err(|_| Error::new("internal: session key"))
        };
        let reader = derive(b"SKReader")?;
        let device = derive(b"SKDevice")?;
        const READER: [u8; 8] = [0; 8];
        const DEVICE: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];
        let (send_key, recv_key, send_id, recv_id) = match role {
            Role::Reader => (reader, device, READER, DEVICE),
            Role::Mdoc => (device, reader, DEVICE, READER),
        };
        Ok(Secure {
            stream,
            send_key,
            recv_key,
            send_id,
            recv_id,
            sent: 0,
            received: 0,
            transcript,
        })
    }

    /// The stream underneath (to shut a socket down from another thread, say).
    pub fn stream(&self) -> &S {
        &self.stream
    }
}

fn nonce(id: &[u8; 8], counter: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(id);
    n[8..].copy_from_slice(&counter.to_be_bytes());
    n
}

impl<S: Read + Write + Send> Channel for Secure<S> {
    fn send(&mut self, msg: &[u8]) -> Result<()> {
        self.sent = self.sent.checked_add(1).ok_or_else(lost)?;
        let n = nonce(&self.send_id, self.sent);
        let c = self
            .send_key
            .encrypt(&Nonce::from(n), Payload { msg, aad: &[] })
            .map_err(|_| Error::new("internal: encrypt"))?;
        write_frame(&mut self.stream, &c)
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        let c = read_frame(&mut self.stream, MAX_FRAME)?;
        self.received = self.received.checked_add(1).ok_or_else(lost)?;
        let n = nonce(&self.recv_id, self.received);
        // a message changed, dropped, replayed or reordered on the way fails here
        self.recv_key
            .decrypt(&Nonce::from(n), Payload { msg: &c, aad: &[] })
            .map_err(|_| {
                Error::new(tr(
                    "The connection to the other phone was tampered with; start again.",
                ))
            })
    }

    fn transcript(&self) -> [u8; 32] {
        self.transcript
    }
}

fn lost() -> Error {
    Error::new(tr("The connection to the other phone was lost."))
}

fn parse_key(b: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(b).map_err(|_| lost())
}

fn write_frame<W: Write>(w: &mut W, b: &[u8]) -> Result<()> {
    let n = u32::try_from(b.len()).map_err(|_| lost())?;
    w.write_all(&n.to_be_bytes())
        .and_then(|_| w.write_all(b))
        .and_then(|_| w.flush())
        .map_err(|_| lost())
}

fn read_frame<R: Read>(r: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut n = [0u8; 4];
    r.read_exact(&mut n).map_err(|_| lost())?;
    let n = u32::from_be_bytes(n) as usize;
    if n > max {
        return Err(lost());
    }
    // read in pieces: a length is only a claim until the bytes arrive
    let mut b = Vec::with_capacity(n.min(1 << 20));
    r.take(n as u64).read_to_end(&mut b).map_err(|_| lost())?;
    if b.len() != n {
        return Err(lost());
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_round_trip_and_junk() {
        let inv = Invitation::new(vec![
            Hint::Tcp("192.168.1.20:41234".into()),
            Hint::Aware("kzsign-1".into()),
        ])
        .unwrap();
        let qr = inv.engagement.qr();
        assert!(qr.starts_with("KZSIGN1:"));
        assert_eq!(Engagement::parse(&qr).unwrap(), inv.engagement);
        assert!(Engagement::parse("https://example.com").is_err());
        assert!(Engagement::parse("KZSIGN1:AAAA").is_err());
        assert!(Engagement::parse(&qr[..qr.len() - 4]).is_err());
    }

    #[test]
    fn a_session_over_tcp_and_what_breaks_it() {
        let door = Door::open().unwrap();
        let inv = Invitation::new(vec![Hint::Tcp(format!("127.0.0.1:{}", door.port()))]).unwrap();
        let qr = Engagement::parse(&inv.engagement.qr()).unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = door.wait().unwrap().unwrap();
            let mut ch = inv.accept(s).unwrap();
            let m = ch.recv().unwrap();
            ch.send(&[m, b" back".to_vec()].concat()).unwrap();
            ch.transcript()
        });
        let mut ch = join_tcp(&qr).unwrap();
        ch.send(b"hello").unwrap();
        assert_eq!(ch.recv().unwrap(), b"hello back");
        assert_eq!(t.join().unwrap(), ch.transcript());

        // someone else's QR key: the two sides don't agree and nothing decrypts
        let door = Door::open().unwrap();
        let inv = Invitation::new(vec![Hint::Tcp(format!("127.0.0.1:{}", door.port()))]).unwrap();
        let other = Invitation::new(vec![Hint::Tcp(format!("127.0.0.1:{}", door.port()))]).unwrap();
        let qr = Engagement::parse(&other.engagement.qr()).unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = door.wait().unwrap().unwrap();
            let mut ch = inv.accept(s).unwrap();
            ch.recv().is_err()
        });
        let mut ch = join_tcp(&qr).unwrap();
        ch.send(b"hello").unwrap();
        assert!(t.join().unwrap());
    }

    #[test]
    fn a_changed_or_replayed_frame_fails() {
        // the two ends over an in-memory stream, with the bytes in between in reach
        #[derive(Clone, Default)]
        struct Wire(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Read for Wire {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let mut v = self.0.lock().unwrap();
                let n = buf.len().min(v.len());
                buf[..n].copy_from_slice(&v[..n]);
                v.drain(..n);
                Ok(n)
            }
        }
        impl Write for Wire {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let inv = Invitation::new(vec![]).unwrap();
        let qr = Engagement::parse(&inv.engagement.qr()).unwrap();
        let w = Wire::default();
        let mut signer = join(&qr, w.clone()).unwrap();
        let mut lawyer = inv.accept(w.clone()).unwrap();
        signer.send(b"one").unwrap();
        let frame = w.0.lock().unwrap().clone();
        assert_eq!(lawyer.recv().unwrap(), b"one");
        // the same frame again
        w.0.lock().unwrap().extend(&frame);
        assert!(lawyer.recv().is_err());
        // a changed one
        signer.send(b"two").unwrap();
        let last = w.0.lock().unwrap().len() - 1;
        w.0.lock().unwrap()[last] ^= 1;
        assert!(lawyer.recv().is_err());
    }
}
