//! Signing in person, for the app (docs/in-person-signing.md): the lawyer's phone holds a
//! [`Meeting`] and shows one QR code per signer; each signer's phone scans it and becomes a
//! [`Guest`]. The QR, the encrypted session and the signing itself are the core's
//! (`kzsigner::inperson`); this is the app's view of them, in facts and codes.
//!
//! The phones talk over TCP on the same network: the same Wi-Fi, or the lawyer's hotspot.

use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kzsigner::cert::{Cert, get, rdns};
use kzsigner::env::Env;
use kzsigner::i18n::Lang;
use kzsigner::inperson::session::{self, Door, Engagement, Hint, Invitation};
use kzsigner::inperson::{Lawyer, Offer, Served, Signer};
use kzsigner::pdf::whosigned::WhoSigned;
use std::time::Duration;

use crate::sign::{Nca, SignError, SignedBy, check, nca_time_of};
use crate::{ChipPrompt, Signed, Vault, cant_sign, now};

/// Someone at the lawyer's phone.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Person {
    pub name: String,
    pub iin: Option<String>,
}

/// A signature waiting for the lawyer's Accept or Reject.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Arrival {
    pub name: String,
    pub iin: Option<String>,
    pub company: Option<String>,
    pub bin: Option<String>,
    /// NCA's time on the signature, when it has one.
    pub nca_time_ms: Option<i64>,
}

/// How one signer's turn at the lawyer's phone ended.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Turn {
    /// Accepted: the signature is in the document.
    Signed { name: String },
    /// The lawyer rejected it; nothing changed.
    Rejected { name: String },
    /// The signer said no, or walked away; nothing changed.
    Left,
    /// Someone who signed already scanned again (and got the signed copy, once finished).
    Collected { name: String },
    /// The signer's phone or this one stopped it: why, in the core's words.
    Refused { why: String },
    /// [`Meeting::stop`] was called.
    Stopped,
}

/// The lawyer's screen, called while a signer is at the phone. Both calls come from the thread
/// in [`Meeting::wait`]; `decide` blocks until the lawyer taps Accept or Reject.
#[uniffi::export(with_foreign)]
pub trait Desk: Send + Sync {
    /// A signer's phone connected and sent its certificate.
    fn arrived(&self, who: Person);
    /// Their valid signature came: true accepts it.
    fn decide(&self, who: Arrival) -> bool;
}

/// Why a meeting or a visit could not go on.
#[derive(Debug, uniffi::Error)]
pub enum MeetError {
    /// Not a kzsigner QR code.
    NotAnInvitation,
    /// The lawyer's phone can't be reached: not on the same network.
    Unreachable,
    /// The connection broke, or the other phone stopped: why.
    Lost {
        why: String,
    },
    Failed {
        detail: String,
    },
}

impl std::fmt::Display for MeetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The lawyer's side: the document, who signed it, and the QR for the next signer.
#[derive(uniffi::Object)]
pub struct Meeting {
    nca: Arc<Nca>,
    lawyer: Mutex<Lawyer>,
    name: String,
    door: Door,
    next: Mutex<Option<Invitation>>,
    /// The signer's connection now, to cut it on [`Meeting::stop`].
    current: Mutex<Option<TcpStream>>,
    stopped: AtomicBool,
}

#[uniffi::export]
impl Vault {
    /// Starts signing `bytes` (a PDF named `name`) in person with key `key_id`: checks the key
    /// with NCA, opens it once for the whole meeting (one prompt, or `password`), and signs
    /// first, which adds the Who signed page. Blocks.
    #[allow(clippy::too_many_arguments)]
    pub fn start_meeting(
        &self,
        nca: Arc<Nca>,
        key_id: String,
        name: String,
        bytes: Vec<u8>,
        password: Option<String>,
        prompt: ChipPrompt,
        lang: String,
    ) -> Result<Arc<Meeting>, SignError> {
        kzsigner::i18n::set(Lang::parse(&lang).unwrap_or(Lang::En));
        if !kzsigner::pdf::is_pdf(&bytes) {
            return Err(SignError::Cannot);
        }
        let cert = self.cert_of(&key_id)?;
        check(&nca, &cert)?;
        let key = self.open_key(&key_id, password, prompt)?;
        let page = WhoSigned {
            document: name.clone(),
        };
        let failed = |e: kzsigner::Error| SignError::Failed {
            detail: e.to_string(),
        };
        let mut lawyer = Lawyer::new(bytes, key, &name, page, true).map_err(failed)?;
        lawyer = lawyer.with_ocsp(&nca.ocsp);
        // the app's own NCA servers (fake ones in the tests) take a signer's requests too
        for url in [&nca.tsa, &nca.ocsp] {
            if let Some(h) = kzsigner::inperson::relay_host(url).map(str::to_string) {
                lawyer = lawyer.allow_relay_host(&h);
            }
        }
        lawyer
            .sign_self(Some(&nca.tsa), nca.engine.env())
            .map_err(|e| {
                if e.server() == Some(kzsigner::Server::Timestamp) {
                    SignError::NoAnswer
                } else {
                    failed(e)
                }
            })?;
        let door = Door::open().map_err(failed)?;
        Ok(Arc::new(Meeting {
            nca,
            lawyer: Mutex::new(lawyer),
            name,
            door,
            next: Mutex::new(None),
            current: Mutex::new(None),
            stopped: AtomicBool::new(false),
        }))
    }
}

#[uniffi::export]
impl Meeting {
    /// A new QR code for the next signer: a new one-time key, and this phone's `addresses` on
    /// its networks (Wi-Fi, hotspot), as the app found them.
    pub fn invite(&self, addresses: Vec<String>) -> Result<String, MeetError> {
        let port = self.door.port();
        let hints = addresses
            .iter()
            .map(|a| {
                if a.contains(':') {
                    Hint::Tcp(format!("[{a}]:{port}"))
                } else {
                    Hint::Tcp(format!("{a}:{port}"))
                }
            })
            .collect();
        let inv = Invitation::new(hints).map_err(|e| MeetError::Failed {
            detail: e.to_string(),
        })?;
        let qr = inv.engagement.qr();
        *self.next.lock().unwrap() = Some(inv);
        Ok(qr)
    }

    /// Waits for a signer to scan the QR from [`Meeting::invite`] and serves them to the end of
    /// their turn. Blocks; [`Meeting::stop`] ends it. A connection that doesn't prove it has
    /// the QR code within [`HANDSHAKE`] (a stranger on the network, a scan of an old QR) is
    /// dropped, and the QR keeps waiting for its signer. While a signer is served, the document
    /// is held: [`Meeting::finish`] and [`Meeting::signers`] wait for the turn to end.
    pub fn wait(&self, desk: Arc<dyn Desk>) -> Turn {
        loop {
            let stream = match self.door.wait() {
                Ok(Some((s, _))) => s,
                Ok(None) => return Turn::Stopped,
                Err(e) => return Turn::Refused { why: e.to_string() },
            };
            let Some(inv) = self.next.lock().unwrap().clone() else {
                return Turn::Refused {
                    why: "no QR code shown".into(),
                };
            };
            *self.current.lock().unwrap() = stream.try_clone().ok();
            let r = self.serve(&inv, stream, &desk);
            self.current.lock().unwrap().take();
            if self.stopped.load(Ordering::SeqCst) {
                return Turn::Stopped;
            }
            match r {
                // not the phone that scanned this QR code: wait for that one
                None => continue,
                Some(t) => return t,
            }
        }
    }

    /// Ends [`Meeting::wait`] (the lawyer left the screen): the signer at the phone, if any, is
    /// cut off and nothing changes.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.door.stopper().store(true, Ordering::SeqCst);
        if let Some(s) = self.current.lock().unwrap().as_ref() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    /// Who signed so far, in order (the lawyer first).
    pub fn signers(&self) -> Vec<Person> {
        self.lawyer
            .lock()
            .unwrap()
            .signers()
            .iter()
            .map(|s| Person {
                name: s.name.clone(),
                iin: s.iin.clone(),
            })
            .collect()
    }

    /// Everyone signed: makes the document long-term (NCA's document timestamp) and from now
    /// on gives it to each signer who scans the QR again. The signed document.
    pub fn finish(&self) -> Result<Signed, SignError> {
        let mut l = self.lawyer.lock().unwrap();
        l.finish_long_term(&self.nca.tsa, &self.nca.ocsp, self.nca.engine.env())
            .map_err(|e| {
                if e.server().is_some() {
                    SignError::NoAnswer
                } else {
                    SignError::Failed {
                        detail: e.to_string(),
                    }
                }
            })?;
        Ok(self.document(&l))
    }

    /// The document as signed so far.
    pub fn signed(&self) -> Signed {
        self.document(&self.lawyer.lock().unwrap())
    }

    pub fn finished(&self) -> bool {
        self.lawyer.lock().unwrap().finished()
    }
}

/// How long a phone that connects has to prove it scanned the QR code (its key, then its
/// certificate). After that there are no time limits: a signer may read for as long as they like.
const HANDSHAKE: Duration = Duration::from_secs(10);

impl Meeting {
    /// One connection; None when it was not the signer this QR code was shown to.
    fn serve(&self, inv: &Invitation, stream: TcpStream, desk: &Arc<dyn Desk>) -> Option<Turn> {
        stream.set_read_timeout(Some(HANDSHAKE)).ok()?;
        let clock = stream.try_clone().ok()?;
        let mut ch = inv.accept(stream).ok()?;
        let env = self.nca.engine.env();
        let mut proven = false;
        let mut lawyer = self.lawyer.lock().unwrap();
        let r = lawyer.serve_with(
            &mut ch,
            env,
            &mut |name, iin| {
                // the certificate came in the session: this is the phone that scanned, and
                // the QR code is used up
                proven = true;
                clock.set_read_timeout(None).ok();
                self.next.lock().unwrap().take();
                desk.arrived(Person {
                    name: name.to_string(),
                    iin: iin.map(str::to_string),
                })
            },
            &mut |c| {
                let cert = c
                    .report
                    .cert_der
                    .as_deref()
                    .and_then(|d| Cert::parse(d).ok());
                let subject = cert.as_ref().map(|c| rdns(&c.subject)).unwrap_or_default();
                desk.decide(Arrival {
                    name: c.name.clone(),
                    iin: c.iin.clone(),
                    company: get(&subject, "O").map(str::to_string),
                    bin: c.report.get("BIN").map(str::to_string),
                    nca_time_ms: c.report.timestamp_time,
                })
            },
        );
        drop(lawyer);
        if !proven {
            return None;
        }
        Some(match r {
            Ok(Served::Signed(name)) => Turn::Signed { name },
            Ok(Served::Rejected(name)) => Turn::Rejected { name },
            Ok(Served::Cancelled | Served::Dropped) => Turn::Left,
            Ok(Served::Status(name)) => Turn::Collected { name },
            Ok(Served::Refused(why)) => Turn::Refused { why },
            Err(e) => Turn::Refused { why: e.to_string() },
        })
    }

    fn document(&self, l: &Lawyer) -> Signed {
        let bytes = l.pdf().to_vec();
        Signed {
            nca_time_ms: nca_time_of(&self.nca.engine, &bytes),
            joined: l.signers().len() > 1,
            name: signed_name(&self.name),
            bytes,
        }
    }
}

/// "contract.pdf" → "contract-signed.pdf", as the app names signed PDFs.
fn signed_name(name: &str) -> String {
    kzsigner::signed_name(std::path::Path::new(name), "pdf")
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string())
}

/// What the lawyer's phone asks of a signer who scanned its QR.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Visit {
    /// Please sign `title`; this will be signature number `number` (from 1).
    Sign {
        title: String,
        lawyer: String,
        lawyer_iin: Option<String>,
        number: u32,
    },
    /// You signed already; `document` is the signed copy once everyone has (your own
    /// signature in it checked), else None: not finished yet.
    Signed { document: Option<Vec<u8>> },
    /// The lawyer's phone said no: why, in the core's words.
    Refused { why: String },
}

/// The document, read before signing.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Reading {
    /// The PDF with the new, empty, signature box: what is shown.
    pub pdf: Vec<u8>,
    /// Who signed it already.
    pub signers: Vec<SignedBy>,
    /// It is what the lawyer asks to sign (else signing is refused).
    pub matches: bool,
}

/// How signing at the lawyer's phone ended.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Outcome {
    pub accepted: bool,
}

/// The signer's side: one visit to the lawyer's phone.
#[derive(uniffi::Object)]
pub struct Guest {
    nca: Arc<Nca>,
    signer: Mutex<Signer>,
    /// The signer's own network, or the lawyer's phone for a signer without internet.
    relayed: Option<Env>,
    visit: Visit,
    key_id: String,
    stream: Option<TcpStream>,
}

fn lost(e: kzsigner::Error) -> MeetError {
    MeetError::Lost { why: e.to_string() }
}

#[uniffi::export]
impl Vault {
    /// Scans in: connects to the lawyer's phone that showed `qr` and sends key `key_id`'s
    /// certificate (no prompt). `online`: this phone has internet; without it, NCA is reached
    /// through the lawyer's phone. Blocks.
    pub fn visit(
        &self,
        nca: Arc<Nca>,
        key_id: String,
        qr: String,
        online: bool,
    ) -> Result<Arc<Guest>, MeetError> {
        let cert = self.cert_of(&key_id).map_err(|e| MeetError::Failed {
            detail: e.to_string(),
        })?;
        let e = Engagement::parse(&qr).map_err(|_| MeetError::NotAnInvitation)?;
        let ch = session::join_tcp(&e).map_err(|_| MeetError::Unreachable)?;
        let stream = ch.stream().try_clone().ok();
        let mut signer = Signer::new(Box::new(ch), cert);
        let relayed = (!online).then(|| {
            Env::new(kzsigner::trust::trust_store(nca.extra_trust.clone())).with_net(signer.relay())
        });
        let env = relayed.as_ref().unwrap_or(nca.engine.env());
        let visit = match signer.start(env, Some(&nca.ocsp)).map_err(lost)? {
            Offer::Sign(r) => Visit::Sign {
                title: r.title,
                lawyer: r.lawyer_name,
                lawyer_iin: r.lawyer_iin,
                number: r.slot + 1,
            },
            Offer::Signed { final_pdf, .. } => Visit::Signed {
                document: final_pdf,
            },
            Offer::Refused(why) => Visit::Refused { why },
        };
        Ok(Arc::new(Guest {
            nca,
            signer: Mutex::new(signer),
            relayed,
            visit,
            key_id,
            stream,
        }))
    }

    /// Signs what `guest`'s lawyer asked, with the key the visit started with: checks the key
    /// with NCA, opens it (one prompt, or `password`), signs with NCA's time, and waits for the
    /// lawyer's Accept or Reject. Blocks.
    pub fn sign_visit(
        &self,
        guest: Arc<Guest>,
        password: Option<String>,
        prompt: ChipPrompt,
        lang: String,
    ) -> Result<Outcome, SignError> {
        kzsigner::i18n::set(Lang::parse(&lang).unwrap_or(Lang::En));
        let cert = self.cert_of(&guest.key_id)?;
        let refuse = |reason| SignError::KeyCantSign {
            reason,
            valid_from_ms: cert.not_before,
            expires_ms: cert.not_after,
        };
        if guest.relayed.is_none() {
            check(&guest.nca, &cert)?;
        } else if let Some(r) = cant_sign(&cert, now()).or_else(|| guest.nca.unrecognized(&cert)) {
            // offline: what the phone can tell; NCA's answer comes through the lawyer's phone
            return Err(refuse(r));
        }
        let key = self.open_key(&guest.key_id, password, prompt)?;
        let env = guest.env();
        guest
            .signer
            .lock()
            .unwrap()
            .sign(&key, env, Some(&guest.nca.tsa), Some(&guest.nca.ocsp))
            .map(|o| Outcome {
                accepted: o.accepted,
            })
            .map_err(|e| {
                if e.server().is_some() {
                    SignError::NoAnswer
                } else {
                    SignError::Failed {
                        detail: e.to_string(),
                    }
                }
            })
    }
}

#[uniffi::export]
impl Guest {
    pub fn visit(&self) -> Visit {
        self.visit.clone()
    }

    /// The document before signing (optional): with the signer's box, without their
    /// signature. Its hash is worked out again here; when it is not what the lawyer asked to
    /// sign, signing is refused.
    pub fn read(&self) -> Result<Reading, MeetError> {
        let mut s = self.signer.lock().unwrap();
        let c = s.read(self.env(), None).map_err(lost)?;
        let mut signers: Vec<SignedBy> = c
            .earlier
            .signers
            .iter()
            .map(crate::sign::signed_by)
            .collect();
        signers.sort_by_key(|s| s.signed_ms.unwrap_or(i64::MAX));
        Ok(Reading {
            pdf: c.pdf,
            signers,
            matches: c.matches,
        })
    }

    /// Says no and leaves.
    /// Doesn't wait: the connection is cut first, which ends a [`Vault::sign_visit`] or
    /// [`Guest::read`] still waiting on the lawyer's phone.
    pub fn cancel(&self) {
        if let Ok(mut s) = self.signer.try_lock() {
            s.cancel();
        }
        if let Some(s) = &self.stream {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

impl Guest {
    fn env(&self) -> &Env {
        self.relayed.as_ref().unwrap_or(self.nca.engine.env())
    }
}
