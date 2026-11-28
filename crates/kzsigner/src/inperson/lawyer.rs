//! The lawyer's side: holds the document, serves one signer at a time, and keeps track of who
//! signed.

use super::wire::{Ack, Msg, Terms};
use super::{Channel, cert_hash, digest_for};
use crate::cert::{self, Cert};
use crate::cms::{self, SignedData};
use crate::env::Env;
use crate::i18n::{tr, trf};
use crate::p12::Key;
use crate::pdf::{self, Look, whosigned::WhoSigned};
use crate::report::SignerReport;
use crate::{Error, Result, Server, gost};

/// How long a request may wait for the signer to start signing.
const REQUEST_LIFETIME_MS: i64 = 15 * 60 * 1000;
/// The biggest revocation list passed on for a signer.
const CRL_LIMIT: u64 = 256 << 20;

/// One signing session on the lawyer's phone. The lawyer's key is opened once for it.
pub struct Lawyer {
    key: Key,
    pdf: Vec<u8>,
    doc_id: [u8; 32],
    title: String,
    page: WhoSigned,
    timestamp: bool,
    ocsp_url: Option<String>,
    signed: Vec<Signed>,
    finished: bool,
}

/// Someone whose signature is in the document.
#[derive(Clone, Debug)]
pub struct Signed {
    pub name: String,
    pub iin: Option<String>,
    /// The hash of their certificate.
    pub cert_hash: Vec<u8>,
    /// The signed ack they got, given again when they scan once more.
    ack: Msg,
}

/// A signature the lawyer is asked to accept: who, and the checks of it.
#[derive(Debug)]
pub struct Candidate<'a> {
    pub name: String,
    pub iin: Option<String>,
    pub report: &'a SignerReport,
}

/// How serving one signer ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Served {
    /// Accepted: the signature is now in the document.
    Signed(String),
    /// The lawyer rejected it; the spot stays free.
    Rejected(String),
    /// The signer said no.
    Cancelled,
    /// The connection was lost before the end; nothing changed.
    Dropped,
    /// Someone who already signed scanned again and got their status (and the final copy, once
    /// the document is finished).
    Status(String),
    /// Stopped: the reason, as told to the signer.
    Refused(String),
}

impl Lawyer {
    /// A session for `pdf`, named `title`, signed on its Who signed page. `timestamp`: each
    /// signature should carry an NCA timestamp.
    pub fn new(
        pdf: Vec<u8>,
        key: Key,
        title: &str,
        page: WhoSigned,
        timestamp: bool,
    ) -> Result<Lawyer> {
        digest_for(&key.cert)?;
        let mut doc_id = [0u8; 32];
        crate::random(&mut doc_id)?;
        Ok(Lawyer {
            key,
            pdf,
            doc_id,
            title: title.to_string(),
            page,
            timestamp,
            ocsp_url: None,
            signed: Vec::new(),
            finished: false,
        })
    }

    /// Checks each signer's certificate with OCSP at `url` before accepting.
    pub fn with_ocsp(mut self, url: &str) -> Lawyer {
        self.ocsp_url = Some(url.to_string());
        self
    }

    /// The lawyer signs too, on this phone, as the app does today (usually first).
    pub fn sign_self(&mut self, tsa_url: Option<&str>, env: &Env) -> Result<()> {
        let r = pdf::sign_with(
            &self.pdf,
            &self.key,
            tsa_url,
            env,
            Look::WhoSigned(&self.page),
        )?;
        self.pdf = r.cms;
        let (name, iin) = who(&self.key.cert);
        let ack = self.ack(
            cert_hash(&self.key.cert.der),
            r.signer_count as u32 - 1,
            true,
        )?;
        self.signed.push(Signed {
            name,
            iin,
            cert_hash: cert_hash(&self.key.cert.der),
            ack,
        });
        Ok(())
    }

    /// The document as signed so far.
    pub fn pdf(&self) -> &[u8] {
        &self.pdf
    }

    /// Who signed, in order.
    pub fn signers(&self) -> &[Signed] {
        &self.signed
    }

    /// Everyone signed: from now on a signer who scans gets the final copy, and nobody new may
    /// sign.
    pub fn finish(&mut self) {
        self.finished = true;
    }

    /// Serves one signer over `ch`: their certificate, the request, then the read, relay and
    /// signature messages until the lawyer's `decide` accepts or rejects. Only an accepted
    /// signature changes the document.
    pub fn serve(
        &mut self,
        ch: &mut dyn Channel,
        env: &Env,
        decide: &mut dyn FnMut(&Candidate) -> bool,
    ) -> Result<Served> {
        let Ok(first) = ch.recv() else {
            return Ok(Served::Dropped);
        };
        let cert = match Msg::parse(&first) {
            Ok(Msg::Hello { cert }) => cert,
            Ok(_) => return refuse(ch, "unexpected message".into()),
            Err(e) => return refuse(ch, e.to_string()),
        };
        let cert = match Cert::parse(&cert) {
            Ok(c) => c,
            Err(e) => return refuse(ch, Error::from(e).to_string()),
        };
        let hash = cert_hash(&cert.der);
        let (name, iin) = who(&cert);

        // scanned again: their status, and the final copy once there is one
        if let Some(s) = self.signed.iter().find(|s| s.cert_hash == hash) {
            let last = if self.finished {
                Msg::Final {
                    pdf: self.pdf.clone(),
                }
            } else {
                Msg::Done
            };
            let ok = ch
                .send(&s.ack.encode())
                .and_then(|_| ch.send(&last.encode()));
            return Ok(if ok.is_ok() {
                Served::Status(name)
            } else {
                Served::Dropped
            });
        }
        if self.finished {
            return refuse(ch, tr("Signing of this document is finished.").into());
        }
        let digest_oid = match digest_for(&cert) {
            Ok(d) => d,
            Err(e) => return refuse(ch, e.to_string()),
        };

        // the next revision for this signer; their signature's value left empty
        let (prepared, slot) = match pdf::prepare(
            &self.pdf,
            &cert,
            self.timestamp,
            env,
            Look::WhoSigned(&self.page),
        ) {
            Ok(p) => p,
            Err(e) => return refuse(ch, e.to_string()),
        };
        let digest = gost::hash(digest_oid, &prepared.signed_bytes())?;
        let terms = Terms {
            doc_id: self.doc_id,
            slot: slot as u32,
            digest,
            title: self.title.clone(),
            lawyer_cert: self.key.cert.der.clone(),
            signer_cert_hash: hash.clone(),
            transcript: ch.transcript().to_vec(),
            timestamp: self.timestamp,
            expires: env.now_ms() + REQUEST_LIFETIME_MS,
        }
        .encode();
        let cms = self.seal(&terms)?;
        if ch.send(&Msg::Request { terms, cms }.encode()).is_err() {
            return Ok(Served::Dropped);
        }

        loop {
            let Ok(m) = ch.recv() else {
                return Ok(Served::Dropped);
            };
            let m = match Msg::parse(&m) {
                Ok(m) => m,
                Err(e) => return refuse(ch, e.to_string()),
            };
            let sent = match m {
                Msg::Read => ch.send(
                    &Msg::File {
                        master_len: self.pdf.len() as u64,
                        pdf: prepared.bytes().to_vec(),
                    }
                    .encode(),
                ),
                Msg::Net { server, url, body } => {
                    let answer = pass_on(env, server, &url, &body).map_err(|e| e.to_string());
                    ch.send(&Msg::NetAnswer { answer }.encode())
                }
                Msg::Cancel => return Ok(Served::Cancelled),
                Msg::Refuse { why } => return Ok(Served::Refused(why)),
                Msg::Signature { cms } => {
                    let signed = match self.check_signature(&cms, &cert, digest_oid, &prepared, env)
                    {
                        Ok(s) => s,
                        Err(e) => return refuse(ch, e.to_string()),
                    };
                    let (pdf, report) = signed;
                    let accepted = decide(&Candidate {
                        name: name.clone(),
                        iin: iin.clone(),
                        report: &report,
                    });
                    let ack = self.ack(hash.clone(), slot as u32, accepted)?;
                    if accepted {
                        self.pdf = pdf;
                        self.signed.push(Signed {
                            name: name.clone(),
                            iin: iin.clone(),
                            cert_hash: hash,
                            ack: ack.clone(),
                        });
                    }
                    // accepted stands even if the ack doesn't arrive: a rescan gives it again
                    let _ = ch.send(&ack.encode());
                    return Ok(if accepted {
                        Served::Signed(name)
                    } else {
                        Served::Rejected(name)
                    });
                }
                _ => return refuse(ch, "unexpected message".into()),
            };
            if sent.is_err() {
                return Ok(Served::Dropped);
            }
        }
    }

    /// The signer's CMS put into the prepared revision, and the checks of it as the app checks
    /// any signature: it must be theirs, over this revision, and valid.
    fn check_signature(
        &self,
        der: &[u8],
        cert: &Cert,
        digest_oid: &str,
        prepared: &pdf::Prepared,
        env: &Env,
    ) -> Result<(Vec<u8>, SignerReport)> {
        let sd = SignedData::parse(der)?;
        let [si] = &sd.signers[..] else {
            return Err(Error::new(tr(
                "A PDF signature must hold exactly one signer.",
            )));
        };
        if si.digest_alg != digest_oid || !sd.certs.contains(&cert.der) {
            return Err(Error::new(tr(
                "The signature was not made with the key whose certificate was sent.",
            )));
        }
        let pdf = prepared.clone().insert(der)?;
        let rep = pdf::verify(&pdf, env, self.ocsp_url.as_deref())?;
        let s = rep
            .signers
            .last()
            .filter(|s| s.cert_der.as_deref() == Some(&cert.der[..]))
            .cloned()
            .ok_or_else(|| {
                Error::new(tr(
                    "The signature was not made with the key whose certificate was sent.",
                ))
            })?;
        if !s.valid {
            let why = s
                .signature_error
                .clone()
                .or_else(|| s.warnings.first().cloned())
                .unwrap_or_default();
            return Err(Error::new(trf("The signature is not valid: {}", &[&why])));
        }
        Ok((pdf, s))
    }

    fn ack(&self, signer_cert_hash: Vec<u8>, slot: u32, accepted: bool) -> Result<Msg> {
        let ack = Ack {
            doc_id: self.doc_id,
            slot,
            signer_cert_hash,
            accepted,
        }
        .encode();
        let cms = self.seal(&ack)?;
        Ok(Msg::Ack { ack, cms })
    }

    /// The lawyer's detached signature over `body`.
    fn seal(&self, body: &[u8]) -> Result<Vec<u8>> {
        let sd = cms::sign_once_with(
            body,
            cms::ID_DATA,
            false,
            &self.key.private_key,
            &self.key.cert,
            None,
            &[],
            &mut crate::OsRng,
        )
        .map_err(|e| Error::new(trf("Signing failed: {}", &[&Error::from(e)])))?;
        Ok(sd.encode()?)
    }
}

/// A signer's OCSP or timestamp request (or revocation list), sent on from this phone. The
/// signer's phone made it and checks the answer; this one only carries it.
fn pass_on(env: &Env, server: Server, url: &str, body: &[u8]) -> Result<Vec<u8>> {
    match server {
        Server::Ocsp => env.net.post(server, url, crate::ocsp::CONTENT_TYPE, body),
        Server::Timestamp => env.net.post(server, url, crate::tsp::CONTENT_TYPE, body),
        Server::RevocationList => env.net.get(server, url, CRL_LIMIT),
    }
}

fn refuse(ch: &mut dyn Channel, why: String) -> Result<Served> {
    let _ = ch.send(&Msg::Refuse { why: why.clone() }.encode());
    Ok(Served::Refused(why))
}

/// A certificate holder's name and IIN, as the lawyer checks them against an ID.
fn who(c: &Cert) -> (String, Option<String>) {
    let mut sr = SignerReport::default();
    cert::describe(&mut sr, c);
    (sr.name(), sr.get("IIN").map(str::to_string))
}
