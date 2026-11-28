//! The signer's side: send the certificate, check the lawyer's request, optionally read the
//! file, then sign its hash with the signer's own key, as the app signs today.

use std::sync::{Arc, Mutex};

use super::wire::{Ack, Msg, Terms};
use super::{Channel, cert_hash, digest_for};
use crate::cert::{self, Cert};
use crate::cms;
use crate::env::{Env, Transport};
use crate::i18n::{tr, trf};
use crate::p12::Key;
use crate::report::{SignResult, SignerReport, VerifyReport};
use crate::{Error, Result, Server, gost, pdf, sign, verify};

/// One signer's session with the lawyer's phone.
pub struct Signer {
    ch: Arc<Mutex<Box<dyn Channel>>>,
    cert: Cert,
    pending: Option<Pending>,
    /// The file read did not match the request, or could not be checked: signing is refused.
    blocked: bool,
    /// The lawyer's certificate (DER), when known from an earlier scan.
    lawyer: Option<Vec<u8>>,
}

struct Pending {
    terms: Terms,
    /// The request as received, the lawyer's signature over it: kept as evidence.
    raw: Vec<u8>,
    cms: Vec<u8>,
}

/// What the lawyer asks, after its checks, to show before signing.
#[derive(Clone, Debug)]
pub struct Request {
    pub title: String,
    pub lawyer_name: String,
    pub lawyer_iin: Option<String>,
    /// Which signature this will be, from 0.
    pub slot: u32,
    /// The signature will need an NCA timestamp.
    pub timestamp: bool,
}

/// What scanning the lawyer's QR gave.
#[derive(Debug)]
pub enum Offer {
    /// A request to sign.
    Sign(Request),
    /// This signer already signed: the lawyer's signed ack, and the signed document once
    /// everyone has signed (its own signature in it checked).
    Signed {
        ack: Ack,
        /// The lawyer's certificate (DER), to keep for [`Signer::with_lawyer`].
        lawyer_cert: Vec<u8>,
        final_pdf: Option<Vec<u8>>,
    },
    /// The lawyer's app said no.
    Refused(String),
}

/// The file, read before signing.
#[derive(Debug)]
pub struct Copy {
    /// The document with the new, still empty, signature field: what is shown.
    pub pdf: Vec<u8>,
    /// The checks of the signatures already in it.
    pub earlier: VerifyReport,
    /// The file is what the request asks to sign. When not, signing is refused and the
    /// request and this file are the evidence.
    pub matches: bool,
}

/// How signing ended.
#[derive(Debug)]
pub struct Outcome {
    /// The lawyer accepted the signature.
    pub accepted: bool,
    pub ack: Ack,
    /// The lawyer's certificate (DER), to keep for [`Signer::with_lawyer`].
    pub lawyer_cert: Vec<u8>,
    pub warnings: Vec<String>,
}

impl Signer {
    /// A session for the holder of `cert`, over `ch`.
    pub fn new(ch: Box<dyn Channel>, cert: Cert) -> Signer {
        Signer {
            ch: Arc::new(Mutex::new(ch)),
            cert,
            pending: None,
            blocked: false,
            lawyer: None,
        }
    }

    /// Only acks signed by this lawyer (certificate DER, as [`Offer::Signed`] gave it when the
    /// signer first signed) count when scanning again.
    pub fn with_lawyer(mut self, cert: Vec<u8>) -> Signer {
        self.lawyer = Some(cert);
        self
    }

    /// The network through the lawyer's phone, for a signer without internet: build the
    /// [`Env`] for [`Signer::start`], [`Signer::read`] and [`Signer::sign`] with it. Requests
    /// are made and answers checked here, as with a direct connection.
    pub fn relay(&self) -> Arc<dyn Transport> {
        Arc::new(Relay {
            ch: self.ch.clone(),
        })
    }

    /// Sends the certificate and checks what comes back. `ocsp_url`: also check the lawyer's
    /// certificate.
    pub fn start(&mut self, env: &Env, ocsp_url: Option<&str>) -> Result<Offer> {
        digest_for(&self.cert)?;
        self.send(&Msg::Hello {
            cert: self.cert.der.clone(),
        })?;
        match self.recv()? {
            Msg::Request { terms, cms } => {
                let r = Terms::parse(&terms)
                    .and_then(|t| Ok((self.check_request(&t, &terms, &cms, env, ocsp_url)?, t)));
                if let Err(e) = &r {
                    self.send(&Msg::Refuse { why: e.to_string() }).ok();
                }
                let (r, t) = r?;
                self.pending = Some(Pending {
                    terms: t,
                    raw: terms,
                    cms,
                });
                Ok(Offer::Sign(r))
            }
            Msg::Ack { ack, cms } => {
                // take both before any check that goes through the lawyer's phone, which
                // passes requests on until told it's done
                let final_pdf = match self.recv()? {
                    Msg::Final { pdf } => Some(pdf),
                    Msg::Done => None,
                    _ => return Err(unexpected()),
                };
                let r = self.check_status(&ack, &cms, final_pdf, env, ocsp_url);
                self.send(&Msg::Done).ok();
                r
            }
            Msg::Refuse { why } => Ok(Offer::Refused(why)),
            _ => Err(unexpected()),
        }
    }

    fn check_status(
        &self,
        ack: &[u8],
        cms: &[u8],
        final_pdf: Option<Vec<u8>>,
        env: &Env,
        ocsp_url: Option<&str>,
    ) -> Result<Offer> {
        let lawyer_cert = seal_ok(ack, cms, env, ocsp_url, self.lawyer.as_deref())?;
        let ack = Ack::parse(ack)?;
        if ack.signer_cert_hash != cert_hash(&self.cert.der)
            || ack.transcript != self.transcript()
            || !ack.accepted
        {
            return Err(not_for_you());
        }
        if let Some(pdf) = &final_pdf {
            own_signature_ok(pdf, &self.cert, env)?;
        }
        Ok(Offer::Signed {
            ack,
            lawyer_cert,
            final_pdf,
        })
    }

    fn check_request(
        &self,
        t: &Terms,
        raw: &[u8],
        cms: &[u8],
        env: &Env,
        ocsp_url: Option<&str>,
    ) -> Result<Request> {
        if t.signer_cert_hash != cert_hash(&self.cert.der) || t.transcript != self.transcript() {
            return Err(not_for_you());
        }
        if env.now_ms() > t.expires {
            return Err(Error::new(tr(
                "This request to sign has expired; scan the lawyer's QR code again.",
            )));
        }
        let want = gost::digest_len(digest_for(&self.cert)?)?;
        if t.digest.len() != want {
            return Err(unexpected());
        }
        if self.lawyer.as_ref().is_some_and(|l| *l != t.lawyer_cert) {
            return Err(Error::new(tr(
                "The lawyer's signature on the request is not valid.",
            )));
        }
        seal_ok(raw, cms, env, ocsp_url, Some(&t.lawyer_cert))?;
        let lawyer = Cert::parse(&t.lawyer_cert)?;
        let mut sr = SignerReport::default();
        cert::describe(&mut sr, &lawyer);
        Ok(Request {
            title: t.title.clone(),
            lawyer_name: sr.name(),
            lawyer_iin: sr.get("IIN").map(str::to_string),
            slot: t.slot,
            timestamp: t.timestamp,
        })
    }

    /// The file, before signing (optional): the document as signed so far plus the revision
    /// this signature goes into, without the signature. Its hash is worked out again here;
    /// when it is not the one in the request, signing is refused.
    pub fn read(&mut self, env: &Env, ocsp_url: Option<&str>) -> Result<Copy> {
        if self.pending.is_none() {
            return Err(unexpected());
        }
        let r = self.read_inner(env, ocsp_url);
        // a file that could not be checked blocks signing as a wrong one does
        if !r.as_ref().is_ok_and(|c| c.matches) {
            self.blocked = true;
        }
        r
    }

    fn read_inner(&mut self, env: &Env, ocsp_url: Option<&str>) -> Result<Copy> {
        let p = self.pending.as_ref().ok_or_else(unexpected)?;
        let digest = p.terms.digest.clone();
        self.send(&Msg::Read)?;
        let Msg::File { master_len, pdf } = self.recv()? else {
            return Err(unexpected());
        };
        let master_len = usize::try_from(master_len)
            .ok()
            .filter(|&n| n <= pdf.len())
            .ok_or_else(unexpected)?;
        let matches = pdf::Prepared::parse(&pdf)
            .and_then(|p| {
                gost::hash(digest_for(&self.cert)?, &p.signed_bytes()).map_err(Into::into)
            })
            .is_ok_and(|d| d == digest);
        let earlier = pdf::verify(&pdf[..master_len], env, ocsp_url)?;
        Ok(Copy {
            pdf,
            earlier,
            matches,
        })
    }

    /// The request as received and the lawyer's signature over it: evidence when the file
    /// read did not match.
    pub fn request_evidence(&self) -> Option<(&[u8], &[u8])> {
        self.pending.as_ref().map(|p| (&p.raw[..], &p.cms[..]))
    }

    /// Signs the requested hash with `key`, as the app signs today: the key's own checks
    /// (OCSP at `ocsp_url`), then the signature and, if asked, an NCA timestamp from
    /// `tsa_url`. Sent only once those answers came back valid; then waits for the lawyer.
    pub fn sign(
        &mut self,
        key: &Key,
        env: &Env,
        tsa_url: Option<&str>,
        ocsp_url: Option<&str>,
    ) -> Result<Outcome> {
        let r = self.sign_inner(key, env, tsa_url, ocsp_url);
        if let Err(e) = &r {
            self.send(&Msg::Refuse { why: e.to_string() }).ok();
        }
        r
    }

    fn sign_inner(
        &mut self,
        key: &Key,
        env: &Env,
        tsa_url: Option<&str>,
        ocsp_url: Option<&str>,
    ) -> Result<Outcome> {
        if self.blocked {
            return Err(Error::new(tr(
                "The file shown is not the one the lawyer asked you to sign; signing is refused.",
            )));
        }
        let p = self.pending.take().ok_or_else(unexpected)?;
        if key.cert != self.cert {
            return Err(Error::new(tr(
                "The signature was not made with the key whose certificate was sent.",
            )));
        }
        let mut r = SignResult {
            warnings: sign::check_key(&key.cert, ocsp_url, env)?,
            ..Default::default()
        };
        r.warnings
            .extend(cert::key_warnings(&key.cert, env.now_ms()));
        // PAdES keeps the signing time in the PDF, not in the signature
        let mut sd = cms::sign_digest(
            &p.terms.digest,
            cms::ID_DATA,
            &key.private_key,
            &key.cert,
            None,
            &[],
            &mut crate::OsRng,
        )
        .map_err(|e| Error::new(trf("Signing failed: {}", &[&Error::from(e)])))?;
        if p.terms.timestamp {
            let url = tsa_url.ok_or_else(|| {
                Error::new(tr(
                    "The lawyer asks for a timestamp; set a timestamp server.",
                ))
            })?;
            sign::timestamp(&mut sd, url, key, env, &mut r)?;
        }
        self.send(&Msg::Signature { cms: sd.encode()? })?;
        match self.recv()? {
            Msg::Ack { ack, cms } => {
                seal_ok(&ack, &cms, env, None, Some(&p.terms.lawyer_cert))?;
                let ack = Ack::parse(&ack)?;
                if ack.doc_id != p.terms.doc_id
                    || ack.slot != p.terms.slot
                    || ack.signer_cert_hash != p.terms.signer_cert_hash
                    || ack.digest != p.terms.digest
                    || ack.transcript != p.terms.transcript
                {
                    return Err(not_for_you());
                }
                Ok(Outcome {
                    accepted: ack.accepted,
                    ack,
                    lawyer_cert: p.terms.lawyer_cert.clone(),
                    warnings: r.warnings,
                })
            }
            Msg::Refuse { why } => Err(Error::new(why)),
            _ => Err(unexpected()),
        }
    }

    /// Says no to the request.
    pub fn cancel(&mut self) {
        self.pending = None;
        self.send(&Msg::Cancel).ok();
    }

    fn transcript(&self) -> Vec<u8> {
        self.ch.lock().unwrap().transcript().to_vec()
    }

    fn send(&self, m: &Msg) -> Result<()> {
        self.ch.lock().unwrap().send(&m.encode())
    }

    fn recv(&self) -> Result<Msg> {
        let m = Msg::parse(&self.ch.lock().unwrap().recv()?)?;
        if let Msg::Refuse { why } = &m {
            // the request ends here; the caller sees why
            if self.pending.is_none() {
                return Ok(m);
            }
            return Err(Error::new(why.clone()));
        }
        Ok(m)
    }
}

/// The OCSP and timestamp servers, reached through the lawyer's phone.
struct Relay {
    ch: Arc<Mutex<Box<dyn Channel>>>,
}

impl Relay {
    fn ask(&self, server: Server, url: &str, body: &[u8]) -> Result<Vec<u8>> {
        let mut ch = self.ch.lock().unwrap();
        ch.send(
            &Msg::Net {
                server,
                url: url.to_string(),
                body: body.to_vec(),
            }
            .encode(),
        )?;
        match Msg::parse(&ch.recv()?)? {
            Msg::NetAnswer { answer } => answer.map_err(|e| {
                Error::new(trf(
                    "The lawyer's phone could not reach {}: {}",
                    &[&server.name(), &e],
                ))
            }),
            Msg::Refuse { why } => Err(Error::new(why)),
            _ => Err(unexpected()),
        }
    }
}

impl Transport for Relay {
    fn post(&self, server: Server, url: &str, _: &str, body: &[u8]) -> Result<Vec<u8>> {
        self.ask(server, url, body)
    }
    fn get(&self, server: Server, url: &str, limit: u64) -> Result<Vec<u8>> {
        let b = self.ask(server, url, &[])?;
        if b.len() as u64 > limit {
            return Err(unexpected());
        }
        Ok(b)
    }
}

/// Checks the lawyer's signature over `body`, as the app checks any signature; and that it is
/// by `expected` (DER) when given. The signer's certificate, DER.
fn seal_ok(
    body: &[u8],
    cms: &[u8],
    env: &Env,
    ocsp_url: Option<&str>,
    expected: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let rep = verify::verify(cms, Some(body), env, ocsp_url)?;
    let bad = || Error::new(tr("The lawyer's signature on the request is not valid."));
    let [s] = &rep.signers[..] else {
        return Err(bad());
    };
    let c = s.cert_der.clone().ok_or_else(bad)?;
    if !rep.valid || expected.is_some_and(|e| e != c) {
        return Err(bad());
    }
    Ok(c)
}

/// The signer's own signature is in `pdf` and intact.
fn own_signature_ok(pdf: &[u8], c: &Cert, env: &Env) -> Result<()> {
    let rep = pdf::verify(pdf, env, None)?;
    if rep
        .signers
        .iter()
        .any(|s| s.signature_ok && s.cert_der.as_deref() == Some(&c.der[..]))
    {
        Ok(())
    } else {
        Err(Error::new(tr(
            "Your signature is missing from the signed document, or it was changed.",
        )))
    }
}

fn not_for_you() -> Error {
    Error::new(tr("This request was not made for you or for this session."))
}

fn unexpected() -> Error {
    Error::new(tr("The other phone sent a message this app can't read."))
}
