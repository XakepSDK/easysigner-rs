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
/// The most requests passed on for one signer: a few OCSP, timestamp and revocation list calls.
const RELAY_LIMIT: usize = 16;
/// The hosts a signer's requests may be passed on to: NCA's.
const NCA_HOSTS: [&str; 3] = ["ocsp.pki.gov.kz", "tsp.pki.gov.kz", "crl.pki.gov.kz"];

/// One signing session on the lawyer's phone. The lawyer's key is opened once for it.
pub struct Lawyer {
    key: Key,
    pdf: Vec<u8>,
    doc_id: [u8; 32],
    title: String,
    page: WhoSigned,
    timestamp: bool,
    ocsp_url: Option<String>,
    relay_hosts: Vec<String>,
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
    slot: u32,
    digest: Vec<u8>,
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
            relay_hosts: NCA_HOSTS.iter().map(|h| h.to_string()).collect(),
            signed: Vec::new(),
            finished: false,
        })
    }

    /// Checks each signer's certificate with OCSP at `url` before accepting.
    pub fn with_ocsp(mut self, url: &str) -> Lawyer {
        self.ocsp_url = Some(url.to_string());
        self
    }

    /// Also passes a signer's requests on to `host` (NCA's own hosts always are).
    pub fn allow_relay_host(mut self, host: &str) -> Lawyer {
        self.relay_hosts.push(host.to_ascii_lowercase());
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
        self.signed.push(Signed {
            name,
            iin,
            cert_hash: cert_hash(&self.key.cert.der),
            slot: r.signer_count as u32 - 1,
            digest: Vec::new(),
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

    /// [`Lawyer::finish`], making the signed document long-term first (PAdES B-LTA: the
    /// certificates and revocation answers inside it, and NCA's document timestamp over it all),
    /// as the app makes every signed file.
    pub fn finish_long_term(&mut self, tsa_url: &str, ocsp_url: &str, env: &Env) -> Result<()> {
        if !self.finished {
            self.pdf = pdf::extend(&self.pdf, true, tsa_url, ocsp_url, env)?.cms;
            self.finished = true;
        }
        Ok(())
    }

    /// Whether [`Lawyer::finish`] was called.
    pub fn finished(&self) -> bool {
        self.finished
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
        self.serve_with(ch, env, &mut |_, _| {}, decide)
    }

    /// [`Lawyer::serve`], telling `hello` who connected (name, IIN) as soon as their
    /// certificate arrives, for the lawyer's screen.
    pub fn serve_with(
        &mut self,
        ch: &mut dyn Channel,
        env: &Env,
        hello: &mut dyn FnMut(&str, Option<&str>),
        decide: &mut dyn FnMut(&Candidate) -> bool,
    ) -> Result<Served> {
        let r = self.serve_inner(ch, env, hello, decide);
        if let Err(e) = &r {
            // the signer is told, not left waiting
            let _ = ch.send(&Msg::Refuse { why: e.to_string() }.encode());
        }
        r
    }

    fn serve_inner(
        &mut self,
        ch: &mut dyn Channel,
        env: &Env,
        hello: &mut dyn FnMut(&str, Option<&str>),
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
        hello(&name, iin.as_deref());

        // scanned again: their status, and the final copy once there is one
        if let Some(s) = self.signed.iter().find(|s| s.cert_hash == hash) {
            let last = if self.finished {
                Msg::Final {
                    pdf: self.pdf.clone(),
                }
            } else {
                Msg::Done
            };
            let ack = self.ack(ch, s.cert_hash.clone(), s.slot, s.digest.clone(), true)?;
            let ok = ch.send(&ack.encode()).and_then(|_| ch.send(&last.encode()));
            if ok.is_err() {
                return Ok(Served::Dropped);
            }
            // the signer may check the ack through this phone; until it says it's done
            let mut relayed = 0;
            while let Ok(Msg::Net { server, url, body }) = ch.recv().and_then(|m| Msg::parse(&m)) {
                let answer = self.pass_on(env, server, &url, &body, &mut relayed);
                if ch.send(&Msg::NetAnswer { answer }.encode()).is_err() {
                    break;
                }
            }
            return Ok(Served::Status(name));
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
            digest: digest.clone(),
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

        let mut relayed = 0;
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
                    let answer = self.pass_on(env, server, &url, &body, &mut relayed);
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
                    let ack = self.ack(ch, hash.clone(), slot as u32, digest.clone(), accepted)?;
                    if accepted {
                        self.pdf = pdf;
                        self.signed.push(Signed {
                            name: name.clone(),
                            iin: iin.clone(),
                            cert_hash: hash,
                            slot: slot as u32,
                            digest,
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
        if self.timestamp && s.timestamp_ok != Some(true) {
            return Err(Error::new(tr(
                "The signature has no valid NCA timestamp, which was asked for.",
            )));
        }
        Ok((pdf, s))
    }

    /// A signer's OCSP or timestamp request (or revocation list), sent on from this phone to
    /// NCA's servers only, a few per signer. The signer's phone made it and checks the answer;
    /// this one only carries it.
    fn pass_on(
        &self,
        env: &Env,
        server: Server,
        url: &str,
        body: &[u8],
        count: &mut usize,
    ) -> std::result::Result<Vec<u8>, String> {
        *count += 1;
        if *count > RELAY_LIMIT || !self.may_relay(url) {
            return Err(
                tr("The lawyer's phone passes on requests to NCA's servers only.").to_string(),
            );
        }
        match server {
            Server::Ocsp => env.net.post(server, url, crate::ocsp::CONTENT_TYPE, body),
            Server::Timestamp => env.net.post(server, url, crate::tsp::CONTENT_TYPE, body),
            Server::RevocationList => env.net.get(server, url, CRL_LIMIT),
        }
        .map_err(|e| e.to_string())
    }

    /// Whether a signer's request to `url` may be passed on: to an allowed host, over http.
    fn may_relay(&self, url: &str) -> bool {
        let Some(host) = relay_host(url) else {
            return false;
        };
        self.relay_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
    }

    /// The signed ack for this session.
    fn ack(
        &self,
        ch: &dyn Channel,
        signer_cert_hash: Vec<u8>,
        slot: u32,
        digest: Vec<u8>,
        accepted: bool,
    ) -> Result<Msg> {
        let ack = Ack {
            doc_id: self.doc_id,
            slot,
            signer_cert_hash,
            digest,
            transcript: ch.transcript().to_vec(),
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

/// The host of an http:// URL the lawyer's phone may pass on (no user part, no IPv6 literal:
/// NCA's servers are names); None for anything else.
pub fn relay_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("http://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') || authority.starts_with('[') {
        return None;
    }
    authority.split(':').next().filter(|h| !h.is_empty())
}
