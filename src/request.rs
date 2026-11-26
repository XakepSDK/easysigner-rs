//! What [`Engine::sign`](crate::Engine::sign) is asked to make: the document, the key, the kind
//! of signature, and the servers to ask.

use crate::p12::Key;
use crate::pdf;

/// A .cms signature's options.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cms<'a> {
    /// Beside the document (a detached .cms), not around it.
    pub detached: bool,
    /// When the input is itself a .cms, add a signature to it instead of signing it as a file.
    pub cosign: bool,
    /// The document of a detached .cms being co-signed.
    pub original: Option<&'a [u8]>,
}

/// The kind of signature to make.
#[derive(Clone, Copy, Debug)]
pub enum Form<'a> {
    /// A .cms (CAdES) around or beside the document.
    Cms(Cms<'a>),
    /// A detached .cms over a document known only by its hash (the input).
    Hash,
    /// A signature inside the PDF (PAdES), with a visible stamp when given.
    Pdf(Option<&'a pdf::stamp::Stamp>),
    /// A PDF signature with the signer's box on the Who signed page ([`pdf::whosigned`]).
    PdfPage(&'a pdf::whosigned::WhoSigned),
    /// An enveloped XAdES signature inside the XML document.
    Xml,
}

/// A request to sign `input` with `key`, built with the constructors and the `tsa`/`ocsp`
/// setters:
///
/// ```ignore
/// engine.sign(SignRequest::pdf(&doc, &key).tsa(kzsigner::DEFAULT_TSA_URL))
/// ```
#[derive(Clone, Copy)]
pub struct SignRequest<'a> {
    pub input: &'a [u8],
    pub key: &'a Key,
    pub form: Form<'a>,
    /// The timestamp server; None for no timestamp.
    pub tsa_url: Option<&'a str>,
    /// The OCSP server the key is checked with first; None to check it offline only.
    pub ocsp_url: Option<&'a str>,
}

impl<'a> SignRequest<'a> {
    pub fn new(input: &'a [u8], key: &'a Key, form: Form<'a>) -> Self {
        SignRequest {
            input,
            key,
            form,
            tsa_url: None,
            ocsp_url: None,
        }
    }

    pub fn cms(input: &'a [u8], key: &'a Key, cms: Cms<'a>) -> Self {
        Self::new(input, key, Form::Cms(cms))
    }

    pub fn hash(hash: &'a [u8], key: &'a Key) -> Self {
        Self::new(hash, key, Form::Hash)
    }

    pub fn pdf(input: &'a [u8], key: &'a Key) -> Self {
        Self::new(input, key, Form::Pdf(None))
    }

    pub fn pdf_page(input: &'a [u8], key: &'a Key, page: &'a pdf::whosigned::WhoSigned) -> Self {
        Self::new(input, key, Form::PdfPage(page))
    }

    pub fn xml(input: &'a [u8], key: &'a Key) -> Self {
        Self::new(input, key, Form::Xml)
    }

    /// A visible stamp, for a PDF signature (ignored by other forms).
    pub fn stamp(mut self, stamp: Option<&'a pdf::stamp::Stamp>) -> Self {
        if let Form::Pdf(s) = &mut self.form {
            *s = stamp;
        }
        self
    }

    pub fn tsa(mut self, url: impl Into<Option<&'a str>>) -> Self {
        self.tsa_url = url.into();
        self
    }

    pub fn ocsp(mut self, url: impl Into<Option<&'a str>>) -> Self {
        self.ocsp_url = url.into();
        self
    }
}
