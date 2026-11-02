//! Карточка электронного документа (electronic document card, https://github.com/kaarkz/ddcard):
//! a PDF that carries the original document and its detached CMS signatures as attachments,
//! with pages people can read: an information block, the document's own pages (when it is a
//! PDF), and one page per signature, optionally with the signature as QR codes.
//!
//! The layout and texts follow SIGEX's reference implementation, ddc
//! (https://github.com/sigex-kz/ddc, MIT licence), whose Kazakh texts are reused here, so cards
//! made by kzsigner and by SIGEX look alike and either tool can read the other's.

use lopdf::{Dictionary, Document, Object, Stream, StringFormat};

use super::import;
use super::layout::{A4, MM, Page, Writer, leading};
use super::qr;
use crate::cert::{self, Cert};
use crate::cms::{self, SignedData};
use crate::der;
use crate::i18n::{tr, trf};
use crate::p12::Key;
use crate::report::{SignResult, SignerReport, VerifyReport};
use crate::trust::TrustStore;
use crate::tsp::TstInfo;
use crate::{Error, Result, gost, ocsp, sign, time, verify};

// ------------------------------------------------------------------ languages

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardLang {
    Ru,
    Kk,
    /// Both, Kazakh first.
    KkRu,
}

impl CardLang {
    pub fn parse(s: &str) -> Option<CardLang> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ru" => Some(CardLang::Ru),
            "kk" | "kz" => Some(CardLang::Kk),
            "kk/ru" | "kk-ru" | "kkru" => Some(CardLang::KkRu),
            _ => None,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            CardLang::Ru => "ru",
            CardLang::Kk => "kk",
            CardLang::KkRu => "kk/ru",
        }
    }
}

/// (Russian, Kazakh). The card's texts, from ddc's translations.go where it has them.
const TEXTS: &[(&str, &str)] = &[
    ("стр. {} из {}", "{1} беттің {0} беті"),
    (
        "Подлинник электронного документа",
        "Электрондық құжаттың түпнұсқасы",
    ),
    ("ЭЦП, {}", "ЭСҚ, {}"),
    (
        "КАРТОЧКА ЭЛЕКТРОННОГО ДОКУМЕНТА",
        "ЭЛЕКТРОНДЫҚ ҚҰЖАТТЫҢ КАРТОЧКАСЫ",
    ),
    ("Дата и время формирования", "Жасалу күні мен уақыты"),
    (
        "Информационная система или сервис",
        "Ақпараттық жүйе немесе сервис",
    ),
    ("Содержание:", "Мазмұны:"),
    ("Информационный блок", "Ақпараттық блок"),
    (
        "Визуализация электронного документа",
        "Электрондық құжатты визуалдау",
    ),
    (
        "Визуализация подписей под электронным документом",
        "Электрондық құжатта қол қоюды визуалдау",
    ),
    (
        "Перечень вложенных файлов:",
        "Тіркемеленген файлдар тізімі:",
    ),
    (
        "Карточка электронного документа",
        "Электрондық құжат карточкасы",
    ),
    (
        "ВИЗУАЛИЗАЦИЯ ЭЛЕКТРОННОГО ДОКУМЕНТА",
        "ЭЛЕКТРОНДЫҚ ҚҰЖАТТЫ ВИЗУАЛДАУ",
    ),
    (
        "Визуализация электронной цифровой подписи",
        "Электрондық сандық қолтаңбаның визуалдауы",
    ),
    ("Подпись №{}", "Қолтаңба №{}"),
    ("Дата формирования подписи:", "Қолтаңба жасалған күн:"),
    ("ИИН {}", "ЖСН {}"),
    ("Подписал(а):", "Қол қойды:"),
    ("Шаблон:", "Үлгі:"),
    ("{}, БИН {}", "{}, БСН {}"),
    ("Допустимое использование:", "Рұқсат етілген пайдалану:"),
    ("Субъект: {}", "Субъект: {}"),
    ("Серийный номер: {}", "Сериялық нөмір: {}"),
    ("С: {}", "Бастап: {}"),
    ("По: {}", "Дейін: {}"),
    ("Издатель: {}", "Басып шығарушы: {}"),
    ("Метка времени: {}", "Уақыт белгісі: {}"),
    ("Сформирован: {}", "Қалыптасты: {}"),
    ("Алгоритм: {}", "Алгоритм: {}"),
    (
        "При формировании карточки электронного документа была автоматически выполнена процедура проверки ЭЦП в соответствии с положениями Приказа Министра по инвестициям и развитию Республики Казахстан «Об утверждении Правил проверки подлинности электронной цифровой подписи».\n\nКарточка электронного документа — это файл в формате PDF, состоящий из визуально отображаемой части и вложенных файлов.\n\nВизуально отображаемая часть карточки электронного документа носит исключительно информативный характер и не обладает юридической значимостью.\n\nМногие программы для просмотра PDF поддерживают вложенные файлы, позволяют просматривать их и сохранять как обычные файлы. Среди них Adobe Acrobat Reader и браузер Firefox.\n\nВ соответствии с Цифровым кодексом Республики Казахстан, подлинник электронного документа обладает юридической значимостью в том случае, если он подписан ЭЦП и были выполнены проверки подписи в соответствии с утвержденными правилами.\n\n{}\n\nВНИМАНИЕ! Остерегайтесь мошенников! При получении электронных документов, обязательно выполняйте проверку подписей! Злоумышленники могут пробовать подделывать или менять визуально отображаемую часть карточки, так как она не защищена от изменения цифровой подписью.",
        "Электрондық құжат карточкасын қалыптастыру кезінде ЭСҚ тексеру рәсімі «Электрондық сандық қолтаңбаның төлнұсқалығын тексеру қағидаларын бекіту туралы» Қазақстан Республикасы Инвестициялар және даму министрінің бұйрығының ережелеріне сәйкес автоматты түрде жүзеге асырылды.\n\nЭлектрондық құжат карточкасы – бұл визуалды түрде көрсетілетін бөліктен және оған қоса берілген файлдардан тұратын PDF файлы.\n\nЭлектрондық құжат карточкасының визуалды көрсетілетін бөлігі тек ақпараттық мақсатта және оның заңдық мәні жоқ.\n\nКөптеген PDF-ті қарауға арналған бағдарламалары тіркемеленген файлдарды қолдайды және оларды кәдімгі файлдар ретінде көруге және сақтауға мүмкіндік береді. Олардың ішінде Adobe Acrobat Reader және Firefox веб шолғышы бар.\n\nҚазақстан Республикасының Цифрлық кодексіне сәйкес электрондық құжаттың түпнұсқасы ЭСҚ-мен қол қойылған және қолтаңбаны тексеру бекітілген ережелерге сәйкес жүргізілген болса, оның заңдық мәні болады.\n\n{}\n\nНАЗАР АУДАРЫҢЫЗ! Алаяқтардан сақ болыңыз! Электрондық құжаттарды алу кезінде міндетті түрде қолтаңбаларды тексеріңіз! Алаяқтар картаның визуалды түрде көрсетілген бөлігін қолдан жасауға немесе өзгертуге әрекеттенуі мүмкін, себебі ол сандық қолтаңба өзгертуінен қорғалмаған.",
    ),
    (
        "Чтобы проверить подписи, откройте этот файл в kzsigner (вкладка «Проверить / Извлечь») или выполните команду «kzsigner verify ФАЙЛ»; подлинник документа сохраняет команда «kzsigner extract ФАЙЛ». Карточку также можно проверить в любой системе, поддерживающей формат карточки электронного документа, например на sigex.kz.",
        "Қолтаңбаларды тексеру үшін осы файлды kzsigner бағдарламасында ашыңыз («Тексеру / Шығарып алу» қойындысы) немесе «kzsigner verify ФАЙЛ» пәрменін орындаңыз; құжаттың түпнұсқасын «kzsigner extract ФАЙЛ» пәрмені сақтайды. Карточканы электрондық құжат карточкасы пішімін қолдайтын кез келген жүйеде, мысалы sigex.kz сайтында да тексеруге болады.",
    ),
];

/// `{}` placeholders filled in order; `{0}`, `{1}` by position.
fn fill(t: &str, args: &[&str]) -> String {
    let mut s = t.to_string();
    for (i, a) in args.iter().enumerate() {
        s = s.replace(&format!("{{{i}}}"), a);
    }
    for a in args {
        if let Some(p) = s.find("{}") {
            s.replace_range(p..p + 2, a);
        }
    }
    s
}

fn t(l: CardLang, ru: &'static str, args: &[&str]) -> String {
    let kk = TEXTS.iter().find(|x| x.0 == ru).map_or(ru, |x| x.1);
    match l {
        CardLang::Ru => fill(ru, args),
        CardLang::Kk => fill(kk, args),
        CardLang::KkRu if kk == ru => fill(ru, args),
        // long texts: whole paragraphs in each language
        CardLang::KkRu if ru.contains('\n') => format!("{}\n\n{}", fill(kk, args), fill(ru, args)),
        CardLang::KkRu => format!("{} / {}", fill(kk, args), fill(ru, args)),
    }
}

// ------------------------------------------------------------------ signing for a card

/// mime-type (ETSI EN 319 122-1, 5.2.4.2)
const ATTR_MIME_TYPE: &str = "0.4.0.1733.2.1";
/// id-ri-ocsp-response (RFC 5940)
const RI_OCSP: &str = "1.3.6.1.5.5.7.16.2";

pub fn mime_type(file_name: &str) -> &'static str {
    let ext = file_name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "xml" => "application/xml",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

/// A detached CMS over `doc` the way the card wants it: CAdES with mime-type, an NCA
/// timestamp, the certificate chain up to the root, and the OCSP answer for the signer's
/// certificate in `crls` (RFC 5940). A missing OCSP answer only warns.
pub fn sign_for_card(
    doc: &[u8],
    file_name: &str,
    key: &Key,
    tsa_url: &str,
    ocsp_url: &str,
    trust: &TrustStore,
    r: &mut SignResult,
) -> Result<Vec<u8>> {
    let mime = cms::attribute(
        ATTR_MIME_TYPE,
        &der::tlv(der::UTF8_STRING, mime_type(file_name).as_bytes()),
    );
    let mut sd = cms::sign_once_with(
        doc,
        cms::ID_DATA,
        false,
        &key.private_key,
        &key.cert,
        true,
        &[mime],
    )
    .map_err(|e| Error::new(trf("Signing failed: {}", &[&e])))?;
    sign::timestamp(&mut sd, tsa_url, key, trust, r)?;
    let chain = trust.check(&key.cert, time::now_ms());
    for c in &chain.issuers {
        if !sd.certs.contains(&c.der) {
            sd.certs.push(c.der.clone());
        }
    }
    // the key was checked before signing, so its issuer is known
    let issuer = chain
        .issuer
        .as_ref()
        .ok_or_else(|| Error::new(chain.status.clone()))?;
    match ocsp::fetch(&key.cert, issuer, ocsp_url, trust) {
        Ok(a) if a.good => {
            let other = der::tlv(der::ctx(1), &der::cat(&[&der::oid(RI_OCSP), &a.raw]));
            sd.crls = Some(der::tlv(der::ctx(1), &other));
            // the same answer where Order 500/НҚ p.8 names it: the CAdES revocationValues
            // attribute, ocspVals [1] SEQUENCE OF BasicOCSPResponse (RFC 5126 §6.3.4)
            if let Some(basic) = ocsp::basic_response(&a.raw) {
                let values = der::seq(&[&der::tlv(der::ctx(1), &der::seq(&[&basic]))]);
                sd.signers[0].add_unsigned(ATTR_REVOCATION_VALUES, &values);
            }
        }
        Ok(a) => {
            return Err(Error::new(trf(
                "The certificate is not usable for signing: {}",
                &[&a.status],
            )));
        }
        Err(e) => {
            // no OCSP answer: the CA's revocation list still decides whether to sign (p.4.3)
            let (_, status, answer) = crate::crl::check(&key.cert, Some(issuer));
            if !answer.is_empty() && answer != "good" {
                return Err(Error::new(trf(
                    "The certificate is not usable for signing: {}",
                    &[&status],
                )));
            }
            r.warnings.push(trf(
                "No OCSP answer could be embedded in the signature ({}); the card does not fully meet its specification.",
                &[&e],
            ));
            if answer.is_empty() {
                r.warnings.push(trf(
                    "Could not check that your key is not revoked: {}",
                    &[&status],
                ));
            }
        }
    }
    Ok(sd.encode())
}

/// id-aa-ets-revocationValues (CAdES, RFC 5126).
pub const ATTR_REVOCATION_VALUES: &str = "1.2.840.113549.1.9.16.2.24";

/// The OCSP response embedded in a SignedData's `crls` (RFC 5940), or else in the first
/// signer's revocationValues attribute, if any.
pub fn embedded_ocsp(sd: &SignedData) -> Option<Vec<u8>> {
    in_crls(sd).or_else(|| in_revocation_values(sd))
}

fn in_revocation_values(sd: &SignedData) -> Option<Vec<u8>> {
    let (_, values) = sd
        .signers
        .first()?
        .unsigned()
        .into_iter()
        .find(|(o, _)| o == ATTR_REVOCATION_VALUES)?;
    let rv = der::parse(values.first()?).ok()?;
    for v in rv.children().ok()? {
        if v.tag == der::ctx(1) {
            let basic = v.inner().ok()?.children().ok()?;
            return Some(ocsp::wrap_basic(basic.first()?.raw));
        }
    }
    None
}

fn in_crls(sd: &SignedData) -> Option<Vec<u8>> {
    let crls = sd.crls.as_ref()?;
    let t = der::parse(crls).ok()?;
    for c in t.children().ok()? {
        if c.tag != der::ctx(1) {
            continue;
        }
        let k = c.children().ok()?;
        if k.first()?.oid().ok()? == RI_OCSP {
            return Some(k.get(1)?.raw.to_vec());
        }
    }
    None
}

// ------------------------------------------------------------------ what a signature shows

struct SigView {
    name: String,
    iin: Option<String>,
    org: Option<(String, String)>,
    subject: String,
    serial: String,
    from: String,
    until: String,
    policies: Vec<String>,
    usages: Vec<String>,
    issuer: String,
    algorithm: String,
    /// (time, TSA serial, subject, issuer)
    tsp: Option<(String, String, String, String)>,
    tsp_ms: Option<i64>,
    /// (status, time, responder serial, subject, issuer)
    ocsp: Option<(String, String, String, String, String)>,
}

/// "19.05.2021 04:01:52 UTC+5", in Astana's time.
pub fn astana(ms: i64) -> String {
    let t = chrono::DateTime::from_timestamp_millis(ms + 5 * 3600 * 1000).unwrap_or_default();
    format!("{} UTC+5", t.format("%d.%m.%Y %H:%M:%S"))
}

fn dn(name: &[u8]) -> String {
    cert::rdns(name)
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn policies(c: &Cert) -> Vec<String> {
    c.policies()
        .and_then(|p| p.ok())
        .unwrap_or_default()
        .into_iter()
        .map(|o| match o.as_str() {
            "1.2.398.3.3.2.1" => format!("Политика применения регистрационных свидетельств электронной цифровой подписи юридических лиц Республики Казахстан ({o})"),
            _ => o,
        })
        .collect()
}

fn usages(c: &Cert) -> Vec<String> {
    const KU: [&str; 9] = [
        "Цифровая подпись (digitalSignature)",
        "Неотказуемость (nonRepudiation)",
        "Шифрование ключей (keyEncipherment)",
        "Шифрование данных (dataEncipherment)",
        "Согласование ключей (keyAgreement)",
        "Подпись сертификатов (keyCertSign)",
        "Подпись списков отзыва (cRLSign)",
        "Только шифрование (encipherOnly)",
        "Только расшифрование (decipherOnly)",
    ];
    let mut out: Vec<String> = c
        .key_usage()
        .unwrap_or_default()
        .iter()
        .zip(KU)
        .filter(|(on, _)| **on)
        .map(|(_, n)| n.to_string())
        .collect();
    for o in c.extended_key_usage() {
        let name = match o.as_str() {
            "1.3.6.1.5.5.7.3.2" => "Аутентификация клиента",
            "1.3.6.1.5.5.7.3.4" => "Защищенная электронная почта",
            "1.2.398.3.3.4.1.1" => "Физическое лицо",
            "1.2.398.3.3.4.1.2" => "Юридическое лицо",
            "1.2.398.3.3.4.1.2.1" => "Первый руководитель юридического лица",
            "1.2.398.3.3.4.1.2.2" => "Лицо, наделенное правом подписи",
            "1.2.398.3.3.4.1.2.3" => "Лицо, наделенное правом подписи финансовых документов",
            "1.2.398.3.3.4.1.2.4" => "Сотрудник отдела кадров",
            "1.2.398.3.3.4.1.2.5" => "Сотрудник организации",
            _ => "",
        };
        out.push(if name.is_empty() {
            o
        } else {
            format!("{name} ({o})")
        });
    }
    out
}

fn view(cms: &[u8], trust: &TrustStore) -> Result<SigView> {
    let sd = SignedData::parse(cms)?;
    let si = sd
        .signers
        .first()
        .ok_or_else(|| Error::new(tr("The file contains no signatures.")))?;
    let c = sd
        .signer_cert(si)
        .ok_or_else(|| Error::new(tr("The signer's certificate is not included in the .cms, so this signature cannot be checked.")))?;
    let mut sr = SignerReport::default();
    cert::describe(&mut sr, &c);
    let org = sr
        .get("O")
        .map(|o| (o.to_string(), sr.get("BIN").unwrap_or("").to_string()));
    let mut v = SigView {
        name: sr.name(),
        iin: sr.get("IIN").map(str::to_string),
        org,
        subject: dn(&c.subject),
        serial: c.serial_hex(),
        from: astana(c.not_before),
        until: astana(c.not_after),
        policies: policies(&c),
        usages: usages(&c),
        issuer: dn(&c.issuer),
        algorithm: format!(
            "{} ({})",
            cert::alg_name(&si.sig_alg, Some(&si.digest_alg)),
            si.sig_alg
        ),
        tsp: None,
        tsp_ms: None,
        ocsp: None,
    };
    if let Some(tok) = si
        .unsigned()
        .into_iter()
        .find(|(o, _)| o == cms::ATTR_TIMESTAMP_TOKEN)
        .and_then(|(_, v)| v.into_iter().next())
        && let Ok(ts) = SignedData::parse_inner(&tok)
        && let Some(info) = ts.content.as_deref().and_then(|c| TstInfo::parse(c).ok())
    {
        let tsa = ts.signers.first().and_then(|s| ts.signer_cert(s));
        v.tsp_ms = Some(info.gen_time);
        v.tsp = Some((
            astana(info.gen_time),
            tsa.as_ref().map(Cert::serial_hex).unwrap_or_default(),
            tsa.as_ref().map(|c| dn(&c.subject)).unwrap_or_default(),
            tsa.as_ref().map(|c| dn(&c.issuer)).unwrap_or_default(),
        ));
    }
    if let Some(raw) = embedded_ocsp(&sd)
        && let Some(issuer) = trust
            .check(&c, v.tsp_ms.unwrap_or_else(time::now_ms))
            .issuer
        && let Ok(a) = ocsp::read_embedded(&raw, &c, &issuer, trust)
    {
        let r = a.responder.as_ref();
        v.ocsp = Some((
            a.cert_status.to_string(),
            a.this_update.map(astana).unwrap_or_default(),
            r.map(Cert::serial_hex).unwrap_or_default(),
            r.map(|c| dn(&c.subject)).unwrap_or_default(),
            r.map(|c| dn(&c.issuer)).unwrap_or_default(),
        ));
    }
    Ok(v)
}

// ------------------------------------------------------------------ building

pub struct CardInput<'a> {
    pub doc: &'a [u8],
    pub file_name: &'a str,
    /// The signatures, as CMS files: (attachment file name, bytes).
    pub signatures: Vec<(String, Vec<u8>)>,
    pub lang: CardLang,
    /// Put each signature on its page as QR codes too.
    pub qr: bool,
}

// page geometry in mm, as in ddc
const LEFT: f64 = 30.0;
const RIGHT: f64 = 10.0;
const TOP: f64 = 10.0;
const BOTTOM: f64 = 10.0;
const HEADER: f64 = 10.0;
const FOOTER: f64 = 10.0;
const CONTENT_TOP: f64 = TOP + HEADER + 5.0;

struct Section {
    page: Page,
    header: Option<String>,
}

/// Attachment file name for signature `n` of `file_name`.
pub fn signature_file_name(file_name: &str, n: usize) -> String {
    format!("{file_name}.{n}.cms")
}

/// Builds the card. Every signature is checked first: a card is only made for signatures that
/// are valid.
pub fn build(input: &CardInput, trust: &TrustStore) -> Result<Vec<u8>> {
    let l = input.lang;
    // check, then order the signatures by their proven time
    let mut sigs = Vec::new();
    for (name, cms) in &input.signatures {
        let rep = verify::verify(cms, Some(input.doc), trust, None)?;
        if !rep.valid {
            let why = rep
                .signers
                .iter()
                .find(|s| !s.valid)
                .and_then(|s| {
                    s.signature_error
                        .clone()
                        .or_else(|| s.chain_ok.then(|| s.usage_error.clone()).flatten())
                        .or(Some(s.chain_status.clone().unwrap_or_default()))
                })
                .unwrap_or_default();
            return Err(Error::new(trf(
                "Signature {} is not valid, so no card was made: {}",
                &[name, &why],
            )));
        }
        let v = view(cms, trust)?;
        let at = rep.signers[0]
            .trusted_time()
            .or(rep.signers[0].signing_time)
            .unwrap_or(0);
        sigs.push((at, name.clone(), cms.clone(), v));
    }
    sigs.sort_by_key(|s| s.0);

    let mut w = Writer::new();
    let mut out = Document::with_version("1.7");
    let created = astana(time::now_ms());
    let builder = format!("kzsigner {}", crate::version());
    let width = A4.0 - LEFT - RIGHT;

    // the document's own pages
    let imported = if super::is_pdf(input.doc) {
        Document::load_mem(input.doc)
            .ok()
            .filter(|d| !d.is_encrypted())
            .and_then(|d| import::import_pages(&d, &mut out).ok())
            .unwrap_or_default()
    } else {
        vec![]
    };

    let attachments: Vec<(String, String)> = std::iter::once((
        input.file_name.to_string(),
        t(l, "Подлинник электронного документа", &[]),
    ))
    .chain(
        sigs.iter()
            .map(|(_, n, _, v)| (n.clone(), t(l, "ЭЦП, {}", &[&v.name]))),
    )
    .collect();

    // the information block takes as many pages as it needs; lay it out once to count them
    let info = |w: &mut Writer, first_doc_page: usize, first_sig_page: usize| -> Vec<Page> {
        let mut pages = vec![Page::new(false)];
        let bottom = A4.1 - BOTTOM - FOOTER;
        let mut y = TOP + 2.0;
        let put = |w: &mut Writer,
                   pages: &mut Vec<Page>,
                   y: &mut f64,
                   x: f64,
                   cw: f64,
                   size: f64,
                   grey: f64,
                   s: &str| {
            for line in w.wrap(s, size, cw) {
                let lh = leading(size);
                if *y + lh > bottom {
                    pages.push(Page::new(false));
                    *y = CONTENT_TOP;
                }
                *y += lh;
                let p = pages.last_mut().expect("a page");
                w.text(p, x, *y - lh * 0.25, size, grey, &line);
            }
        };
        let centred = |w: &mut Writer, p: &mut Page, y: f64, size: f64, s: &str| {
            let x = LEFT + (width - w.width(s, size)) / 2.0;
            w.text(p, x.max(LEFT), y, size, 0.0, s);
        };
        for line in t(l, "КАРТОЧКА ЭЛЕКТРОННОГО ДОКУМЕНТА", &[]).split(" / ")
        {
            y += leading(14.0);
            centred(w, &mut pages[0], y, 14.0, line);
        }
        y += 8.0;
        for line in w.wrap(input.file_name, 13.0, width) {
            y += leading(13.0);
            centred(w, &mut pages[0], y, 13.0, &line);
        }
        y += 5.0;
        let half = width / 2.0;
        let y0 = y;
        let mut y1 = y;
        put(
            w,
            &mut pages,
            &mut y1,
            LEFT,
            half - 2.0,
            10.0,
            0.35,
            &t(l, "Дата и время формирования", &[]),
        );
        put(
            w,
            &mut pages,
            &mut y1,
            LEFT,
            half - 2.0,
            11.0,
            0.0,
            &created,
        );
        let mut y2 = y0;
        put(
            w,
            &mut pages,
            &mut y2,
            LEFT + half,
            half,
            10.0,
            0.35,
            &t(l, "Информационная система или сервис", &[]),
        );
        put(
            w,
            &mut pages,
            &mut y2,
            LEFT + half,
            half,
            11.0,
            0.0,
            &builder,
        );
        y = y1.max(y2) + 5.0;

        put(
            w,
            &mut pages,
            &mut y,
            LEFT,
            width,
            11.5,
            0.0,
            &t(l, "Содержание:", &[]),
        );
        let pg = |n: usize| {
            if n == 0 {
                "-".to_string()
            } else {
                n.to_string()
            }
        };
        for (label, n) in [
            (t(l, "Информационный блок", &[]), "1".to_string()),
            (
                t(l, "Визуализация электронного документа", &[]),
                pg(first_doc_page),
            ),
            (
                t(l, "Визуализация подписей под электронным документом", &[]),
                pg(first_sig_page),
            ),
        ] {
            let before = y;
            put(w, &mut pages, &mut y, LEFT, width - 12.0, 10.5, 0.0, &label);
            let p = pages.last_mut().expect("a page");
            let nx = LEFT + width - w.width(&n, 10.5);
            w.text(
                p,
                nx,
                if y > before {
                    y - leading(10.5) * 0.25
                } else {
                    y
                },
                10.5,
                0.0,
                &n,
            );
        }
        y += 4.0;
        put(
            w,
            &mut pages,
            &mut y,
            LEFT,
            width,
            11.5,
            0.0,
            &t(l, "Перечень вложенных файлов:", &[]),
        );
        for (i, (name, desc)) in attachments.iter().enumerate() {
            let start = y;
            let start_page = pages.len();
            put(
                w,
                &mut pages,
                &mut y,
                LEFT,
                10.0,
                10.0,
                0.0,
                &format!("{}.", i + 1),
            );
            let mut yn = start;
            if pages.len() == start_page {
                put(
                    w,
                    &mut pages,
                    &mut yn,
                    LEFT + 11.0,
                    width - 11.0 - 75.0,
                    10.0,
                    0.0,
                    name,
                );
                let mut yd = start;
                put(
                    w,
                    &mut pages,
                    &mut yd,
                    LEFT + width - 75.0,
                    75.0,
                    10.0,
                    0.35,
                    desc,
                );
                y = y.max(yn).max(yd);
            }
        }
        y += 4.0;
        let note_in = |l: CardLang| {
            t(
                l,
                "При формировании карточки электронного документа была автоматически выполнена процедура проверки ЭЦП в соответствии с положениями Приказа Министра по инвестициям и развитию Республики Казахстан «Об утверждении Правил проверки подлинности электронной цифровой подписи».\n\nКарточка электронного документа — это файл в формате PDF, состоящий из визуально отображаемой части и вложенных файлов.\n\nВизуально отображаемая часть карточки электронного документа носит исключительно информативный характер и не обладает юридической значимостью.\n\nМногие программы для просмотра PDF поддерживают вложенные файлы, позволяют просматривать их и сохранять как обычные файлы. Среди них Adobe Acrobat Reader и браузер Firefox.\n\nВ соответствии с Цифровым кодексом Республики Казахстан, подлинник электронного документа обладает юридической значимостью в том случае, если он подписан ЭЦП и были выполнены проверки подписи в соответствии с утвержденными правилами.\n\n{}\n\nВНИМАНИЕ! Остерегайтесь мошенников! При получении электронных документов, обязательно выполняйте проверку подписей! Злоумышленники могут пробовать подделывать или менять визуально отображаемую часть карточки, так как она не защищена от изменения цифровой подписью.",
                &[&t(
                    l,
                    "Чтобы проверить подписи, откройте этот файл в kzsigner (вкладка «Проверить / Извлечь») или выполните команду «kzsigner verify ФАЙЛ»; подлинник документа сохраняет команда «kzsigner extract ФАЙЛ». Карточку также можно проверить в любой системе, поддерживающей формат карточки электронного документа, например на sigex.kz.",
                    &[],
                )],
            )
        };
        let note = match l {
            CardLang::KkRu => format!("{}\n\n{}", note_in(CardLang::Kk), note_in(CardLang::Ru)),
            l => note_in(l),
        };
        put(w, &mut pages, &mut y, LEFT, width, 9.0, 0.2, &note);
        pages
    };
    let mut probe = Writer::new();
    let info_pages = info(&mut probe, 1, 1).len();
    let first_doc = if imported.is_empty() {
        0
    } else {
        info_pages + 1
    };
    let first_sig = info_pages + imported.len() + 1;

    let mut sections: Vec<Section> = info(&mut w, first_doc, first_sig)
        .into_iter()
        .map(|p| Section {
            page: p,
            header: None,
        })
        .collect();

    // the document's pages, scaled into the content area, with a watermark
    for (i, im) in imported.iter().enumerate() {
        let landscape = im.w > im.h;
        let mut p = Page::new(landscape);
        let (maxw, maxh) = (p.w - LEFT - RIGHT, p.h - TOP - BOTTOM - HEADER - FOOTER);
        let (mut pw, mut ph) = (im.w / MM, im.h / MM);
        if pw > maxw {
            ph *= maxw / pw;
            pw = maxw;
        }
        if ph > maxh {
            pw *= maxh / ph;
            ph = maxh;
        }
        let x = LEFT + ((maxw - pw) / 2.0).max(0.0);
        let y = TOP + HEADER + ((maxh - ph) / 2.0).max(0.0);
        p.form(&format!("P{}", i + 1), im.id, x, y, pw, ph, (im.w, im.h));
        p.rect(x, y, pw, ph, 0.83);
        let mark = t(l, "ВИЗУАЛИЗАЦИЯ ЭЛЕКТРОННОГО ДОКУМЕНТА", &[]);
        let size = (20.0f64).min(pw.hypot(ph) * MM * 0.8 / w.font.text_width(&mark, 1.0).max(1.0));
        w.watermark(&mut p, x + pw / 2.0, y + ph / 2.0, size, 45.0, &mark);
        sections.push(Section {
            page: p,
            header: Some(t(l, "Визуализация электронного документа", &[])),
        });
    }

    // one page per signature
    for (k, (_, name, cms, v)) in sigs.iter().enumerate() {
        let mut p = Page::new(false);
        let left_w = width / 3.0 * 2.0;
        let right_x = LEFT + left_w;
        let right_w = width / 3.0;
        let mut y = CONTENT_TOP;
        let put = |w: &mut Writer, p: &mut Page, y: &mut f64, size: f64, grey: f64, s: &str| {
            *y = w.para(p, LEFT, *y, left_w - 3.0, size, grey, s);
        };
        put(
            &mut w,
            &mut p,
            &mut y,
            10.5,
            0.0,
            &t(l, "Подпись №{}", &[&(k + 1).to_string()]),
        );
        y += 1.5;
        put(
            &mut w,
            &mut p,
            &mut y,
            8.0,
            0.35,
            &t(l, "Дата формирования подписи:", &[]),
        );
        put(
            &mut w,
            &mut p,
            &mut y,
            8.5,
            0.0,
            &v.tsp
                .as_ref()
                .map(|t| t.0.clone())
                .unwrap_or_else(|| "-".into()),
        );
        y += 1.5;
        put(
            &mut w,
            &mut p,
            &mut y,
            8.0,
            0.35,
            &t(l, "Подписал(а):", &[]),
        );
        let mut who = v.name.clone();
        if let Some(iin) = &v.iin {
            who = format!("{who}, {}", t(l, "ИИН {}", &[iin]));
        }
        if let Some((org, bin)) = &v.org {
            who = format!("{who}\n{}", t(l, "{}, БИН {}", &[org, bin]));
        }
        put(&mut w, &mut p, &mut y, 8.5, 0.0, &who);
        if !v.policies.is_empty() {
            y += 1.5;
            put(&mut w, &mut p, &mut y, 8.0, 0.35, &t(l, "Шаблон:", &[]));
            for s in &v.policies {
                put(&mut w, &mut p, &mut y, 8.5, 0.0, &format!("- {s}"));
            }
        }
        if !v.usages.is_empty() {
            y += 1.5;
            put(
                &mut w,
                &mut p,
                &mut y,
                8.0,
                0.35,
                &t(l, "Допустимое использование:", &[]),
            );
            for s in &v.usages {
                put(&mut w, &mut p, &mut y, 8.5, 0.0, &format!("- {s}"));
            }
        }
        // the right column: boxes with the certificate, timestamp and OCSP details
        let mut yr = CONTENT_TOP;
        let boxed = |w: &mut Writer, p: &mut Page, yr: &mut f64, lines: Vec<String>| {
            let top = *yr;
            *yr = w.para(
                p,
                right_x + 1.0,
                *yr + 0.5,
                right_w - 2.0,
                6.0,
                0.0,
                &lines.join("\n"),
            ) + 0.8;
            p.rect(right_x, top, right_w, *yr - top, 0.83);
            *yr += 1.5;
        };
        boxed(
            &mut w,
            &mut p,
            &mut yr,
            vec![
                t(l, "Субъект: {}", &[&v.subject]),
                t(l, "Серийный номер: {}", &[&v.serial]),
                t(l, "С: {}", &[&v.from]),
                t(l, "По: {}", &[&v.until]),
                t(l, "Издатель: {}", &[&v.issuer]),
                t(l, "Алгоритм: {}", &[&v.algorithm]),
            ],
        );
        if let Some((at, serial, subject, issuer)) = &v.tsp {
            boxed(
                &mut w,
                &mut p,
                &mut yr,
                vec![
                    t(l, "Метка времени: {}", &[at]),
                    t(l, "Субъект: {}", &[subject]),
                    t(l, "Серийный номер: {}", &[serial]),
                    t(l, "Издатель: {}", &[issuer]),
                ],
            );
        }
        if let Some((status, at, serial, subject, issuer)) = &v.ocsp {
            boxed(
                &mut w,
                &mut p,
                &mut yr,
                vec![
                    format!("OCSP: {status}"),
                    t(l, "Сформирован: {}", &[at]),
                    t(l, "Субъект: {}", &[subject]),
                    t(l, "Серийный номер: {}", &[serial]),
                    t(l, "Издатель: {}", &[issuer]),
                ],
            );
        }
        let mut pages = vec![p];
        if input.qr {
            let codes = qr::payloads((k + 1) as u32, cms)?;
            let size = 42.0;
            let per_row = 4;
            let gap = (width - size * per_row as f64) / (per_row as f64 + 2.0);
            let mut qy = y.max(yr) + 5.0 + gap;
            for (i, c) in codes.iter().enumerate() {
                let col = i % per_row;
                if col == 0 && i > 0 {
                    qy += gap + size;
                }
                if qy + size > A4.1 - BOTTOM - FOOTER {
                    pages.push(Page::new(false));
                    qy = CONTENT_TOP;
                }
                let x = LEFT + gap * (col as f64 + 1.0) + size * col as f64;
                let q = qr::code(c)?;
                pages.last_mut().expect("a page").qr(x, qy, size, &q);
            }
        }
        let _ = name;
        for p in pages {
            sections.push(Section {
                page: p,
                header: Some(t(l, "Визуализация электронной цифровой подписи", &[])),
            });
        }
    }

    // headers and footers, now that the page count is known
    let total = sections.len().to_string();
    let footer = t(l, "Карточка электронного документа", &[]);
    let desc: String = {
        let d: String = input.file_name.chars().take(87).collect();
        if input.file_name.chars().count() > 90 {
            format!("{d}...")
        } else {
            input.file_name.to_string()
        }
    };
    for (i, s) in sections.iter_mut().enumerate() {
        let p = &mut s.page;
        let right = p.w - RIGHT;
        let fy = p.h - BOTTOM - FOOTER;
        p.line(LEFT, TOP + HEADER, right, TOP + HEADER, 0.0);
        p.line(LEFT, fy, right, fy, 0.0);
        if let Some(h) = &s.header {
            let size = (10.5 * (right - LEFT) / w.width(h, 10.5).max(1.0)).min(10.5);
            w.text(p, LEFT, TOP + HEADER / 2.0 + 1.5, size, 0.0, h);
        }
        if i > 0 {
            w.text(p, LEFT, fy + 4.0, 8.0, 0.0, &footer);
            w.text(p, LEFT, fy + 8.0, 8.0, 0.35, &desc);
            let n = t(l, "стр. {} из {}", &[&(i + 1).to_string(), &total]);
            let nx = right - w.width(&n, 10.0);
            w.text(p, nx, fy + 6.5, 10.0, 0.0, &n);
        }
    }

    // assemble the PDF
    let font_id = w.font.embed(&w.used, &mut |o| out.add_object(o));
    let gs = out.add_object(Dictionary::from_iter([
        ("Type", Object::from("ExtGState")),
        ("ca", Object::Real(0.5)),
        ("CA", Object::Real(0.5)),
    ]));
    let pages_id = out.new_object_id();
    let mut kids = Vec::new();
    for s in sections {
        let p = s.page;
        let mut content = Stream::new(Dictionary::new(), p.ops.into_bytes());
        let _ = content.compress();
        let content_id = out.add_object(content);
        let mut res = Dictionary::from_iter([(
            "Font",
            Object::Dictionary(Dictionary::from_iter([("F1", Object::Reference(font_id))])),
        )]);
        if !p.xobjects.is_empty() {
            res.set(
                "XObject",
                Dictionary::from_iter(
                    p.xobjects
                        .iter()
                        .map(|(n, id)| (n.as_str(), Object::Reference(*id))),
                ),
            );
        }
        if p.alpha {
            res.set(
                "ExtGState",
                Dictionary::from_iter([("GS1", Object::Reference(gs))]),
            );
        }
        let page = Dictionary::from_iter([
            ("Type", Object::from("Page")),
            ("Parent", pages_id.into()),
            (
                "MediaBox",
                Object::Array(vec![
                    0.into(),
                    0.into(),
                    Object::Real((p.w * MM) as f32),
                    Object::Real((p.h * MM) as f32),
                ]),
            ),
            ("Resources", res.into()),
            ("Contents", content_id.into()),
        ]);
        kids.push(Object::Reference(out.add_object(page)));
    }
    let count = kids.len() as i64;
    out.objects.insert(
        pages_id,
        Dictionary::from_iter([
            ("Type", Object::from("Pages")),
            ("Kids", Object::Array(kids)),
            ("Count", count.into()),
        ])
        .into(),
    );

    // attachments: the original first, then the signatures in time order (as ddc writes them)
    let mut names = Vec::new();
    let files = std::iter::once((input.file_name.to_string(), input.doc.to_vec()))
        .chain(sigs.iter().map(|(_, n, c, _)| (n.clone(), c.clone())));
    for (i, ((name, data), (_, desc))) in files.zip(attachments.iter()).enumerate() {
        let mut ef = Stream::new(
            Dictionary::from_iter([
                ("Type", Object::from("EmbeddedFile")),
                (
                    "Params",
                    Object::Dictionary(Dictionary::from_iter([(
                        "Size",
                        Object::Integer(data.len() as i64),
                    )])),
                ),
            ]),
            data,
        );
        let _ = ef.compress();
        let ef_id = out.add_object(ef);
        let spec = out.add_object(Dictionary::from_iter([
            ("Type", Object::from("Filespec")),
            ("F", Object::string_literal(ascii_name(&name))),
            ("UF", utf16(&name)),
            (
                "EF",
                Object::Dictionary(Dictionary::from_iter([("F", Object::Reference(ef_id))])),
            ),
            ("Desc", utf16(desc)),
        ]));
        names.push(Object::string_literal(format!("Attachement{}", i + 1)));
        names.push(Object::Reference(spec));
    }
    let catalog = out.add_object(Dictionary::from_iter([
        ("Type", Object::from("Catalog")),
        ("Pages", pages_id.into()),
        (
            "Names",
            Object::Dictionary(Dictionary::from_iter([(
                "EmbeddedFiles",
                Object::Dictionary(Dictionary::from_iter([("Names", Object::Array(names))])),
            )])),
        ),
        ("PageMode", "UseAttachments".into()),
    ]));
    let info = out.add_object(Dictionary::from_iter([
        (
            "Title",
            utf16(&format!(
                "{} - {}",
                t(l, "Карточка электронного документа", &[]),
                input.file_name
            )),
        ),
        ("Producer", Object::string_literal(builder)),
        // how the card was made, so that adding a signature keeps it
        (
            "KzsignerCard",
            Object::string_literal(format!("{}{}", l.code(), if input.qr { ";qr" } else { "" })),
        ),
    ]));
    out.trailer.set("Root", catalog);
    out.trailer.set("Info", info);
    let mut data = Vec::new();
    out.save_to(&mut data)
        .map_err(|e| Error::new(format!("could not write the card: {e}")))?;
    Ok(data)
}

fn utf16(s: &str) -> Object {
    let mut b = vec![0xfe, 0xff];
    for u in s.encode_utf16() {
        b.extend(u.to_be_bytes());
    }
    Object::String(b, StringFormat::Hexadecimal)
}

/// The legacy /F file name: the name with non-ASCII characters replaced.
fn ascii_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn text_from(b: &[u8]) -> String {
    if let Some(rest) = b.strip_prefix(&[0xfe, 0xff]) {
        let u: Vec<u16> = rest
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u)
    } else {
        String::from_utf8(b.to_vec()).unwrap_or_else(|_| b.iter().map(|&c| c as char).collect())
    }
}

// ------------------------------------------------------------------ reading

/// A card's attachments: the original document and the signatures, in order.
pub struct Card {
    pub original: (String, Vec<u8>),
    pub signatures: Vec<(String, Vec<u8>)>,
    /// For a card kzsigner made: its language and whether it has QR codes.
    pub made_with: Option<(CardLang, bool)>,
}

/// The PDF's attachments (EmbeddedFiles name tree), in order.
fn attachments(doc: &Document) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let deref = |o: &Object| doc.dereference(o).ok().map(|(_, o)| o.clone());
    let Some(names) = doc
        .catalog()
        .ok()
        .and_then(|c| deref(c.get(b"Names").ok()?))
        .and_then(|n| deref(n.as_dict().ok()?.get(b"EmbeddedFiles").ok()?))
    else {
        return out;
    };
    let mut stack = vec![(names, 0)];
    let mut leaves = Vec::new();
    while let Some((node, depth)) = stack.pop() {
        let Ok(d) = node.as_dict() else { continue };
        if let Ok(a) = d.get(b"Names").and_then(Object::as_array) {
            leaves.extend(a.chunks_exact(2).filter_map(|p| deref(&p[1])));
        }
        if depth < 16
            && let Some(kids) = d.get(b"Kids").ok().and_then(deref)
            && let Ok(kids) = kids.as_array()
        {
            for k in kids.iter().rev() {
                if let Some(k) = deref(k) {
                    stack.push((k, depth + 1));
                }
            }
        }
    }
    for spec in leaves {
        let Ok(spec) = spec.as_dict() else { continue };
        let name = spec
            .get(b"UF")
            .or_else(|_| spec.get(b"F"))
            .and_then(Object::as_str)
            .map(text_from)
            .unwrap_or_default();
        let Some(ef) = spec.get(b"EF").ok().and_then(deref) else {
            continue;
        };
        let Some(stream) = ef.as_dict().ok().and_then(|e| deref(e.get(b"F").ok()?)) else {
            continue;
        };
        let Ok(s) = stream.as_stream() else { continue };
        let data = s
            .decompressed_content()
            .unwrap_or_else(|_| s.content.clone());
        out.push((name, data));
    }
    out
}

/// The card in a PDF, if it is one: attachments where all but the first are CMS signatures.
pub fn read(data: &[u8]) -> Option<Card> {
    let doc = Document::load_mem(data).ok()?;
    let mut files = attachments(&doc).into_iter();
    let original = files.next()?;
    let signatures: Vec<_> = files.collect();
    if signatures.is_empty()
        || !signatures
            .iter()
            .all(|(_, c)| SignedData::try_parse(c).is_some())
    {
        return None;
    }
    let made_with = doc
        .trailer
        .get(b"Info")
        .ok()
        .and_then(|i| doc.dereference(i).ok())
        .and_then(|(_, i)| {
            i.as_dict()
                .ok()?
                .get(b"KzsignerCard")
                .ok()?
                .as_str()
                .ok()
                .map(text_from)
        })
        .and_then(|s| {
            let (lang, rest) = s.split_once(';').unwrap_or((&s, ""));
            Some((CardLang::parse(lang)?, rest == "qr"))
        });
    Some(Card {
        original,
        signatures,
        made_with,
    })
}

/// Checks every signature in a card against the original document inside it. Without
/// `ocsp_url`, the OCSP answers embedded in the signatures are reported instead.
pub fn verify(card: &Card, trust: &TrustStore, ocsp_url: Option<&str>) -> VerifyReport {
    let doc = &card.original.1;
    let mut rep = VerifyReport {
        has_content: true,
        card_document: Some(card.original.0.clone()),
        content_size: doc.len() as u64,
        content_sha256: Some(crate::hex(&gost::sha256(doc))),
        ..Default::default()
    };
    for (name, cms) in &card.signatures {
        let mut s = match verify::verify(cms, Some(doc), trust, ocsp_url) {
            Ok(r) if r.signers.len() == 1 => r.signers.into_iter().next().unwrap_or_default(),
            Ok(_) => SignerReport {
                signature_error: Some(tr("A card signature must hold exactly one signer.").into()),
                ..Default::default()
            },
            Err(e) => SignerReport {
                signature_error: Some(e.0),
                ..Default::default()
            },
        };
        s.kind = Some(trf("Signature in the document card ({})", &[name]));
        if let Ok(sd) = SignedData::parse(cms) {
            if sd.content.is_some() {
                s.warnings.push(tr("The signature contains the document; a card's signatures should be detached.").into());
            }
            match embedded_ocsp(&sd) {
                Some(raw) if ocsp_url.is_none() => {
                    let c = sd.signers.first().and_then(|si| sd.signer_cert(si));
                    let at = s.trusted_time().unwrap_or_else(time::now_ms);
                    let issuer = c.as_ref().and_then(|c| trust.check(c, at).issuer);
                    if let (Some(c), Some(i)) = (c, issuer) {
                        match ocsp::read_embedded(&raw, &c, &i, trust) {
                            Ok(a) => {
                                s.ocsp_status = Some(trf("{} (answer kept in the signature)", &[&a.status]));
                                // a revoked certificate fails the signature; an answer that
                                // cannot be relied on only warns, as no answer would
                                if a.cert_status == "revoked" {
                                    s.valid = false;
                                }
                                if let (Some(u), Some(ts)) = (a.this_update, s.timestamp_time)
                                    && u + 5 * 60 * 1000 < ts
                                {
                                    s.warnings.push(tr("The kept OCSP answer is older than the signature's timestamp.").into());
                                }
                            }
                            Err(e) => s.ocsp_status = Some(trf("ERROR: could not check OCSP ({})", &[&e])),
                        }
                    }
                }
                None => s.warnings.push(tr("The signature carries no OCSP answer, which the card specification asks for.").into()),
                _ => {}
            }
            if s.timestamp_time.is_none() {
                s.warnings.push(
                    tr("The signature has no timestamp, which the card specification requires.")
                        .into(),
                );
            }
        }
        rep.signers.push(s);
    }
    for (k, s) in rep.signers.iter_mut().enumerate() {
        s.index = k + 1;
    }
    rep.valid = !rep.signers.is_empty() && rep.signers.iter().all(|s| s.valid);
    // the card PDF itself is not signed: anyone can edit its pages
    rep.warnings.push(
        tr("Only the document attached to the card is checked against its signatures. The card's pages (the document's image and the signature pages) are not signed and may differ from it; rely on the attached document.")
            .into(),
    );
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texts() {
        assert_eq!(t(CardLang::Ru, "стр. {} из {}", &["2", "5"]), "стр. 2 из 5");
        assert_eq!(
            t(CardLang::Kk, "стр. {} из {}", &["2", "5"]),
            "5 беттің 2 беті"
        );
        assert_eq!(t(CardLang::KkRu, "Шаблон:", &[]), "Үлгі: / Шаблон:");
        assert_eq!(astana(0), "01.01.1970 05:00:00 UTC+5");
        assert_eq!(mime_type("a.PDF"), "application/pdf");
    }
}
