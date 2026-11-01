//! The window's languages: English, Kazakh and Russian.
//!
//! Texts are written in English in the code as `tr("...")`, or `trf("... {} ...", &[..])` with
//! `{}` placeholders filled in order; [`TABLE`] holds the Kazakh and Russian for each. A test
//! checks that every `tr`/`trf` text in src/ is in the table with matching placeholders.
//! The command line stays in English: its output matches the Java kzsigner and scripts read it.

use std::fmt::Display;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En = 0,
    Kk = 1,
    Ru = 2,
}

impl Lang {
    pub const ALL: [Lang; 3] = [Lang::Kk, Lang::Ru, Lang::En];

    /// The language's own name, for the language menu.
    pub fn name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Kk => "Қазақша",
            Lang::Ru => "Русский",
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Kk => "kk",
            Lang::Ru => "ru",
        }
    }

    /// From a code or locale name: "kk", "kk_KZ.UTF-8", "ru-RU", "kz", ...
    pub fn parse(s: &str) -> Option<Lang> {
        let s = s.trim().to_ascii_lowercase();
        let p = s.split(['_', '-', '.', '@', ':']).next().unwrap_or("");
        match p {
            "en" => Some(Lang::En),
            "kk" | "kz" | "kaz" => Some(Lang::Kk),
            "ru" | "rus" => Some(Lang::Ru),
            _ => None,
        }
    }
}

static LANG: AtomicU8 = AtomicU8::new(Lang::En as u8);

pub fn lang() -> Lang {
    match LANG.load(Ordering::Relaxed) {
        1 => Lang::Kk,
        2 => Lang::Ru,
        _ => Lang::En,
    }
}

pub fn set(l: Lang) {
    LANG.store(l as u8, Ordering::Relaxed);
}

/// The text in the current language.
pub fn tr(en: &'static str) -> &'static str {
    tr_in(lang(), en)
}

/// The text in language `l`.
pub fn tr_in(l: Lang, en: &'static str) -> &'static str {
    if l == Lang::En {
        return en;
    }
    match TABLE.iter().find(|r| r.0 == en) {
        Some(r) if l == Lang::Kk => r.1,
        Some(r) => r.2,
        None => en,
    }
}

/// `tr(template)` with each `{}` replaced by the next argument.
pub fn trf(template: &'static str, args: &[&dyn Display]) -> String {
    trf_in(lang(), template, args)
}

/// `trf` in language `l`.
pub fn trf_in(l: Lang, template: &'static str, args: &[&dyn Display]) -> String {
    let mut out = String::new();
    let mut args = args.iter();
    let mut parts = tr_in(l, template).split("{}");
    if let Some(first) = parts.next() {
        out.push_str(first);
    }
    for p in parts {
        if let Some(a) = args.next() {
            out.push_str(&a.to_string());
        }
        out.push_str(p);
    }
    out
}

/// The language for the window: the one chosen in it before, else KZSIGNER_LANG, else the
/// system's language (Kazakh or Russian; anything else gives English).
pub fn detect() -> Lang {
    saved()
        .or_else(|| {
            std::env::var("KZSIGNER_LANG")
                .ok()
                .and_then(|v| Lang::parse(&v))
        })
        .or_else(system)
        .unwrap_or(Lang::En)
}

#[cfg(windows)]
fn system() -> Option<Lang> {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
    let mut buf = [0u16; 85];
    let n = unsafe { GetUserDefaultLocaleName(buf.as_mut_ptr(), buf.len() as i32) };
    if n <= 1 {
        return None;
    }
    Lang::parse(&String::from_utf16_lossy(&buf[..n as usize - 1]))
}

#[cfg(not(windows))]
fn system() -> Option<Lang> {
    // LANGUAGE is a list ("kk:ru"); the others a single locale
    for var in ["LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(var)
            && !v.is_empty()
        {
            return v.split(':').find_map(Lang::parse);
        }
    }
    None
}

fn config_file() -> Option<std::path::PathBuf> {
    let dir = if cfg!(windows) {
        std::env::var_os("APPDATA").map(std::path::PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join(".config")))
    }?;
    Some(dir.join("kzsigner").join("language"))
}

fn saved() -> Option<Lang> {
    Lang::parse(&std::fs::read_to_string(config_file()?).ok()?)
}

/// Remembers the language chosen in the window (best effort).
pub fn save(l: Lang) {
    if let Some(f) = config_file() {
        let _ = f.parent().map(std::fs::create_dir_all);
        let _ = std::fs::write(f, l.code());
    }
}

/// (English, Kazakh, Russian).
#[rustfmt::skip]
pub const TABLE: &[(&str, &str, &str)] = &[
    // window
    ("Could not open the window: {}", "Терезені ашу мүмкін болмады: {}", "Не удалось открыть окно: {}"),
    ("Sign", "Қол қою", "Подписать"),
    ("Verify / Extract", "Тексеру / Шығарып алу", "Проверить / Извлечь"),
    ("Error", "Қате", "Ошибка"),
    ("Browse…", "Шолу…", "Обзор…"),
    ("1. Document", "1. Құжат", "1. Документ"),
    ("Document to sign (or a .cms to add your signature to)", "Қол қойылатын құжат (немесе қолтаңбаңыз қосылатын .cms)", "Документ для подписи (или .cms, чтобы добавить в него свою подпись)"),
    ("Original document (only for a detached .cms)", "Түпнұсқа құжат (тек бөлек .cms үшін)", "Исходный документ (только для открепленной .cms)"),
    ("2. Your key", "2. Сіздің кілтіңіз", "2. Ваш ключ"),
    ("Key file (.p12), e.g. RSA_… or GOSTKNCA_…", "Кілт файлы (.p12), мысалы RSA_… немесе GOSTKNCA_…", "Файл ключа (.p12), например RSA_… или GOSTKNCA_…"),
    ("Password:", "Құпиясөз:", "Пароль:"),
    ("Key:", "Кілт:", "Ключ:"),
    ("3. Options", "3. Баптаулар", "3. Параметры"),
    ("Detached signature (the .cms will not contain the document)", "Бөлек қолтаңба (.cms ішінде құжат болмайды)", "Открепленная подпись (документ не войдет в .cms)"),
    ("Add NCA timestamp (needs internet, sends only a hash)", "ҰКО уақыт белгісін қосу (интернет керек, тек хеш жіберіледі)", "Добавить метку времени НУЦ (нужен интернет, отправляется только хеш)"),
    ("Sign…", "Қол қою…", "Подписать…"),
    ("Opening key…", "Кілт ашылуда…", "Ключ открывается…"),
    ("IIN {}", "ЖСН {}", "ИИН {}"),
    (" (BIN {})", " (БСН {})", " (БИН {})"),
    ("Valid until {} · {}", "{} дейін жарамды · {}", "Действителен до {} · {}"),
    ("Issuer: {} ✔", "Куәлікті берген: {} ✔", "Издатель: {} ✔"),
    ("Issuer: {} (not a trusted NCA RK issuer)", "Куәлікті берген: {} (ҚР ҰКО сенімді орталығы емес)", "Издатель: {} (не доверенный центр НУЦ РК)"),
    ("Could not save: {}", "Сақтау мүмкін болмады: {}", "Не удалось сохранить: {}"),
    ("Signature added", "Қолтаңба қосылды", "Подпись добавлена"),
    ("Signed", "Қол қойылды", "Подписано"),
    ("Saved to {}", "Сақталды: {}", "Сохранено: {}"),
    ("Signatures in the file: {}", "Файлдағы қолтаңбалар саны: {}", "Подписей в файле: {}"),
    (", with timestamp", ", уақыт белгісімен", ", с меткой времени"),
    ("Warning: {}", "Ескерту: {}", "Внимание: {}"),
    ("Signed .cms file", "Қол қойылған .cms файлы", "Подписанный файл .cms"),
    ("Check revocation online (OCSP, ocsp.pki.gov.kz)", "Кері қайтарып алынбағанын онлайн тексеру (OCSP, ocsp.pki.gov.kz)", "Проверить отзыв онлайн (OCSP, ocsp.pki.gov.kz)"),
    ("Verify", "Тексеру", "Проверить"),
    ("Save original document…", "Түпнұсқа құжатты сақтау…", "Сохранить исходный документ…"),
    ("Checking…", "Тексерілуде…", "Проверка…"),
    ("Saved {} bytes to\n{}", "{} байт сақталды:\n{}", "Сохранено {} байт:\n{}"),
    ("Already signed ({}): {}.", "Бұрын қол қойылған ({}): {}.", "Уже подписан ({}): {}."),
    ("Your signature will be added to this file.", "Сіздің қолтаңбаңыз осы файлға қосылады.", "Ваша подпись будет добавлена в этот файл."),
    ("✔ Valid. Signatures: {}, all check out.", "✔ Жарамды. Қолтаңбалар: {}, барлығы дұрыс.", "✔ Действительно. Подписей: {}, все верны."),
    ("✖ Not valid (see details)", "✖ Жарамсыз (толығырақ төменде)", "✖ Недействительно (подробности ниже)"),
    ("Document inside: {} bytes, SHA-256 {}", "Ішіндегі құжат: {} байт, SHA-256 {}", "Документ внутри: {} байт, SHA-256 {}"),
    ("Detached signature, checked against the original you chose.", "Бөлек қолтаңба, сіз таңдаған түпнұсқамен тексерілді.", "Открепленная подпись, проверена по выбранному исходному документу."),
    ("VALID", "ЖАРАМДЫ", "ДЕЙСТВИТЕЛЬНА"),
    ("NOT VALID", "ЖАРАМСЫЗ", "НЕДЕЙСТВИТЕЛЬНА"),
    ("IIN", "ЖСН", "ИИН"),
    ("Organization", "Ұйым", "Организация"),
    ("Email", "Эл. пошта", "Эл. почта"),
    ("Signed at", "Қол қойылған уақыт", "Время подписи"),
    ("Signature", "Қолтаңба", "Подпись"),
    ("Matches the document ✔", "Құжатқа сәйкес ✔", "Соответствует документу ✔"),
    ("Trust", "Сенім", "Доверие"),
    ("Revocation", "Кері қайтарып алу", "Отзыв"),
    ("Not checked", "Тексерілмеді", "Не проверялся"),
    ("Algorithm", "Алгоритм", "Алгоритм"),
    ("Certificate", "Куәлік", "Сертификат"),
    ("serial {}, valid {} – {}", "сериялық нөмірі {}, жарамды {} – {}", "серийный номер {}, действителен {} – {}"),
    ("Issuer", "Куәлікті берген", "Издатель"),
    ("{} · signer's own clock", "{} · қол қоюшының өз сағаты бойынша", "{} · по часам подписавшего"),
    (" (INVALID)", " (ЖАРАМСЫЗ)", " (НЕДЕЙСТВИТЕЛЬНА)"),
    (" (TSA not trusted)", " (уақыт белгісі қызметі сенімді емес)", " (служба меток времени не доверенная)"),
    ("{} · timestamp by {}{}", "{} · уақыт белгісі: {}{}", "{} · метка времени: {}{}"),
    ("Language", "Тіл", "Язык"),
    ("Show password", "Құпиясөзді көрсету", "Показать пароль"),
    ("Hide password", "Құпиясөзді жасыру", "Скрыть пароль"),
    // key and certificate
    ("The certificate expired on {}.", "Куәліктің мерзімі {} аяқталды.", "Срок действия сертификата истек {}."),
    ("The certificate is not valid until {}.", "Куәлік тек {} бастап жарамды.", "Сертификат действителен только с {}."),
    ("This certificate has no 'non-repudiation' key usage, so it looks like an authentication (AUTH_) key. Documents are normally signed with the signing key (RSA_... / GOSTKNCA_... file); some services will reject this signature.",
     "Бұл куәлікте «non-repudiation» (бас тартпау) кілт қолданысы жоқ, сондықтан бұл аутентификация (AUTH_) кілті сияқты. Құжаттарға әдетте қол қою кілтімен (RSA_... / GOSTKNCA_... файлы) қол қойылады; кейбір қызметтер бұл қолтаңбаны қабылдамайды.",
     "У этого сертификата нет назначения ключа «non-repudiation» (неотрекаемость), похоже, это ключ аутентификации (AUTH_). Документы обычно подписывают ключом подписи (файл RSA_... / GOSTKNCA_...); некоторые сервисы не примут такую подпись."),
    ("Could not open the key file. The password is probably wrong, or the file uses an unsupported format ({})", "Кілт файлын ашу мүмкін болмады. Құпиясөз қате болуы мүмкін немесе файл пішімі қолдау көрсетілмейді ({})", "Не удалось открыть файл ключа. Вероятно, пароль неверный, или формат файла не поддерживается ({})"),
    ("The key file contains no private key.", "Кілт файлында жабық кілт жоқ.", "В файле ключа нет закрытого ключа."),
    ("No key with alias '{}'. Available: [{}]", "'{}' бүркеншік атымен кілт жоқ. Барлары: [{}]", "Нет ключа с псевдонимом '{}'. Доступны: [{}]"),
    ("Unsupported private key type: {}", "Жабық кілт түріне қолдау көрсетілмейді: {}", "Неподдерживаемый тип закрытого ключа: {}"),
    ("The key file has no certificate for its key.", "Кілт файлында кілтке сай куәлік жоқ.", "В файле ключа нет сертификата для этого ключа."),
    ("Could not open the key file: it is not a PKCS#12 (.p12) key ({})", "Кілт файлын ашу мүмкін болмады: бұл PKCS#12 (.p12) кілті емес ({})", "Не удалось открыть файл ключа: это не ключ PKCS#12 (.p12) ({})"),
    ("Could not open the key file. The password is probably wrong.", "Кілт файлын ашу мүмкін болмады. Құпиясөз қате болуы мүмкін.", "Не удалось открыть файл ключа. Вероятно, пароль неверный."),
    // signing
    ("This file is not a CMS/PKCS#7 signed file ({}).", "Бұл файл қол қойылған CMS/PKCS#7 файлы емес ({}).", "Этот файл не является подписанным файлом CMS/PKCS#7 ({})."),
    ("This .cms has no embedded document: it is a detached signature, the original was never inside it.", "Бұл .cms ішінде құжат жоқ: бұл бөлек қолтаңба, түпнұсқа оның ішінде ешқашан болмаған.", "В этом .cms нет вложенного документа: это открепленная подпись, исходного документа в нем никогда не было."),
    ("This .cms has no embedded document (detached signature). Provide the original file to add a signature.", "Бұл .cms ішінде құжат жоқ (бөлек қолтаңба). Қолтаңба қосу үшін түпнұсқа файлды көрсетіңіз.", "В этом .cms нет вложенного документа (открепленная подпись). Укажите исходный файл, чтобы добавить подпись."),
    ("Signing failed: {}", "Қол қою сәтсіз аяқталды: {}", "Не удалось подписать: {}"),
    ("The original file does not match this .cms: its existing signatures are for a different document.", "Түпнұсқа файл бұл .cms-ке сәйкес емес: ондағы қолтаңбалар басқа құжатқа қойылған.", "Исходный файл не соответствует этому .cms: имеющиеся подписи относятся к другому документу."),
    ("Could not check the original file against the .cms: {}", "Түпнұсқа файлды .cms-пен салыстыру мүмкін болмады: {}", "Не удалось сверить исходный файл с .cms: {}"),
    ("timestamp server", "Уақыт белгісі сервері", "Сервер меток времени"),
    ("OCSP server", "OCSP сервері", "Сервер OCSP"),
    ("The {} answered HTTP {} ({})", "{} HTTP {} жауабын қайтарды ({})", "{} ответил HTTP {} ({})"),
    ("Could not reach the {} at {}: {}", "Байланыс орнату мүмкін болмады: {} ({}): {}", "Не удалось связаться: {} ({}): {}"),
    ("The timestamp server's answer does not match the request: {}", "Уақыт белгісі серверінің жауабы сұрауға сәйкес емес: {}", "Ответ сервера меток времени не соответствует запросу: {}"),
    ("The timestamp server's answer is unreadable ({})", "Уақыт белгісі серверінің жауабын оқу мүмкін емес ({})", "Ответ сервера меток времени не удается прочитать ({})"),
    ("The timestamp server refused the request{}", "Уақыт белгісі сервері сұрауды қабылдамады{}", "Сервер меток времени отклонил запрос{}"),
    // verification
    ("This is a detached signature (the document is not inside the .cms). Provide the original file to check the signatures against it.", "Бұл бөлек қолтаңба (құжат .cms ішінде жоқ). Қолтаңбаларды тексеру үшін түпнұсқа файлды көрсетіңіз.", "Это открепленная подпись (документа нет внутри .cms). Укажите исходный файл, чтобы проверить по нему подписи."),
    ("The file contains no signatures.", "Файлда қолтаңба жоқ.", "В файле нет подписей."),
    ("The signer's certificate is not included in the .cms, so this signature cannot be checked.", "Қол қоюшының куәлігі .cms ішінде жоқ, сондықтан бұл қолтаңбаны тексеру мүмкін емес.", "Сертификата подписавшего нет в .cms, поэтому эту подпись проверить нельзя."),
    ("Not checked: original document not provided (detached signature).", "Тексерілмеді: түпнұсқа құжат көрсетілмеген (бөлек қолтаңба).", "Не проверено: исходный документ не указан (открепленная подпись)."),
    ("The certificate was not valid at the signing time ({}).", "Қол қойылған кезде куәлік жарамсыз болған ({}).", "Сертификат не был действителен в момент подписи ({})."),
    ("Signing time comes from the signer's own computer clock (no trusted timestamp).", "Қол қою уақыты қол қоюшының компьютер сағатынан алынған (сенімді уақыт белгісі жоқ).", "Время подписи взято с часов компьютера подписавшего (нет доверенной метки времени)."),
    ("The signed reference to the signer's certificate does not match the certificate in the file.", "Қол қоюшы куәлігіне қол қойылған сілтеме файлдағы куәлікке сәйкес емес.", "Подписанная ссылка на сертификат подписавшего не совпадает с сертификатом в файле."),
    ("Signature check failed: {}", "Қолтаңбаны тексеру қатесі: {}", "Ошибка проверки подписи: {}"),
    ("Signature does not match the document (the document or signature was changed).", "Қолтаңба құжатқа сәйкес емес (құжат немесе қолтаңба өзгертілген).", "Подпись не соответствует документу (документ или подпись изменены)."),
    ("Signature check failed: the document's content hash does not match the signed hash (the document was changed).", "Қолтаңбаны тексеру қатесі: құжаттың хеші қол қойылған хешке сәйкес емес (құжат өзгертілген).", "Ошибка проверки подписи: хеш документа не совпадает с подписанным хешем (документ изменен)."),
    ("unreadable timestamp: {}", "уақыт белгісін оқу мүмкін емес: {}", "метку времени не удается прочитать: {}"),
    ("invalid timestamp signature", "уақыт белгісінің қолтаңбасы жарамсыз", "подпись метки времени недействительна"),
    ("unknown TSA", "белгісіз уақыт белгісі қызметі", "неизвестная служба меток времени"),
    ("The timestamp authority '{}' is not a trusted NCA RK TSA.", "'{}' уақыт белгісі қызметі ҚР ҰКО-ның сенімді қызметі емес.", "Служба меток времени '{}' не является доверенной службой НУЦ РК."),
    ("The timestamp authority's certificate is not issued for timestamping.", "Уақыт белгісі қызметінің куәлігі уақыт белгісіне арналмаған.", "Сертификат службы меток времени выпущен не для меток времени."),
    // trust
    ("Certificate path not valid: {}", "Куәліктер тізбегі жарамсыз: {}", "Цепочка сертификатов недействительна: {}"),
    ("certificate '{}' was not valid on {}", "'{}' куәлігі {} кезінде жарамсыз болған", "сертификат '{}' не был действителен на {}"),
    ("root certificate signature is invalid", "түбірлік куәліктің қолтаңбасы жарамсыз", "подпись корневого сертификата недействительна"),
    ("Issued by a trusted CA: {}", "Сенімді куәландырушы орталық берген: {}", "Выдан доверенным удостоверяющим центром: {}"),
    ("self-signed certificate '{}' is not a trusted root", "өзі қол қойған '{}' куәлігі сенімді түбірлік куәлік емес", "самоподписанный сертификат '{}' не является доверенным корневым"),
    ("Issuer not found among trusted NCA RK certificates: {}", "Куәлікті берген ҚР ҰКО сенімді куәліктерінің арасында жоқ: {}", "Издатель не найден среди доверенных сертификатов НУЦ РК: {}"),
    ("certificate path too long", "куәліктер тізбегі тым ұзын", "слишком длинная цепочка сертификатов"),
    ("issuer '{}' is not a CA", "'{}' куәландырушы орталық емес", "издатель '{}' не является удостоверяющим центром"),
    ("issuer '{}' may not sign certificates", "'{}' куәліктерге қол қоя алмайды", "издатель '{}' не вправе подписывать сертификаты"),
    // revocation
    ("UNKNOWN (issuer certificate not available)", "БЕЛГІСІЗ (куәлікті берген орталықтың куәлігі жоқ)", "НЕИЗВЕСТНО (нет сертификата издателя)"),
    ("ERROR: could not check OCSP ({})", "ҚАТЕ: OCSP арқылы тексеру мүмкін болмады ({})", "ОШИБКА: не удалось проверить через OCSP ({})"),
    ("ERROR: OCSP server answered status {}", "ҚАТЕ: OCSP сервері {} күйін қайтарды", "ОШИБКА: сервер OCSP вернул статус {}"),
    ("ERROR: {}", "ҚАТЕ: {}", "ОШИБКА: {}"),
    ("ERROR: OCSP response is not for this request (nonce mismatch)", "ҚАТЕ: OCSP жауабы бұл сұрауға емес (nonce сәйкес емес)", "ОШИБКА: ответ OCSP не на этот запрос (nonce не совпадает)"),
    ("ERROR: OCSP answer is out of date", "ҚАТЕ: OCSP жауабы ескірген", "ОШИБКА: ответ OCSP устарел"),
    ("GOOD (not revoked, checked {})", "ЖАРАМДЫ (кері қайтарып алынбаған, тексерілді {})", "ДЕЙСТВИТЕЛЕН (не отозван, проверено {})"),
    ("REVOKED on {}", "КЕРІ ҚАЙТАРЫП АЛЫНҒАН: {}", "ОТОЗВАН: {}"),
    ("UNKNOWN (the OCSP server does not know this certificate)", "БЕЛГІСІЗ (OCSP сервері бұл куәлікті білмейді)", "НЕИЗВЕСТНО (сервер OCSP не знает этот сертификат)"),
    ("UNKNOWN (no answer for this certificate)", "БЕЛГІСІЗ (бұл куәлік үшін жауап жоқ)", "НЕИЗВЕСТНО (нет ответа для этого сертификата)"),
    ("OCSP responder was not issued by the certificate's CA", "OCSP жауап берушісін куәліктің орталығы бермеген", "Ответчик OCSP выпущен не центром, выдавшим сертификат"),
    ("OCSP responder certificate is not issued for OCSP signing", "OCSP жауап берушісінің куәлігі OCSP-ге қол қоюға арналмаған", "Сертификат ответчика OCSP выпущен не для подписи ответов OCSP"),
    ("OCSP responder is not trusted ({})", "OCSP жауап берушісі сенімді емес ({})", "Ответчик OCSP не доверенный ({})"),
    ("OCSP response signature is invalid", "OCSP жауабының қолтаңбасы жарамсыз", "Подпись ответа OCSP недействительна"),
    ("The document was not compared with the signature: give the signed PDF or the original document to check it.", "Құжат қолтаңбамен салыстырылмады: тексеру үшін қол қойылған PDF файлын немесе түпнұсқа құжатты беріңіз.", "Документ не сверен с подписью: для проверки укажите подписанный PDF или исходный документ."),
    ("Only the signature was checked, not the document: it signs a document whose {} hash is {}.", "Тек қолтаңба тексерілді, құжат емес: ол {} хэші {} болатын құжатқа қойылған.", "Проверена только подпись, а не документ: она поставлена под документом, {}-хэш которого {}."),
    ("Signature file (.cms)", "Қолтаңба файлы (.cms)", "Файл подписи (.cms)"),
    ("Inside the PDF (opens in any PDF viewer; PDF documents only)", "PDF ішінде (кез келген PDF бағдарламасында ашылады; тек PDF құжаттары үшін)", "Внутри PDF (открывается в любой программе для PDF; только для PDF-документов)"),
    ("Document card (a PDF with the document, its signatures and their details)", "Электрондық құжат карточкасы (құжат, оның қолтаңбалары және олар туралы мәліметтер бар PDF)", "Карточка электронного документа (PDF с документом, его подписями и сведениями о них)"),
    ("Print the signatures as QR codes too", "Қолтаңбаларды QR кодтар түрінде де басу", "Также напечатать подписи в виде QR-кодов"),
    ("Card language:", "Карточка тілі:", "Язык карточки:"),
    ("Add NCA timestamp and revocation answer (a card always has them; needs internet)", "ҰКО уақыт белгісі мен кері қайтарып алу туралы жауапты қосу (карточкада олар әрқашан болады; интернет қажет)", "Добавить метку времени и ответ о статусе сертификата НУЦ (в карточке они есть всегда; нужен интернет)"),
    ("Signed file (.cms, signed PDF or document card)", "Қол қойылған файл (.cms, қол қойылған PDF немесе құжат карточкасы)", "Подписанный файл (.cms, подписанный PDF или карточка документа)"),
    ("Your signature will be added to this document card.", "Сіздің қолтаңбаңыз осы құжат карточкасына қосылады.", "Ваша подпись будет добавлена в эту карточку документа."),
    ("Your signature can be added inside this PDF.", "Сіздің қолтаңбаңызды осы PDF ішіне қосуға болады.", "Вашу подпись можно добавить внутрь этого PDF."),
    ("Type", "Түрі", "Тип"),
    ("Covers", "Қамтиды", "Охватывает"),
    ("Document card. Document inside: {}, {} bytes, SHA-256 {}", "Құжат карточкасы. Ішіндегі құжат: {}, {} байт, SHA-256 {}", "Карточка документа. Документ внутри: {}, {} байт, SHA-256 {}"),
    ("Signed PDF: {} bytes, SHA-256 {}", "Қол қойылған PDF: {} байт, SHA-256 {}", "Подписанный PDF: {} байт, SHA-256 {}"),
    ("No OCSP answer could be embedded in the signature (the certificate's issuer is not a trusted NCA RK certificate); the card does not fully meet its specification.", "Қолтаңбаға OCSP жауабын енгізу мүмкін болмады (сертификатты берген ҰКО-ның сенімді сертификаты емес); карточка өз спецификациясына толық сәйкес келмейді.", "Не удалось вложить в подпись ответ OCSP (издатель сертификата не является доверенным сертификатом НУЦ РК); карточка не полностью соответствует спецификации."),
    ("A card signature must hold exactly one signer.", "Карточкадағы қолтаңбада бір ғана қол қоюшы болуы керек.", "Подпись в карточке должна содержать ровно одного подписанта."),
    ("The signature contains the document; a card's signatures should be detached.", "Қолтаңбаның ішінде құжат бар; карточканың қолтаңбалары бөлек (detached) болуы керек.", "Подпись содержит документ; подписи в карточке должны быть открепленными."),
    ("The kept OCSP answer is older than the signature's timestamp.", "Сақталған OCSP жауабы қолтаңбаның уақыт белгісінен ескі.", "Сохраненный ответ OCSP старше метки времени подписи."),
    ("The signature carries no OCSP answer, which the card specification asks for.", "Қолтаңбада карточка спецификациясы талап ететін OCSP жауабы жоқ.", "В подписи нет ответа OCSP, которого требует спецификация карточки."),
    ("The signature has no timestamp, which the card specification requires.", "Қолтаңбада карточка спецификациясы талап ететін уақыт белгісі жоқ.", "В подписи нет метки времени, которую требует спецификация карточки."),
    ("The certificate is not usable for signing: {}", "Сертификатты қол қою үшін пайдалану мүмкін емес: {}", "Сертификат нельзя использовать для подписи: {}"),
    ("No OCSP answer could be embedded in the signature ({}); the card does not fully meet its specification.", "Қолтаңбаға OCSP жауабын енгізу мүмкін болмады ({}); карточка өз спецификациясына толық сәйкес келмейді.", "Не удалось вложить в подпись ответ OCSP ({}); карточка не полностью соответствует спецификации."),
    ("Signature {} is not valid, so no card was made: {}", "{} қолтаңбасы жарамсыз, сондықтан карточка жасалмады: {}", "Подпись {} недействительна, поэтому карточка не создана: {}"),
    ("Signature in the document card ({})", "Құжат карточкасындағы қолтаңба ({})", "Подпись в карточке документа ({})"),
    ("{} (answer kept in the signature)", "{} (жауап қолтаңбада сақталған)", "{} (ответ сохранен в подписи)"),
    ("This PDF is encrypted (password-protected or with restrictions); kzsigner cannot sign or check it.", "Бұл PDF шифрланған (құпиясөзбен немесе шектеулермен); kzsigner оған қол қоя да, оны тексере де алмайды.", "Этот PDF зашифрован (защищен паролем или ограничениями); kzsigner не может его подписать или проверить."),
    ("This PDF has no pages.", "Бұл PDF-те беттер жоқ.", "В этом PDF нет страниц."),
    ("This PDF has no signatures.", "Бұл PDF-те қолтаңбалар жоқ.", "В этом PDF нет подписей."),
    ("The signature field has no signature value.", "Қолтаңба өрісінде қолтаңба мәні жоқ.", "В поле подписи нет значения подписи."),
    ("The signature's byte range is damaged.", "Қолтаңбаның байт ауқымы (ByteRange) бүлінген.", "Диапазон байтов (ByteRange) подписи поврежден."),
    ("A PDF signature must hold exactly one signer.", "PDF қолтаңбасында бір ғана қол қоюшы болуы керек.", "Подпись PDF должна содержать ровно одного подписанта."),
    ("The signature leaves out more of the file than its own value.", "Қолтаңба файлдың өз мәнінен басқа бөліктерін де қамтымайды.", "Подпись не охватывает часть файла помимо собственного значения."),
    ("Covers the whole file.", "Бүкіл файлды қамтиды.", "Охватывает весь файл."),
    ("This PDF could not be read: {}", "Бұл PDF оқылмады: {}", "Не удалось прочитать этот PDF: {}"),
    ("PDF signature \"{}\"", "PDF қолтаңбасы «{}»", "Подпись PDF «{}»"),
    ("Unsupported PDF signature type: {}", "PDF қолтаңбасының қолдау көрсетілмейтін түрі: {}", "Неподдерживаемый тип подписи PDF: {}"),
    ("Covers the file as it was when signed; it was updated {} time(s) after that, only to add signatures.", "Файлды қол қойылған кездегі күйінде қамтиды; содан кейін ол {} рет тек қолтаңба қосу үшін жаңартылды.", "Охватывает файл в том виде, в каком он был при подписании; после этого он обновлялся {} раз(а), только для добавления подписей."),
    ("The PDF was changed after this signature, not only by adding signatures, so what it shows now is not what was signed: {}", "PDF осы қолтаңбадан кейін тек қолтаңба қосумен ғана емес өзгертілді, сондықтан қазір көрсетіп тұрғаны қол қойылған нұсқа емес: {}", "PDF изменён после этой подписи не только добавлением подписей, поэтому то, что он показывает сейчас, — не то, что было подписано: {}"),
    ("the signed part of the file cannot be read as a PDF", "файлдың қол қойылған бөлігін PDF ретінде оқу мүмкін емес", "подписанную часть файла не удаётся прочитать как PDF"),
    ("the document catalog is missing", "құжат каталогы жоқ", "отсутствует каталог документа"),
    ("the document catalog was replaced", "құжат каталогы ауыстырылды", "каталог документа заменён"),
    ("the document catalog", "құжат каталогы", "каталог документа"),
    ("a page", "бет", "страница"),
    ("the page tree", "беттер ағашы", "дерево страниц"),
    ("an annotation", "аннотация", "аннотация"),
    ("an object", "объект", "объект"),
    ("Only the document attached to the card is checked against its signatures. The card's pages (the document's image and the signature pages) are not signed and may differ from it; rely on the attached document.", "Карточкаға тіркелген құжат қана оның қолтаңбаларымен тексеріледі. Карточканың беттеріне (құжаттың бейнесі мен қолтаңба беттері) қол қойылмаған және олар құжаттан өзгеше болуы мүмкін; тіркелген құжатқа сүйеніңіз.", "С подписями сверяется только документ, вложенный в карточку. Страницы карточки (изображение документа и страницы подписей) не подписаны и могут от него отличаться; опирайтесь на вложенный документ."),
    ("This PDF is certified with no changes allowed (DocMDP); adding a signature would break its certification.", "Бұл PDF ешқандай өзгеріске рұқсат етілмей куәландырылған (DocMDP); қолтаңба қосу оның куәландыруын бұзады.", "Этот PDF заверен с запретом любых изменений (DocMDP); добавление подписи нарушит заверение."),
    ("{} (object {}) changed", "{} ({} объект) өзгертілді", "изменён(а) {} (объект {})"),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every tr("...") / trf("...") text in src/ has a translation with the same placeholders.
    #[test]
    fn every_text_is_translated() {
        let mut missing = Vec::new();
        let mut found = 0;
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        for dir in ["src", "src/pdf"] {
            for e in std::fs::read_dir(dir).unwrap() {
                files.push(e.unwrap().path());
            }
        }
        for p in files {
            if p.extension().is_none_or(|x| x != "rs") || p.ends_with("i18n.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            for text in literals(&src) {
                found += 1;
                match TABLE.iter().find(|r| r.0 == text) {
                    None => missing.push(format!("{}: {text:?}", p.display())),
                    Some(r) => {
                        let n = text.matches("{}").count();
                        for t in [r.1, r.2] {
                            assert_eq!(t.matches("{}").count(), n, "placeholders: {t:?}");
                        }
                    }
                }
            }
        }
        assert!(
            missing.is_empty(),
            "not in i18n::TABLE:\n{}",
            missing.join("\n")
        );
        assert!(found > 50, "only {found} texts found");
        // no duplicates
        for (i, r) in TABLE.iter().enumerate() {
            assert!(!TABLE[..i].iter().any(|x| x.0 == r.0), "twice: {:?}", r.0);
        }
    }

    /// The string literals passed to tr( and trf( in Rust source.
    fn literals(src: &str) -> Vec<String> {
        let mut out = Vec::new();
        for start in ["tr(", "trf(", "tr_in(", "trf_in("] {
            let mut rest = src;
            while let Some(i) = rest.find(start) {
                let before = rest[..i].chars().next_back();
                rest = &rest[i + start.len()..];
                if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    continue;
                }
                let mut r = rest.trim_start();
                // tr_in(lang, "...")
                if start.ends_with("_in(") {
                    match r.split_once(',') {
                        Some((_, after)) => r = after.trim_start(),
                        None => continue,
                    }
                }
                let Some(r) = r.strip_prefix('"') else {
                    continue;
                };
                let mut s = String::new();
                let mut chars = r.chars();
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => match chars.next() {
                            Some('n') => s.push('\n'),
                            Some(o) => s.push(o),
                            None => {}
                        },
                        c => s.push(c),
                    }
                }
                out.push(s);
            }
        }
        out
    }

    #[test]
    fn fills_placeholders() {
        assert_eq!(trf("IIN {}", &[&"123"]), "IIN 123");
        assert_eq!(Lang::parse("kk_KZ.UTF-8"), Some(Lang::Kk));
        assert_eq!(Lang::parse("ru-RU"), Some(Lang::Ru));
        assert_eq!(Lang::parse("de_DE"), None);
    }
}
