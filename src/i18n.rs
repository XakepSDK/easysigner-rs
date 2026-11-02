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

/// Set by the Android app: the phone's language, and the app's private folder for the saved
/// choice (Android has no HOME or LANG for apps).
static SYSTEM_LANG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static CONFIG_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Tells i18n the system language and the folder to remember the choice in.
pub fn set_platform(language: &str, config_dir: std::path::PathBuf) {
    let _ = SYSTEM_LANG.set(language.to_string());
    let _ = CONFIG_DIR.set(config_dir);
}

#[cfg(not(windows))]
fn system() -> Option<Lang> {
    if let Some(l) = SYSTEM_LANG.get() {
        return Lang::parse(l);
    }
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
    if let Some(d) = CONFIG_DIR.get() {
        return Some(d.join("kzsigner").join("language"));
    }
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
    ("The certificate is not valid now ({}), and no trusted timestamp shows that it was valid when the document was signed.", "Куәлік қазір жарамсыз ({}), ал қол қойылған кезде жарамды болғанын көрсететін сенімді уақыт белгісі жоқ.", "Сертификат сейчас недействителен ({}), и нет доверенной метки времени, которая показала бы, что он был действителен в момент подписи."),
    ("The signer's key is not valid now, and the signature has no trusted timestamp that would show it was valid when the document was signed.", "Қол қоюшының кілті қазір жарамсыз, ал қолтаңбада қол қойылған кезде жарамды болғанын көрсететін сенімді уақыт белгісі жоқ.", "Ключ подписавшего сейчас недействителен, а в подписи нет доверенной метки времени, которая показала бы, что он был действителен в момент подписи."),
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
    ("A card signature must hold exactly one signer.", "Карточкадағы қолтаңбада бір ғана қол қоюшы болуы керек.", "Подпись в карточке должна содержать ровно одного подписанта."),
    ("The signature contains the document; a card's signatures should be detached.", "Қолтаңбаның ішінде құжат бар; карточканың қолтаңбалары бөлек (detached) болуы керек.", "Подпись содержит документ; подписи в карточке должны быть открепленными."),
    ("The kept OCSP answer is older than the signature's timestamp.", "Сақталған OCSP жауабы қолтаңбаның уақыт белгісінен ескі.", "Сохраненный ответ OCSP старше метки времени подписи."),
    ("The signature carries no OCSP answer, which the card specification asks for.", "Қолтаңбада карточка спецификациясы талап ететін OCSP жауабы жоқ.", "В подписи нет ответа OCSP, которого требует спецификация карточки."),
    ("The signature has no timestamp, which the card specification requires.", "Қолтаңбада карточка спецификациясы талап ететін уақыт белгісі жоқ.", "В подписи нет метки времени, которую требует спецификация карточки."),
    ("The certificate is not usable for signing: {}", "Сертификатты қол қою үшін пайдалану мүмкін емес: {}", "Сертификат нельзя использовать для подписи: {}"),
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
    (" · BIN {}", " · БСН {}", " · БИН {}"),
    ("1 · Document", "1 · Құжат", "1 · Документ"),
    ("2 · Your signature key", "2 · Қолтаңба кілтіңіз", "2 · Ваш ключ подписи"),
    ("3 · How to save the signed document", "3 · Қол қойылған құжатты қалай сақтау керек", "3 · Как сохранить подписанный документ"),
    ("A PDF that shows the document and who signed it, to print or send.", "Құжатты және оған кім қол қойғанын көрсететін PDF: басып шығаруға немесе жіберуге.", "PDF с документом и тем, кто его подписал: для печати или отправки."),
    ("A document opens for signing, a signed file is checked, and a key file (.p12) is remembered for signing.", "Құжат қол қоюға ашылады, қол қойылған файл тексеріледі, ал кілт файлы (.p12) қол қою үшін есте сақталады.", "Документ откроется для подписи, подписанный файл будет проверен, а файл ключа (.p12) запомнится для подписи."),
    ("A signature failed the checks; see the details below.", "Қолтаңба тексеруден өтпеді; толығырақ төменде.", "Подпись не прошла проверку; подробности ниже."),
    ("Add the official signing time from NCA (needs internet; only a fingerprint of the document is sent)", "ҰКО-дан ресми қол қою уақытын қосу (интернет керек; құжаттың тек хеші жіберіледі)", "Добавить официальное время подписи от НУЦ (нужен интернет; отправляется только хеш документа)"),
    ("Also print the signatures as QR codes", "Қолтаңбаларды QR-кодтар түрінде де басып шығару", "Также напечатать подписи в виде QR-кодов"),
    ("Back", "Артқа", "Назад"),
    ("Check a signed file", "Қол қойылған файлды тексеру", "Проверить подписанный файл"),
    ("Check online that the signers' keys were not revoked (needs internet)", "Қол қоюшылардың кілттері кері қайтарылмағанын онлайн тексеру (интернет керек)", "Проверить онлайн, что ключи подписантов не отозваны (нужен интернет)"),
    ("Choose a signed file above, or drop it onto this window.", "Жоғарыда қол қойылған файлды таңдаңыз немесе оны осы терезеге сүйреп әкеліңіз.", "Выберите подписанный файл выше или перетащите его в это окно."),
    ("Choose the document first.", "Алдымен құжатты таңдаңыз.", "Сначала выберите документ."),
    ("Choose the signed document.", "Қол қойылған құжатты таңдаңыз.", "Выберите подписанный документ."),
    ("Choose your key file and type its password.", "Кілт файлыңызды таңдап, оның құпиясөзін енгізіңіз.", "Выберите файл ключа и введите его пароль."),
    ("Document fingerprint", "Құжат хеші", "Хеш документа"),
    ("Document in the card", "Карточкадағы құжат", "Документ в карточке"),
    ("Document to sign", "Қол қойылатын құжат", "Документ для подписи"),
    ("Document", "Құжат", "Документ"),
    ("Inside the PDF", "PDF ішінде", "Внутри PDF"),
    ("Issued by NCA RK ✔", "ҚР ҰКО берген ✔", "Выдан НУЦ РК ✔"),
    ("Kazakh and Russian", "Қазақша және орысша", "Казахский и русский"),
    ("Kazakh", "Қазақша", "Казахский"),
    ("Keep the document out of the signature file (then send both files together)", "Құжатты қолтаңба файлына салмау (сонда екі файлды бірге жіберіңіз)", "Не включать документ в файл подписи (тогда отправляйте оба файла вместе)"),
    ("Key file (.p12), for example GOSTKNCA_… or RSA_…", "Кілт файлы (.p12), мысалы GOSTKNCA_… немесе RSA_…", "Файл ключа (.p12), например GOSTKNCA_… или RSA_…"),
    ("Key in the file:", "Файлдағы кілт:", "Ключ в файле:"),
    ("Key", "Кілт", "Ключ"),
    ("More options", "Қосымша баптаулар", "Дополнительно"),
    ("Not changed since signing ✔", "Қол қойылғаннан бері өзгермеген ✔", "Не изменён после подписания ✔"),
    ("Not checked (the online check is off in More options)", "Тексерілмеген (онлайн тексеру «Қосымша баптауларда» өшірілген)", "Не проверено (онлайн-проверка выключена в разделе «Дополнительно»)"),
    ("OK", "Жарайды", "ОК"),
    ("Official signing time and key check from NCA (always on a card; needs internet)", "ҰКО-дан ресми қол қою уақыты және кілтті тексеру (карточкада әрқашан бар; интернет керек)", "Официальное время подписи и проверка ключа от НУЦ (в карточке всегда; нужен интернет)"),
    ("Or drop a file onto this window", "Немесе файлды осы терезеге сүйреп әкеліңіз", "Или перетащите файл в это окно"),
    ("Password", "Құпиясөз", "Пароль"),
    ("Printable card", "Басып шығаруға арналған карточка", "Карточка для печати"),
    ("Put your electronic signature (ЭЦП) on a contract, a letter or any other file.", "Шартқа, хатқа немесе кез келген басқа файлға электрондық қолтаңбаңызды (ЭЦҚ) қойыңыз.", "Поставьте электронную подпись (ЭЦП) на договор, письмо или любой другой файл."),
    ("Revoked?", "Кері қайтарылған ба?", "Отозван?"),
    ("Russian", "Орысша", "Русский"),
    ("Save the document…", "Құжатты сақтау…", "Сохранить документ…"),
    ("Saved in {}", "Сақталған орны: {}", "Сохранено в {}"),
    ("Saves a .cms file, like NCALayer and eGov. Recommended.", "NCALayer мен eGov сияқты .cms файлын сақтайды. Ұсынылады.", "Сохраняет файл .cms, как NCALayer и eGov. Рекомендуется."),
    ("See who signed it and when, and whether it was changed. Get the document out of a .cms file.", "Кім және қашан қол қойғанын, өзгертілген-өзгертілмегенін көріңіз. Құжатты .cms файлынан шығарып алыңыз.", "Узнайте, кто и когда подписал и не изменён ли документ. Извлеките документ из файла .cms."),
    ("Send this .cms file together with the document: it holds only your signature.", "Осы .cms файлын құжатпен бірге жіберіңіз: онда тек сіздің қолтаңбаңыз бар.", "Отправьте этот файл .cms вместе с документом: в нём только ваша подпись."),
    ("Send this .cms file: it holds both the document and your signature.", "Осы .cms файлын жіберіңіз: онда құжат та, қолтаңбаңыз да бар.", "Отправьте этот файл .cms: в нём и документ, и ваша подпись."),
    ("Show in folder", "Қалтада көрсету", "Показать в папке"),
    ("Share", "Бөлісу", "Поделиться"),
    ("Unreadable revocation list (CRL)", "Кері қайтарылғандар тізімі (CRL) оқылмайды", "Не удаётся прочитать список отзыва (CRL)"),
    ("ERROR: the revocation list is not from the certificate's CA", "ҚАТЕ: кері қайтарылғандар тізімі куәліктің КО-нан емес", "ОШИБКА: список отзыва выпущен не УЦ сертификата"),
    ("ERROR: the revocation list's signature is not valid", "ҚАТЕ: кері қайтарылғандар тізімінің қолтаңбасы жарамсыз", "ОШИБКА: подпись списка отзыва недействительна"),
    ("ERROR: the revocation list is out of date", "ҚАТЕ: кері қайтарылғандар тізімі ескірген", "ОШИБКА: список отзыва устарел"),
    ("REVOKED on {} (revocation list)", "{} КЕРІ ҚАЙТАРЫЛҒАН (кері қайтарылғандар тізімі)", "ОТОЗВАН {} (список отзыва)"),
    ("GOOD (not in the revocation list of {})", "ЖАРАМДЫ ({} кері қайтарылғандар тізімінде жоқ)", "ДЕЙСТВИТЕЛЕН (нет в списке отзыва от {})"),
    ("the certificate names no revocation list", "куәлікте кері қайтарылғандар тізімі көрсетілмеген", "в сертификате не указан список отзыва"),
    ("ERROR: the revocation list has a critical extension kzsigner does not support", "ҚАТЕ: кері қайтарылғандар тізімінде kzsigner қолдамайтын критикалық кеңейтім бар", "ОШИБКА: в списке отзыва есть критическое расширение, которое kzsigner не поддерживает"),
    ("ERROR: the revocation list is not a full list", "ҚАТЕ: кері қайтарылғандар тізімі толық тізім емес", "ОШИБКА: список отзыва не является полным"),
    ("ERROR: the delta revocation list is not a delta list", "ҚАТЕ: дельта-тізім дельта-тізім емес", "ОШИБКА: дельта-список отзыва не является дельта-списком"),
    ("ERROR: the delta revocation list could not be read", "ҚАТЕ: кері қайтарылғандардың дельта-тізімін оқу мүмкін болмады", "ОШИБКА: не удалось получить дельта-список отзыва"),
    ("{} (OCSP: {})", "{} (OCSP: {})", "{} (OCSP: {})"),
    ("The certificate's key usage does not allow signing.", "Куәліктің кілтті пайдалану мақсаты қол қоюға рұқсат бермейді.", "Назначение ключа в сертификате не разрешает подпись."),
    ("The certificate belongs to a timestamp or OCSP service, not to a person or organization.", "Куәлік адамға немесе ұйымға емес, уақыт белгісі немесе OCSP қызметіне тиесілі.", "Сертификат принадлежит службе меток времени или OCSP, а не человеку или организации."),
    ("The certificate's policy ({}) is not one of its CA's policies ({}).", "Куәліктің саясаты ({}) оның КО саясаттарының ({}) бірі емес.", "Политика сертификата ({}) не входит в политики его УЦ ({})."),
    ("The certificate names no certificate policy, but its CA issues under {}.", "Куәлікте саясат көрсетілмеген, ал оның КО {} саясаты бойынша береді.", "В сертификате не указана политика, а его УЦ выпускает сертификаты по политике {}."),
    ("The certificate belongs to a certification authority, not to a person or organization.", "Куәлік адамға немесе ұйымға емес, куәландырушы орталыққа тиесілі.", "Сертификат принадлежит удостоверяющему центру, а не человеку или организации."),
    ("The CA certificate's policies can't be read.", "КО куәлігінің саясаттарын оқу мүмкін емес.", "Не удаётся прочитать политики сертификата УЦ."),
    ("The certificate's policies can't be read.", "Куәліктің саясаттарын оқу мүмкін емес.", "Не удаётся прочитать политики сертификата."),
    ("This key may not sign documents: {}", "Бұл кілт құжаттарға қол қоя алмайды: {}", "Этим ключом нельзя подписывать документы: {}"),
    ("The timestamp authority '{}' was certified by {}, not by the signer's CA ({}).", "'{}' уақыт белгісі қызметін {} куәландырған, қол қоюшының КО ({}) емес.", "Служба меток времени '{}' сертифицирована {}, а не УЦ подписавшего ({})."),
    ("Your key cannot sign: {}", "Сіздің кілтіңіз қол қоя алмайды: {}", "Ваш ключ не может подписывать: {}"),
    ("the certificate expired on {}.", "куәліктің мерзімі {} аяқталды.", "срок действия сертификата истёк {}."),
    ("the certificate is not valid until {}.", "куәлік {} дейін жарамсыз.", "сертификат недействителен до {}."),
    ("{} (kzsigner trusts NCA RK; a test CA's certificate can be added with --trust)", "{} (kzsigner ҰКО ҚР-ға сенеді; сынақ КО куәлігін --trust арқылы қосуға болады)", "{} (kzsigner доверяет НУЦ РК; сертификат тестового УЦ можно добавить через --trust)"),
    ("Could not check that your key is not revoked: {}", "Кілтіңіздің кері қайтарылмағанын тексеру мүмкін болмады: {}", "Не удалось проверить, что ваш ключ не отозван: {}"),
    ("Open the document", "Құжатты ашу", "Открыть документ"),
    ("Choose a file…", "Файлды таңдау…", "Выбрать файл…"),
    ("Choose another…", "Басқасын таңдау…", "Выбрать другой…"),
    ("Got a file in Telegram, WhatsApp or e-mail?", "Файл Telegram, WhatsApp немесе поштамен келді ме?", "Получили файл в Telegram, WhatsApp или по почте?"),
    ("Tap Share or Open with on the file, then choose kzsigner. It opens in the right place.", "Файлда «Бөлісу» немесе «Ашу арқылы» түймесін басып, kzsigner таңдаңыз. Ол керекті жерде ашылады.", "Нажмите «Поделиться» или «Открыть с помощью» на файле и выберите kzsigner. Он откроется в нужном месте."),
    ("Could not open the document: {}", "Құжатты ашу мүмкін болмады: {}", "Не удалось открыть документ: {}"),
    ("Read it before you sign: it opens in the program your computer uses for it.", "Қол қоймас бұрын оқып шығыңыз: ол компьютеріңіз осы түрге қолданатын бағдарламада ашылады.", "Прочитайте перед подписанием: он откроется в программе, которую ваш компьютер использует для таких файлов."),
    ("No app on this phone can open this kind of file.", "Бұл телефонда мұндай файлды ашатын қосымша жоқ.", "На этом телефоне нет приложения, которое может открыть такой файл."),
    ("The signer's key may not sign documents: {}", "Қол қоюшының кілті құжаттарға қол қоя алмайды: {}", "Ключ подписавшего не может подписывать документы: {}"),
    ("ERROR: could not check the revocation list ({})", "ҚАТЕ: кері қайтарылғандар тізімін тексеру мүмкін болмады ({})", "ОШИБКА: не удалось проверить список отзыва ({})"),
    ("revocation list server", "кері қайтарылғандар тізімінің сервері", "сервер списков отзыва"),
    ("Saved: {}", "Сақталды: {}", "Сохранено: {}"),
    ("Save to the phone…", "Телефонға сақтау…", "Сохранить на телефон…"),
    ("Not saved. Use Save to the phone or Share on this screen.", "Сақталмады. Осы экрандағы «Телефонға сақтау» немесе «Бөлісу» батырмасын басыңыз.", "Не сохранено. Нажмите «Сохранить на телефон» или «Поделиться» на этом экране."),
    ("Sign a document", "Құжатқа қол қою", "Подписать документ"),
    ("Sign another document", "Басқа құжатқа қол қою", "Подписать другой документ"),
    ("Signature file", "Қолтаңба файлы", "Файл подписи"),
    ("Signatures in the file now: {}", "Файлдағы қолтаңбалар саны енді: {}", "Подписей в файле теперь: {}"),
    ("Signed on", "Қол қойылған уақыты", "Подписано"),
    ("Signing…", "Қол қойылуда…", "Подписание…"),
    ("Something went wrong", "Бір нәрсе дұрыс болмады", "Что-то пошло не так"),
    ("Still opens as a normal PDF. Only for PDF files.", "Кәдімгі PDF ретінде ашыла береді. Тек PDF файлдары үшін.", "Открывается как обычный PDF. Только для PDF-файлов."),
    ("Technical details", "Техникалық мәліметтер", "Технические подробности"),
    ("The document has not been changed since it was signed, and the keys were issued by NCA RK.", "Құжат қол қойылғаннан бері өзгертілмеген, ал кілттерді ҚР ҰКО берген.", "Документ не изменён после подписания, а ключи выданы НУЦ РК."),
    ("The document inside the card has not been changed since it was signed, and the keys were issued by NCA RK.", "Карточкадағы құжат қол қойылғаннан бері өзгертілмеген, ал кілттерді ҚР ҰКО берген.", "Документ в карточке не изменён после подписания, а ключи выданы НУЦ РК."),
    ("The document was changed after it was signed.", "Құжат қол қойылғаннан кейін өзгертілген.", "Документ изменён после подписания."),
    ("The signer's key check failed: {}", "Қол қоюшының кілтін тексеру сәтсіз аяқталды: {}", "Проверка ключа подписанта не пройдена: {}"),
    ("The signer's key was not issued by NCA RK: {}", "Қол қоюшының кілтін ҚР ҰКО бермеген: {}", "Ключ подписанта выдан не НУЦ РК: {}"),
    ("The signing time comes from this computer's clock.", "Қол қою уақыты осы компьютердің сағатынан алынған.", "Время подписи взято с часов этого компьютера."),
    ("The signing time is confirmed by NCA.", "Қол қою уақытын ҰКО растаған.", "Время подписи подтверждено НУЦ."),
    ("This PDF opens in any PDF viewer and carries your signature inside it.", "Бұл PDF кез келген PDF бағдарламасында ашылады және қолтаңбаңыз оның ішінде.", "Этот PDF открывается в любой программе для PDF, ваша подпись внутри него."),
    ("This PDF shows the document and its signatures; the original file and the signatures are attached inside it.", "Бұл PDF құжатты және оның қолтаңбаларын көрсетеді; түпнұсқа файл мен қолтаңбалар оның ішіне тіркелген.", "Этот PDF показывает документ и его подписи; исходный файл и подписи вложены в него."),
    ("This file could not be checked", "Бұл файлды тексеру мүмкін болмады", "Этот файл не удалось проверить"),
    ("This file has no signatures.", "Бұл файлда қолтаңбалар жоқ.", "В этом файле нет подписей."),
    ("This signature file does not contain the document. Choose the signed document:", "Бұл қолтаңба файлында құжат жоқ. Қол қойылған құжатты таңдаңыз:", "В этом файле подписи нет документа. Выберите подписанный документ:"),
    ("Time", "Уақыт", "Время"),
    ("What do you want to do?", "Не істегіңіз келеді?", "Что вы хотите сделать?"),
    ("{} bytes, SHA-256 {}", "{} байт, SHA-256 {}", "{} байт, SHA-256 {}"),
    ("{} is signed by {}.", "{} құжатына {} қол қойды.", "Документ {} подписан: {}."),
    ("{} · time confirmed by NCA", "{} · уақытты ҰКО растаған", "{} · время подтверждено НУЦ"),
    ("{} · time from the signer's computer", "{} · уақыт қол қоюшының компьютерінен", "{} · время с компьютера подписанта"),
    ("{} · time stamp not confirmed (see details)", "{} · уақыт белгісі расталмаған (толығырақ қараңыз)", "{} · метка времени не подтверждена (см. подробности)"),
    ("All {} signatures are valid", "Барлық {} қолтаңба жарамды", "Все подписи ({}) действительны"),
    ("The signature is valid", "Қолтаңба жарамды", "Подпись действительна"),
    ("Do not trust this document", "Бұл құжатқа сенбеңіз", "Не доверяйте этому документу"),
    ("Valid, but not checked for revocation", "Жарамды, бірақ кері қайтарылуы тексерілмеген", "Действительна, но отзыв не проверен"),
    ("The document has not been changed and the keys were issued by NCA RK, but NCA's revocation service could not be reached, so it is not known whether a key was revoked. Check the internet connection and open the file again.", "Құжат өзгертілмеген және кілттерді ҚР ҰКО берген, бірақ ҰКО-ның кері қайтару қызметіне қосылу мүмкін болмады, сондықтан кілттің кері қайтарылғаны белгісіз. Интернет байланысын тексеріп, файлды қайта ашыңыз.", "Документ не изменён, и ключи выданы НУЦ РК, но служба отзыва НУЦ недоступна, поэтому неизвестно, не отозван ли ключ. Проверьте подключение к интернету и откройте файл снова."),
    ("A printable card needs the internet: it gets the official time and the key check from NCA. Check the connection and try again, or save a signature file instead.", "Басып шығаруға арналған карточкаға интернет керек: ол ҰКО-дан ресми уақыт пен кілтті тексеруді алады. Байланысты тексеріп, қайталап көріңіз немесе оның орнына қолтаңба файлын сақтаңыз.", "Карточке для печати нужен интернет: она получает от НУЦ официальное время и проверку ключа. Проверьте подключение и повторите или сохраните вместо этого файл подписи."),
    ("Getting the official time from NCA needs the internet. Check the connection and try again, or turn off the NCA time under More options.", "ҰКО-дан ресми уақытты алу үшін интернет керек. Байланысты тексеріп, қайталап көріңіз немесе «Қосымша баптауларда» ҰКО уақытын өшіріңіз.", "Для получения официального времени от НУЦ нужен интернет. Проверьте подключение и повторите или выключите время НУЦ в разделе «Дополнительно»."),
    ("The signer's key was not valid when the document was signed (expired, or not yet valid).", "Құжатқа қол қойылған кезде қол қоюшының кілті жарамсыз болған (мерзімі өткен немесе әлі басталмаған).", "Ключ подписанта был недействителен в момент подписания (истёк или ещё не начал действовать)."),
    ("the archive timestamp must carry exactly one hash index", "архивтік уақыт белгісінде бір ғана хэш индексі болуы керек", "архивная метка времени должна содержать ровно один хэш-индекс"),
    ("the archive timestamp's hash index is malformed", "архивтік уақыт белгісінің хэш индексі бүлінген", "хэш-индекс архивной метки времени повреждён"),
    ("a certificate the archive timestamp covers is no longer in the signature", "архивтік уақыт белгісі қамтитын сертификат енді қолтаңбада жоқ", "сертификата, который охватывает архивная метка времени, больше нет в подписи"),
    ("a revocation answer the archive timestamp covers is no longer in the signature", "архивтік уақыт белгісі қамтитын кері қайтарып алу туралы жауап енді қолтаңбада жоқ", "ответа об отзыве, который охватывает архивная метка времени, больше нет в подписи"),
    ("an unsigned attribute the archive timestamp covers is no longer in the signature", "архивтік уақыт белгісі қамтитын қол қойылмаған атрибут енді қолтаңбада жоқ", "неподписанного атрибута, который охватывает архивная метка времени, больше нет в подписи"),
    ("not checked: the signed document is needed to check the archive timestamp", "тексерілмеді: архивтік уақыт белгісін тексеру үшін қол қойылған құжат керек", "не проверена: для проверки архивной метки времени нужен подписанный документ"),
    ("the archive timestamp does not match the signature (it or the signature was changed)", "архивтік уақыт белгісі қолтаңбаға сәйкес емес (ол немесе қолтаңба өзгертілген)", "архивная метка времени не соответствует подписи (она или подпись изменены)"),
    ("No validation data could be kept for '{}': {}", "'{}' үшін тексеру деректерін сақтау мүмкін болмады: {}", "Не удалось сохранить данные для проверки для '{}': {}"),
    ("No revocation data could be kept for '{}': {}", "'{}' үшін кері қайтарып алу туралы деректерді сақтау мүмкін болмады: {}", "Не удалось сохранить данные об отзыве для '{}': {}"),
    ("Archive timestamp of {}: {}", "{} архивтік уақыт белгісі: {}", "Архивная метка времени от {}: {}"),
    ("An archive timestamp is not valid: {}", "Архивтік уақыт белгісі жарамсыз: {}", "Архивная метка времени недействительна: {}"),
    ("The archive timestamp authority '{}' is not a trusted NCA RK TSA.", "'{}' архивтік уақыт белгісі қызметі ҚР ҰКО-ның сенімді қызметі емес.", "Служба архивной метки времени '{}' не является доверенной службой НУЦ РК."),
    ("A document card's signatures already keep their revocation answers; a card cannot be extended.", "Құжат карточкасының қолтаңбалары кері қайтарып алу туралы жауаптарды өздері сақтайды; карточканы ұзартуға болмайды.", "Подписи карточки документа уже хранят ответы об отзыве; карточку нельзя расширить."),
    ("This .cms has no embedded document (detached signature). Provide the original file to add an archive timestamp.", "Бұл .cms ішінде құжат жоқ (бөлек қолтаңба). Архивтік уақыт белгісін қосу үшін түпнұсқа файлды көрсетіңіз.", "В этом .cms нет вложенного документа (открепленная подпись). Укажите исходный файл, чтобы добавить архивную метку времени."),
    ("The signature of {} has no timestamp: a long-term signature needs one, so it stays checkable only while the certificate is valid.", "{} қолтаңбасында уақыт белгісі жоқ: ұзақ мерзімді қолтаңбаға ол керек, сондықтан оны тек сертификат жарамды кезде тексеруге болады.", "В подписи {} нет метки времени: она нужна долгосрочной подписи, поэтому подпись можно проверить, только пока сертификат действителен."),
    ("The signature of {} was not extended: {}", "{} қолтаңбасы ұзартылмады: {}", "Подпись {} не расширена: {}"),
    ("No signature could be made long-term: {}", "Бірде-бір қолтаңбаны ұзақ мерзімді ету мүмкін болмады: {}", "Ни одну подпись не удалось сделать долгосрочной: {}"),
    ("Keep it checkable for years: store NCA's revocation answers in the signature and add an archive timestamp (long-term signature)", "Жылдар бойы тексеруге болатындай ету: ҰКО-ның кері қайтарып алу туралы жауаптарын қолтаңбада сақтау және архивтік уақыт белгісін қосу (ұзақ мерзімді қолтаңба)", "Сохранить возможность проверки на годы: хранить в подписи ответы НУЦ об отзыве и добавить архивную метку времени (долгосрочная подпись)"),
    ("Long-term", "Ұзақ мерзімділік", "Долгосрочность"),
    ("Archive timestamp", "Архивтік уақыт белгісі", "Архивная метка времени"),
    ("B-B: no timestamp, checkable only while the key is valid", "B-B: уақыт белгісі жоқ, тек кілт жарамды кезде тексеріледі", "B-B: без метки времени, проверяется, только пока ключ действителен"),
    ("B-T: with a timestamp", "B-T: уақыт белгісімен", "B-T: с меткой времени"),
    ("B-LT: NCA's revocation answers are kept in it", "B-LT: ҰКО-ның кері қайтарып алу туралы жауаптары ішінде сақталған", "B-LT: ответы НУЦ об отзыве хранятся в подписи"),
    ("B-LTA: revocation answers kept, and an archive timestamp", "B-LTA: кері қайтарып алу туралы жауаптар сақталған және архивтік уақыт белгісі бар", "B-LTA: ответы об отзыве хранятся, есть архивная метка времени"),
    ("No OCSP answer could be embedded in the signature; the card does not fully meet its specification.", "Қолтаңбаға OCSP жауабын енгізу мүмкін болмады; карточка өз спецификациясына толық сәйкес келмейді.", "Не удалось вложить в подпись ответ OCSP; карточка не полностью соответствует спецификации."),
    ("the timestamp does not match the document (it or the document was changed)", "уақыт белгісі құжатқа сәйкес емес (ол немесе құжат өзгертілген)", "метка времени не соответствует документу (она или документ изменены)"),
    ("A document timestamp is not valid: {}", "Құжаттың уақыт белгісі жарамсыз: {}", "Метка времени документа недействительна: {}"),
    ("The document timestamp authority '{}' is not a trusted NCA RK TSA.", "'{}' құжат уақыт белгісі қызметі ҚР ҰКО-ның сенімді қызметі емес.", "Служба метки времени документа '{}' не является доверенной службой НУЦ РК."),
    ("Covers the file as it was when signed; it was updated {} time(s) after that, only to add signatures, timestamps or validation data.", "Файлды қол қойылған кездегі күйінде қамтиды; содан кейін ол {} рет тек қолтаңбалар, уақыт белгілері немесе тексеру деректері қосу үшін жаңартылды.", "Охватывает файл в том виде, в каком он был при подписании; после этого он обновлялся {} раз(а), только для добавления подписей, меток времени или данных для проверки."),
    ("the PDF was changed after it, not only by adding signatures: {}", "PDF одан кейін тек қолтаңба қосумен ғана емес өзгертілген: {}", "PDF изменён после неё не только добавлением подписей: {}"),
    ("GOOD at the signing time (revoked later, on {})", "Қол қойылған кезде ЖАРАМДЫ (кейін, {} кері қайтарып алынған)", "ДЕЙСТВИТЕЛЕН на момент подписания (отозван позже, {})"),
    ("The certificate '{}' is not usable: {}", "'{}' сертификатын пайдалануға болмайды: {}", "Сертификат '{}' нельзя использовать: {}"),
    ("The signature was made, but not as a long-term one: {}", "Қолтаңба қойылды, бірақ ұзақ мерзімді емес: {}", "Подпись создана, но не долгосрочная: {}"),
    ("This PDF has no page {}.", "Бұл PDF-те {} бет жоқ.", "В этом PDF нет страницы {}."),
    ("The logo must be a JPEG or PNG image.", "Логотип JPEG немесе PNG суреті болуы керек.", "Логотип должен быть изображением JPEG или PNG."),
    ("The logo image could not be read.", "Логотип суретін оқу мүмкін болмады.", "Не удалось прочитать изображение логотипа."),
    ("This PNG logo is not supported (use 8 bits per channel or a palette, not interlaced), or use a JPEG.", "Бұл PNG логотипіне қолдау көрсетілмейді (арнаға 8 бит немесе палитра, interlace-сіз қолданыңыз) немесе JPEG қолданыңыз.", "Этот логотип PNG не поддерживается (нужны 8 бит на канал или палитра, без чересстрочности), или используйте JPEG."),
    ("This JPEG logo is not supported (use 8 bits per channel), or use a PNG.", "Бұл JPEG логотипіне қолдау көрсетілмейді (арнаға 8 бит қолданыңыз) немесе PNG қолданыңыз.", "Этот логотип JPEG не поддерживается (нужны 8 бит на канал), или используйте PNG."),
    ("The page is too small for the stamp.", "Бет мөр үшін тым кішкентай.", "Страница слишком мала для штампа."),
    ("There is no free room for one more stamp in that corner of the page.", "Беттің осы бұрышында тағы бір мөрге бос орын жоқ.", "В этом углу страницы нет места для ещё одного штампа."),
    ("Show a stamp with your name and the signing time on the last page", "Соңғы бетте атыңыз және қол қойылған уақыт көрсетілген мөрді көрсету", "Показать на последней странице штамп с вашим именем и временем подписания"),
    ("Inside the XML", "XML ішінде", "Внутри XML"),
    ("Keeps the XML document, with the signature inside it (XAdES). Only for XML files.", "XML құжаты сақталады, қолтаңба оның ішінде болады (XAdES). Тек XML файлдары үшін.", "XML-документ остаётся прежним, подпись внутри него (XAdES). Только для файлов XML."),
    ("This XML document carries your signature inside it (XAdES).", "Бұл XML құжатының ішінде сіздің қолтаңбаңыз бар (XAdES).", "Этот XML-документ содержит вашу подпись внутри (XAdES)."),
    ("Another signature cannot go inside this XML document without breaking the first one; yours can go into a .cms file or a card.", "Бұл XML құжатының ішіне біріншісін бұзбай басқа қолтаңба қою мүмкін емес; сіздің қолтаңбаңыз .cms файлына немесе карточкаға қойылады.", "Ещё одну подпись нельзя поместить внутрь этого XML-документа, не испортив первую; вашу подпись можно сохранить в файл .cms или в карточку."),
    ("The signer's certificate is not included in the signature, so it cannot be checked.", "Қол қоюшының сертификаты қолтаңбада жоқ, сондықтан оны тексеру мүмкін емес.", "Сертификат подписавшего не включён в подпись, поэтому её нельзя проверить."),
    ("This signature covers only part of the document, so the rest could be changed without notice.", "Бұл қолтаңба құжаттың тек бір бөлігін қамтиды, сондықтан қалғанын байқатпай өзгертуге болады.", "Эта подпись покрывает только часть документа, поэтому остальное можно изменить незаметно."),
    ("This is a plain XML signature without signed XAdES properties (signing time, signer's certificate), which Order 500/НҚ p.10 asks for.", "Бұл қол қойылған XAdES қасиеттері (қол қою уақыты, қол қоюшының сертификаты) жоқ қарапайым XML қолтаңбасы, ал 500/НҚ бұйрығының 10-тармағы оларды талап етеді.", "Это простая XML-подпись без подписанных свойств XAdES (время подписания, сертификат подписавшего), которых требует п.10 Приказа 500/НҚ."),
    ("The XML signature has no SignedInfo.", "XML қолтаңбасында SignedInfo жоқ.", "В XML-подписи нет SignedInfo."),
    ("The signature uses a canonicalization method that is not supported.", "Қолтаңба қолдау көрсетілмейтін канонизация әдісін пайдаланады.", "Подпись использует неподдерживаемый метод канонизации."),
    ("This XML document could not be read: {}", "Бұл XML құжатын оқу мүмкін болмады: {}", "Не удалось прочитать этот XML-документ: {}"),
    ("The signed part {} is missing or appears more than once.", "Қол қойылған {} бөлігі жоқ немесе бірнеше рет кездеседі.", "Подписанная часть {} отсутствует или встречается больше одного раза."),
    ("The signature refers to {}, outside the document; such signatures are not supported.", "Қолтаңба құжаттан тыс {} сілтейді; мұндай қолтаңбаларға қолдау көрсетілмейді.", "Подпись ссылается на {} вне документа; такие подписи не поддерживаются."),
    ("The signature uses a transform that is not supported: {}", "Қолтаңба қолдау көрсетілмейтін түрлендіруді пайдаланады: {}", "Подпись использует неподдерживаемое преобразование: {}"),
    ("The signature uses a digest algorithm that is not supported: {}", "Қолтаңба қолдау көрсетілмейтін хэш алгоритмін пайдаланады: {}", "Подпись использует неподдерживаемый алгоритм хэширования: {}"),
    ("The signed part {} was changed after signing.", "Қол қойылған {} бөлігі қол қойылғаннан кейін өзгертілген.", "Подписанная часть {} была изменена после подписания."),
    ("The signature uses an algorithm that is not supported: {}", "Қолтаңба қолдау көрсетілмейтін алгоритмді пайдаланады: {}", "Подпись использует неподдерживаемый алгоритм: {}"),
    ("XML documents whose DTD declares attributes are not supported.", "DTD-сы атрибуттарды жариялайтын XML құжаттарына қолдау көрсетілмейді.", "XML-документы, DTD которых объявляет атрибуты, не поддерживаются."),
    ("The signature uses SHA-1, which is no longer safe: a document with the same hash can be made.", "Қолтаңба SHA-1 пайдаланады, ол енді қауіпсіз емес: хэші бірдей құжат жасауға болады.", "Подпись использует SHA-1, который больше не безопасен: можно создать документ с тем же хэшем."),
    ("An XML signature is inside the document it signs: check the signed XML file alone.", "XML қолтаңбасы өзі қол қойған құжаттың ішінде: қол қойылған XML файлын жалғыз тексеріңіз.", "XML-подпись находится внутри подписанного документа: проверяйте подписанный XML-файл отдельно."),
    ("This XML document's encoding is not supported ({}): use UTF-8, windows-1251, KZ-1048 or ISO-8859-1.", "Бұл XML құжатының кодтауына қолдау көрсетілмейді ({}): UTF-8, windows-1251, KZ-1048 немесе ISO-8859-1 қолданыңыз.", "Кодировка этого XML-документа не поддерживается ({}): используйте UTF-8, windows-1251, KZ-1048 или ISO-8859-1."),
    ("The hash is {} bytes long, but this key signs {}-byte hashes ({}).", "Хэш ұзындығы {} байт, бірақ бұл кілт {} байттық хэштерге қол қояды ({}).", "Длина хэша {} байт, а этот ключ подписывает хэши длиной {} байт ({})."),
    ("This XML document is already signed, and its signature covers everything in it, so another signature inside it would break that one. Add yours as a .cms file or a card instead.", "Бұл XML құжатына қол қойылған және оның қолтаңбасы ішіндегінің бәрін қамтиды, сондықтан ішіне тағы бір қолтаңба қойылса, ол бұзылады. Өз қолтаңбаңызды .cms файлы немесе карточка ретінде қосыңыз.", "Этот XML-документ уже подписан, и его подпись покрывает всё его содержимое, поэтому ещё одна подпись внутри испортит её. Добавьте свою подпись в виде файла .cms или карточки."),
    ("This XML document is not valid UTF-8: name its encoding in the XML declaration (windows-1251, KZ-1048 or ISO-8859-1), or save it as UTF-8.", "Бұл XML құжаты дұрыс UTF-8 емес: оның кодтауын XML декларациясында көрсетіңіз (windows-1251, KZ-1048 немесе ISO-8859-1) немесе оны UTF-8 ретінде сақтаңыз.", "Этот XML-документ не является корректным UTF-8: укажите его кодировку в XML-декларации (windows-1251, KZ-1048 или ISO-8859-1) или сохраните его в UTF-8."),
    ("An XML document's signatures are inside it: extend the signed XML file alone, without --data.", "XML құжатының қолтаңбалары оның ішінде: қол қойылған XML файлын --data параметрінсіз жалғыз ұзартыңыз.", "Подписи XML-документа находятся внутри него: продлевайте подписанный XML-файл отдельно, без --data."),
    ("Another signature in this XML document covers this one, so adding validation data to it would break that signature.", "Осы XML құжатындағы басқа қолтаңба бұл қолтаңбаны қамтиды, сондықтан оған тексеру деректерін қосу ол қолтаңбаны бұзады.", "Другая подпись в этом XML-документе покрывает эту, поэтому добавление в неё данных для проверки испортит ту подпись."),
    ("Your signature can be added inside this XML document.", "Сіздің қолтаңбаңызды осы XML құжатының ішіне қосуға болады.", "Вашу подпись можно добавить внутрь этого XML-документа."),
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
        for dir in ["src", "src/pdf", "src/xml", "src/gui"] {
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
