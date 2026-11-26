//! The window's words in English, Kazakh and Russian.
//!
//! Written in English in the code as `t("...")`, or `tf("... {} ...", &[..])` with `{}` filled
//! in order; [`TABLE`] holds the Kazakh and Russian. A test checks that every `t`/`tf` text in
//! the window's code is in the table with the same placeholders. These are the window's own
//! words, separate from the phone app's (docs/desktop-plan.md).

use std::fmt::Display;

use kzsigner::i18n::{Lang, lang};

/// The text in the window's language.
pub fn t(en: &'static str) -> &'static str {
    t_in(lang(), en)
}

/// The text in language `l`.
pub fn t_in(l: Lang, en: &'static str) -> &'static str {
    if l == Lang::En {
        return en;
    }
    match TABLE.iter().find(|r| r.0 == en) {
        Some(r) if l == Lang::Kk => r.1,
        Some(r) => r.2,
        None => en,
    }
}

/// `t(template)` with each `{}` replaced by the next argument.
pub fn tf(template: &'static str, args: &[&dyn Display]) -> String {
    let mut out = String::new();
    let mut args = args.iter();
    let mut parts = t(template).split("{}");
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

const MONTHS: [[&str; 12]; 3] = [
    [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ],
    [
        "қаңтар",
        "ақпан",
        "наурыз",
        "сәуір",
        "мамыр",
        "маусым",
        "шілде",
        "тамыз",
        "қыркүйек",
        "қазан",
        "қараша",
        "желтоқсан",
    ],
    [
        "января",
        "февраля",
        "марта",
        "апреля",
        "мая",
        "июня",
        "июля",
        "августа",
        "сентября",
        "октября",
        "ноября",
        "декабря",
    ],
];

fn local(ms: i64) -> Option<kzsigner::jiff::Zoned> {
    kzsigner::time::local(ms)
}

/// "24 November 2026", "2026 жылғы 24 қараша", "24 ноября 2026" in this computer's time zone.
pub fn date(ms: i64) -> String {
    let Some(d) = local(ms) else {
        return String::new();
    };
    let l = lang();
    let m = MONTHS[l as usize][usize::try_from(d.month() - 1).unwrap_or(0)];
    match l {
        Lang::Kk => format!("{} жылғы {} {m}", d.year(), d.day()),
        _ => format!("{} {m} {}", d.day(), d.year()),
    }
}

/// [`date`] with the time: "24 November 2026, 16:40".
pub fn date_time(ms: i64) -> String {
    let Some(d) = local(ms) else {
        return String::new();
    };
    format!("{}, {:02}:{:02}", date(ms), d.hour(), d.minute())
}

/// Russian's plural form for `n`: 0 one, 1 few, 2 many.
fn ru_form(n: i64) -> usize {
    let (m10, m100) = (n % 10, n % 100);
    if m10 == 1 && m100 != 11 {
        0
    } else if (2..=4).contains(&m10) && !(12..=14).contains(&m100) {
        1
    } else {
        2
    }
}

/// "Expires in 3 days, on 27 November 2026".
pub fn expires_in(days: i64, date: &str) -> String {
    match lang() {
        Lang::En if days == 1 => format!("Expires in 1 day, on {date}"),
        Lang::En => format!("Expires in {days} days, on {date}"),
        Lang::Kk => format!("{days} күннен кейін, {date} аяқталады"),
        Lang::Ru => {
            let w = ["день", "дня", "дней"][ru_form(days)];
            format!("Истекает через {days} {w}, {date}")
        }
    }
}

/// "Too many wrong passwords. Try again in 30 seconds."
pub fn wait_seconds(n: u64) -> String {
    let n = n as i64;
    match lang() {
        Lang::En if n == 1 => "Too many wrong passwords. Try again in 1 second.".into(),
        Lang::En => format!("Too many wrong passwords. Try again in {n} seconds."),
        Lang::Kk => format!("Құпиясөз тым көп рет қате терілді. {n} секундтан кейін қайталаңыз."),
        Lang::Ru => {
            let w = ["секунду", "секунды", "секунд"][ru_form(n)];
            format!("Слишком много неверных паролей. Попробуйте снова через {n} {w}.")
        }
    }
}

/// (English, Kazakh, Russian).
#[rustfmt::skip]
pub const TABLE: &[(&str, &str, &str)] = &[
    ("Changed after it was signed",
     "Қол қойылғаннан кейін өзгертілген",
     "Изменён после подписи"),
    ("Ask the sender to sign it again and send the new file.",
     "Жіберушіден оған қайта қол қойып, жаңа файлды жіберуін сұраңыз.",
     "Попросите отправителя подписать его заново и прислать новый файл."),
    ("The signer's key was revoked",
     "Қол қоюшының кілті кері қайтарылған",
     "Ключ подписавшего отозван"),
    ("It was cancelled before this signature was made. Ask the sender to sign again with their new key.",
     "Ол осы қол қойылғанға дейін кері қайтарылған. Жіберушіден жаңа кілтімен қайта қол қоюын сұраңыз.",
     "Его отозвали до того, как была сделана эта подпись. Попросите отправителя подписать заново новым ключом."),
    ("The signer's key had expired",
     "Қол қоюшының кілтінің мерзімі өткен",
     "Ключ подписавшего истёк"),
    ("It was no longer valid when this was signed. Ask the sender to sign again with a current key.",
     "Қол қойылған кезде ол жарамсыз болған. Жіберушіден жарамды кілтпен қайта қол қоюын сұраңыз.",
     "Он уже не действовал в момент подписи. Попросите отправителя подписать заново действующим ключом."),
    ("The signer's key has expired since",
     "Қол қоюшының кілтінің мерзімі содан бері өтті",
     "Ключ подписавшего с тех пор истёк"),
    ("It was signed without NCA's time, so it can only be checked while the key is valid. Ask for a newly signed file.",
     "Қол ҰКО уақытынсыз қойылған, сондықтан оны кілт жарамды кезде ғана тексеруге болады. Жаңадан қол қойылған файлды сұраңыз.",
     "Подпись сделана без времени НУЦ, поэтому её можно проверить, только пока ключ действует. Попросите заново подписанный файл."),
    ("This key isn't recognized in Kazakhstan",
     "Бұл кілт Қазақстанда танылмайды",
     "Ключ не признаётся в Казахстане"),
    ("It wasn't issued by NCA or another accredited center, or by a foreign one registered here, so the signature has no legal force. Ask the sender to sign with a Kazakhstan key.",
     "Оны ҰКО не басқа аккредиттелген орталық, не мұнда тіркелген шетелдік орталық бермеген, сондықтан қолдың заңдық күші жоқ. Жіберушіден қазақстандық кілтпен қол қоюын сұраңыз.",
     "Он выпущен не НУЦ и не другим аккредитованным центром, и не зарегистрированным здесь иностранным, поэтому подпись не имеет юридической силы. Попросите отправителя подписать казахстанским ключом."),
    ("The signature is damaged",
     "Қол бүлінген",
     "Подпись повреждена"),
    ("The file may have been cut or broken in sending. Ask for it again.",
     "Файл жіберу кезінде қысқарып не бүлінуі мүмкін. Оны қайта жіберуін сұраңыз.",
     "Возможно, файл обрезался или повредился при отправке. Попросите прислать его ещё раз."),
    ("NCA didn't confirm the key",
     "ҰКО кілтті растамады",
     "НУЦ не подтвердил ключ"),
    ("Try again in a few minutes. If it keeps happening, check that the computer is online.",
     "Бірнеше минуттан кейін қайталап көріңіз. Көмектеспесе, компьютердің желіде екенін тексеріңіз.",
     "Попробуйте через несколько минут. Если не помогает, проверьте, что компьютер в сети."),
    ("valid",
     "жарамды",
     "действительна"),
    ("not confirmed",
     "расталмаған",
     "не подтверждена"),
    ("changed",
     "өзгертілген",
     "изменён"),
    ("revoked",
     "кері қайтарылған",
     "отозван"),
    ("expired",
     "мерзімі өткен",
     "истёк"),
    ("not recognized",
     "танылмаған",
     "не признан"),
    ("damaged",
     "бүлінген",
     "повреждена"),
    ("PAdES, signature inside the PDF",
     "PAdES, қол PDF ішінде",
     "PAdES, подпись внутри PDF"),
    ("XAdES, signature inside the XML document",
     "XAdES, қол XML құжаттың ішінде",
     "XAdES, подпись внутри XML-документа"),
    ("CAdES, document and signatures inside the .cms",
     "CAdES, құжат пен қолдар .cms ішінде",
     "CAdES, документ и подписи внутри .cms"),
    ("CAdES, signatures in a .cms beside the document",
     "CAdES, қолдар құжаттан бөлек .cms-те",
     "CAdES, подписи в .cms отдельно от документа"),
    ("No signature",
     "Қол жоқ",
     "Подписи нет"),
    ("Not revoked: NCA confirmed the key",
     "Кері қайтарылмаған: ҰКО кілтті растады",
     "Не отозван: НУЦ подтвердил ключ"),
    ("Revoked: NCA cancelled this key",
     "Кері қайтарылған: ҰКО бұл кілтті жойды",
     "Отозван: НУЦ аннулировал этот ключ"),
    ("NCA doesn't know this key",
     "ҰКО бұл кілтті білмейді",
     "НУЦ не знает этот ключ"),
    ("NCA didn't answer",
     "ҰКО жауап бермеді",
     "НУЦ не ответил"),
    ("NCA's answer kept in the signature",
     "ҰКО жауабы қолтаңбада сақталған",
     "Ответ НУЦ сохранён в подписи"),
    ("Document",
     "Құжат",
     "Документ"),
    ("Format",
     "Пішім",
     "Формат"),
    ("Signed by",
     "Қол қойған",
     "Подписал(а)"),
    ("IIN {}",
     "ЖСН {}",
     "ИИН {}"),
    ("On behalf of",
     "Атынан",
     "От имени"),
    ("BIN {}",
     "БСН {}",
     "БИН {}"),
    ("Document fingerprint",
     "Құжаттың саусақ ізі",
     "Отпечаток документа"),
    ("timestamp by NCA (TSA)",
     "ҰКО уақыт белгісі (TSA)",
     "метка времени НУЦ (TSA)"),
    ("from the signer's own clock, not confirmed by NCA",
     "қол қоюшының сағатынан, ҰКО растамаған",
     "с часов подписавшего, не подтверждено НУЦ"),
    ("Signing time",
     "Қол қою уақыты",
     "Время подписи"),
    ("Revocation",
     "Кері қайтару",
     "Отзыв"),
    ("serial {}",
     "сериялық нөмірі {}",
     "серийный номер {}"),
    ("valid {} to {}",
     "{} бастап {} дейін жарамды",
     "действует с {} по {}"),
    ("Certificate",
     "Сертификат",
     "Сертификат"),
    ("Issued by",
     "Кім берген",
     "Кем выдан"),
    ("Level",
     "Деңгейі",
     "Уровень"),
    ("Found",
     "Табылғаны",
     "Обнаружено"),
    ("Check a signature",
     "Қолды тексеру",
     "Проверить подпись"),
    ("Asking NCA…",
     "ҰКО-дан сұрап жатырмыз…",
     "Спрашиваем НУЦ…"),
    ("This file isn't signed",
     "Бұл файлға қол қойылмаған",
     "Этот файл не подписан"),
    ("{} has no electronic signature in it, so there is nothing to check.",
     "{} файлында электрондық қол жоқ, сондықтан тексеретін ештеңе жоқ.",
     "В файле {} нет электронной подписи, поэтому проверять нечего."),
    ("If someone sent it as signed, ask them for the signed file: a .cms, or the PDF they signed.",
     "Егер оны сізге қол қойылған деп жіберсе, қол қойылған файлды сұраңыз: .cms не қол қойылған PDF.",
     "Если вам прислали его как подписанный, попросите подписанный файл: .cms или подписанный PDF."),
    ("Choose the signed document",
     "Қол қойылған құжатты таңдаңыз",
     "Выберите подписанный документ"),
    ("This .cms holds only the signatures. To check them, choose the document they sign: {}.",
     "Бұл .cms ішінде тек қолдар бар. Оларды тексеру үшін қол қойылған құжатты таңдаңыз: {}.",
     "В этом .cms только подписи. Чтобы их проверить, выберите документ, который они подписывают: {}."),
    ("Choose the document",
     "Құжатты таңдау",
     "Выбрать документ"),
    ("Or drop it here.",
     "Немесе осында сүйреп әкеліңіз.",
     "Или перетащите его сюда."),
    ("The signature is valid",
     "Қол жарамды",
     "Подпись действительна"),
    ("Both signatures are valid",
     "Екі қол да жарамды",
     "Обе подписи действительны"),
    ("All {} signatures are valid",
     "Барлық қол ({}) жарамды",
     "Все подписи ({}) действительны"),
    ("Not changed since it was signed, and the key was valid then.",
     "Қол қойылғаннан бері өзгертілмеген, ал кілт сол кезде жарамды болған.",
     "Не изменён с момента подписи, и ключ тогда был действителен."),
    ("Not changed since it was signed, and the key is valid today.",
     "Қол қойылғаннан бері өзгертілмеген, ал кілт бүгін жарамды.",
     "Не изменён с момента подписи, и ключ действителен сегодня."),
    ("Do not trust this document",
     "Бұл құжатқа сенбеңіз",
     "Не доверяйте этому документу"),
    ("Couldn't confirm the signature",
     "Қолды растау мүмкін болмады",
     "Не удалось подтвердить подпись"),
    ("NCA didn't confirm the key was valid when it signed. Until it does, don't rely on this document.",
     "ҰКО кілттің қол қойылған кезде жарамды болғанын растамады. Растағанша бұл құжатқа сүйенбеңіз.",
     "НУЦ не подтвердил, что ключ был действителен в момент подписи. Пока не подтвердит, не полагайтесь на этот документ."),
    ("Not confirmed by NCA",
     "ҰКО растамаған",
     "Не подтверждена НУЦ"),
    ("This signature can only be checked until {}'s key expires on {}, or sooner if it is cancelled. After that, ask for a newly signed file.",
     "Бұл қолды кілт ({}) әрекет еткенше ғана, {} дейін, ал кері қайтарылса одан да ертерек тексеруге болады. Одан кейін жаңадан қол қойылған файлды сұраңыз.",
     "Эту подпись можно проверить, только пока ключ ({}) действует — до {}, или меньше, если его отзовут. После этого попросите заново подписанный файл."),
    ("Check again",
     "Қайта тексеру",
     "Проверить ещё раз"),
    ("Add my signature",
     "Қолымды қосу",
     "Добавить мою подпись"),
    ("Sign it myself",
     "Өзім қол қою",
     "Подписать самому"),
    ("Open the document",
     "Құжатты ашу",
     "Открыть документ"),
    ("Hide details",
     "Мәліметтерді жасыру",
     "Скрыть подробности"),
    ("Details",
     "Толығырақ",
     "Подробности"),
    ("Check another file",
     "Басқа файлды тексеру",
     "Проверить другой файл"),
    ("Signed on",
     "Қол қойылған күні",
     "Дата подписи"),
    ("For {} · BIN {}",
     "{} атынан · БСН {}",
     "За {} · БИН {}"),
    ("For {}",
     "{} атынан",
     "За {}"),
    ("NCA time",
     "ҰКО уақыты",
     "время НУЦ"),
    ("The file says {}, but that comes from the signer's own clock.",
     "Файлда {} деп көрсетілген, бірақ бұл қол қоюшының өз сағатының уақыты.",
     "В файле указано {}, но это время с часов самого подписавшего."),
    ("Signature details",
     "Қол туралы толығырақ",
     "Подробности подписи"),
    ("For checking by hand or by a specialist. Nothing here needs action.",
     "Қолмен не маманның тексеруіне арналған. Мұнда ештеңе істеудің қажеті жоқ.",
     "Для проверки вручную или специалистом. Здесь ничего не нужно делать."),
    ("Copy details",
     "Толығырақты көшіру",
     "Скопировать подробности"),
    ("kzsigner opens only documents and pictures, and this file is neither (or is an Office file with macros). Save it and open it yourself only if you trust whoever sent it: a valid signature does not make a file safe to run.",
     "kzsigner тек құжаттар мен суреттерді ашады, ал бұл файл олай емес (немесе макростары бар Office файлы). Оны сақтап, жіберушіге сенсеңіз ғана өзіңіз ашыңыз: жарамды қолтаңба файлды іске қосуға қауіпсіз етпейді.",
     "kzsigner открывает только документы и изображения, а этот файл не из них (или это файл Office с макросами). Сохраните его и откройте сами, только если доверяете отправителю: действительная подпись не делает файл безопасным для запуска."),
    ("Your key has expired",
     "Кілттің мерзімі өтті",
     "Срок действия ключа истёк"),
    ("It stopped working on {}.",
     "Ол {} бастап жұмыс істемейді.",
     "Он перестал действовать {}."),
    ("Your key isn't valid yet",
     "Кілт әлі жарамсыз",
     "Ключ ещё не действует"),
    ("It starts working on {}. Check that the computer's date is right.",
     "Ол {} бастап жұмыс істейді. Компьютердегі күннің дұрыс екенін тексеріңіз.",
     "Он начнёт работать {}. Проверьте, что дата на компьютере верна."),
    ("This key is too old to sign",
     "Кілт қол қою үшін тым ескі",
     "Ключ слишком старый для подписи"),
    ("It's a GOST 2004 key. NCA no longer confirms the time of its signatures, so documents signed with it aren't accepted.",
     "Бұл ГОСТ 2004 кілті. ҰКО оның қолтаңбаларының уақытын енді растамайды, сондықтан онымен қол қойылған құжаттар қабылданбайды.",
     "Это ключ ГОСТ 2004. НУЦ больше не подтверждает время его подписей, поэтому подписанные им документы не принимают."),
    ("Your key was revoked",
     "Кілтіңіз кері қайтарылған",
     "Ваш ключ отозван"),
    ("NCA says this key no longer works. A key is revoked when a new one is issued or the old one is reported lost.",
     "ҰКО бұл кілт енді жұмыс істемейтінін хабарлайды. Жаңа кілт берілгенде не ескісі жоғалды деп хабарланғанда кілт кері қайтарылады.",
     "НУЦ сообщает, что этот ключ больше не действует. Ключ отзывают, когда выпущен новый или старый заявлен утерянным."),
    ("This key isn't recognized",
     "Бұл кілт танылмады",
     "Этот ключ не распознан"),
    ("It isn't a key from NCA, Kazakhstan's certification authority, or NCA doesn't know it. Documents signed with it aren't accepted.",
     "Бұл — ҰКО-ның (Қазақстанның куәландырушы орталығының) кілті емес, не ҰКО оны білмейді. Онымен қол қойылған құжаттар қабылданбайды.",
     "Это не ключ НУЦ — удостоверяющего центра Казахстана, или НУЦ его не знает. Документы, подписанные им, не принимаются."),
    ("Get a new key",
     "Жаңа кілт алыңыз",
     "Получите новый ключ"),
    ("On egov.kz or in the eGov Mobile app, under “Get a digital signature”. It's free. Then add the new key here.",
     "egov.kz сайтында немесе eGov Mobile қолданбасында, «ЭЦҚ алу» бөлімінде. Бұл тегін. Содан кейін жаңа кілтті осында қосыңыз.",
     "На egov.kz или в приложении eGov Mobile, в разделе «Получить ЭЦП». Это бесплатно. Затем добавьте новый ключ здесь."),
    ("Open egov.kz",
     "egov.kz ашу",
     "Открыть egov.kz"),
    ("Can't read your keys.",
     "Кілттеріңізді оқу мүмкін болмады.",
     "Не удалось прочитать ваши ключи."),
    ("PDF, Word or any file. First add your key: only once.",
     "PDF, Word немесе кез келген файл. Алдымен кілтіңізді қосыңыз: тек бір рет.",
     "PDF, Word или любой файл. Сначала добавьте ключ: только один раз."),
    ("PDF, Word or any file. Confirm with your key's password.",
     "PDF, Word немесе кез келген файл. Кілт құпиясөзімен растайсыз.",
     "PDF, Word или любой файл. Подтверждаете паролем ключа."),
    ("Sign a document",
     "Құжатқа қол қою",
     "Подписать документ"),
    ("Who signed it, and was it changed?",
     "Кім қол қойды және құжат өзгертілді ме?",
     "Кто подписал и не изменён ли документ?"),
    ("Or drop a file anywhere in this window. kzsigner sees whether it's signed and opens the right screen.",
     "Немесе файлды осы терезенің кез келген жеріне сүйреп әкеліңіз. kzsigner оған қол қойылған-қойылмағанын көріп, керекті бетті ашады.",
     "Или перетащите файл в любое место этого окна. kzsigner сам поймёт, подписан ли он, и откроет нужный экран."),
    ("Add your signature key",
     "Қолтаңба кілтін қосыңыз",
     "Добавьте ключ подписи"),
    ("To sign {}, first add your key. You'll come straight back to it.",
     "{} файлына қол қою үшін алдымен кілтіңізді қосыңыз. Содан кейін бірден құжатқа ораласыз.",
     "Чтобы подписать {}, сначала добавьте ключ. Потом вы сразу вернётесь к документу."),
    ("To sign, first add your key. You do this once, then choose the document.",
     "Қол қою үшін алдымен кілтіңізді қосыңыз. Мұны бір рет жасайсыз, содан кейін құжатты таңдайсыз.",
     "Чтобы подписать, сначала добавьте свой ключ. Это делается один раз, затем выберите документ."),
    ("Only once. After this, you sign with the key's password.",
     "Тек бір рет. Осыдан кейін кілт құпиясөзімен қол қоясыз.",
     "Только один раз. После этого вы подписываете паролем ключа."),
    ("Choose another key file",
     "Басқа кілт файлын таңдау",
     "Выбрать другой файл ключа"),
    ("Choose the key file",
     "Кілт файлын таңдау",
     "Выбрать файл ключа"),
    ("or drop it here. From NCA or egov.kz, usually GOSTKNCA_….p12",
     "немесе осында сүйреп әкеліңіз. ҰКО-дан немесе egov.kz-тен, әдетте GOSTKNCA_….p12",
     "или перетащите его сюда. От НУЦ или с egov.kz, обычно GOSTKNCA_….p12"),
    ("Key password",
     "Кілт құпиясөзі",
     "Пароль ключа"),
    ("The one from NCA's center or egov.kz",
     "ҰКО-да немесе egov.kz-те берілген",
     "Тот, что дали в НУЦ или на egov.kz"),
    ("That password doesn't open this key.",
     "Бұл құпиясөз кілтті ашпайды.",
     "Этот пароль не подходит к ключу."),
    ("Is the keyboard in Russian or Kazakh?",
     "Пернетақта орысша не қазақша ма?",
     "Клавиатура на русском или казахском?"),
    ("Switch it to English and try again.",
     "Оны ағылшыншаға ауыстырып, қайталап көріңіз.",
     "Переключите её на английский и попробуйте снова."),
    ("Forgot it? NCA can't recover it. Get a new key on egov.kz.",
     "Ұмыттыңыз ба? ҰКО оны қалпына келтіре алмайды. egov.kz-тен жаңа кілт алыңыз.",
     "Забыли пароль? НУЦ не может его восстановить. Получите новый ключ на egov.kz."),
    ("This file isn't a signature key.",
     "Бұл қолтаңба кілтінің файлы емес.",
     "Это не файл ключа подписи."),
    ("Choose the .p12 file from NCA or egov.kz.",
     "ҰКО-дан немесе egov.kz-тен алған .p12 файлын таңдаңыз.",
     "Выберите файл .p12 от НУЦ или с egov.kz."),
    ("This key is already on this computer.",
     "Бұл кілт осы компьютерде бар.",
     "Этот ключ уже есть на этом компьютере."),
    ("Couldn't save the key: {}",
     "Кілтті сақтау мүмкін болмады: {}",
     "Не удалось сохранить ключ: {}"),
    ("The key stays on this computer, locked with this password. You type it each time you sign; it is never saved.",
     "Кілт осы компьютерде осы құпиясөзбен құлыпталып сақталады. Әр қол қойғанда оны енгізесіз; құпиясөздің өзі ешқайда сақталмайды.",
     "Ключ остаётся на этом компьютере, закрытый этим паролем. Вы вводите его при каждой подписи; сам пароль нигде не сохраняется."),
    ("Adding…",
     "Қосылуда…",
     "Добавление…"),
    ("Add key",
     "Кілт қосу",
     "Добавить ключ"),
    ("Don't have a key?",
     "Кілт жоқ па?",
     "Нет ключа?"),
    ("Get one free on egov.kz",
     "egov.kz-тен тегін алыңыз",
     "Получите бесплатно на egov.kz"),
    ("Your keys",
     "Сіздің кілттеріңіз",
     "Ваши ключи"),
    ("Opens with its password",
     "Өз құпиясөзімен ашылады",
     "Открывается своим паролем"),
    ("Opens with your fingerprint",
     "Саусақ ізімен ашылады",
     "Открывается отпечатком пальца"),
    ("Opens with Windows Hello",
     "Windows Hello арқылы ашылады",
     "Открывается через Windows Hello"),
    ("Opens with your fingerprint and its password",
     "Саусақ ізімен және өз құпиясөзімен ашылады",
     "Открывается отпечатком пальца и своим паролем"),
    ("Remove {}'s key from this computer?",
     "«{}» кілтін осы компьютерден жою керек пе?",
     "Удалить с этого компьютера ключ «{}»?"),
    ("To sign again, you'll need the key file and its password. The key itself stays valid: this only removes it from this computer.",
     "Қайта қол қою үшін кілт файлы мен оның құпиясөзі керек болады. Кілттің өзі жарамды болып қалады: ол тек осы компьютерден жойылады.",
     "Чтобы снова подписывать, понадобятся файл ключа и его пароль. Сам ключ остаётся действительным: он удаляется только с этого компьютера."),
    ("Remove",
     "Жою",
     "Удалить"),
    ("Keep it",
     "Қалдыру",
     "Оставить"),
    ("Remove from this computer",
     "Осы компьютерден жою",
     "Удалить с этого компьютера"),
    ("No keys on this computer yet.",
     "Бұл компьютерде әзірге кілт жоқ.",
     "На этом компьютере пока нет ключей."),
    ("Add another key",
     "Тағы бір кілт қосу",
     "Добавить ещё один ключ"),
    ("Language",
     "Тіл",
     "Язык"),
    ("Same as the computer",
     "Компьютердегідей",
     "Как на компьютере"),
    ("About kzsigner · version, license, privacy",
     "kzsigner туралы · нұсқа, лицензия, құпиялылық",
     "О kzsigner · версия, лицензия, конфиденциальность"),
    ("Couldn't remove the key: {}",
     "Кілтті жою мүмкін болмады: {}",
     "Не удалось удалить ключ: {}"),
    ("About kzsigner",
     "kzsigner туралы",
     "О kzsigner"),
    ("Your documents stay on your computer",
     "Құжаттарыңыз компьютеріңізде қалады",
     "Ваши документы остаются на компьютере"),
    ("When you sign or check, only a short fingerprint of the document goes to NCA, never the document itself. Your key never leaves the computer. No accounts, no tracking.",
     "Қол қойғанда немесе тексергенде ҰКО-ға құжаттың өзі емес, тек оның қысқа ізі жіберіледі. Кілт компьютерден ешқашан шықпайды. Аккаунтсыз, бақылаусыз.",
     "Когда вы подписываете или проверяете, в НУЦ уходит только короткий отпечаток документа, а не сам документ. Ключ никогда не покидает компьютер. Без аккаунтов и слежки."),
    ("Version",
     "Нұсқа",
     "Версия"),
    ("Talks only to",
     "Тек мынамен байланысады",
     "Связывается только с"),
    ("NCA: key check and signing time (pki.gov.kz)",
     "ҰКО: кілтті тексеру және қол қою уақыты (pki.gov.kz)",
     "НУЦ: проверка ключа и время подписи (pki.gov.kz)"),
    ("License",
     "Лицензия",
     "Лицензия"),
    ("See the source code",
     "Бастапқы код",
     "Исходный код"),
    ("Expired on {}",
     "Мерзімі {} өтті",
     "Истёк {}"),
    ("Expires today",
     "Бүгін аяқталады",
     "Истекает сегодня"),
    ("Valid until {}",
     "{} дейін жарамды",
     "Действует до {}"),
    ("Signature key",
     "Қолтаңба кілті",
     "Ключ подписи"),
    ("All files",
     "Барлық файлдар",
     "Все файлы"),
    ("Can't find the folder for your keys.",
     "Кілттерге арналған қалта табылмады.",
     "Не найдена папка для ключей."),
    ("Could not open the window: {}",
     "Терезені ашу мүмкін болмады: {}",
     "Не удалось открыть окно: {}"),
    ("Close",
     "Жабу",
     "Закрыть"),
    ("Drop the file to open it",
     "Ашу үшін файлды осында тастаңыз",
     "Отпустите файл, чтобы открыть его"),
    ("Back",
     "Артқа",
     "Назад"),
    ("This file is too big.",
     "Бұл файл тым үлкен.",
     "Этот файл слишком большой."),
    ("Can't read {}: {}",
     "{} оқылмады: {}",
     "Не удалось прочитать {}: {}"),
    ("Could not open the document: {}",
     "Құжатты ашу мүмкін болмады: {}",
     "Не удалось открыть документ: {}"),
    ("PDF document",
     "PDF құжаты",
     "Документ PDF"),
    ("XML document",
     "XML құжаты",
     "Документ XML"),
    ("Signatures only (.cms)",
     "Тек қолтаңбалар (.cms)",
     "Только подписи (.cms)"),
    ("Signed file (.cms)",
     "Қол қойылған файл (.cms)",
     "Подписанный файл (.cms)"),
    ("{} and {}",
     "{} және {}",
     "{} и {}"),
    ("Saved next to the original as {}.",
     "Түпнұсқаның қасына {} деп сақталады.",
     "Сохранится рядом с оригиналом как {}."),
    ("Your signature goes inside this PDF, and a “Who signed” page is added at the end with your name and the signing time.",
     "Қолыңыз осы PDF-тің ішіне қойылады, ал соңына атыңыз бен қол қойылған уақыт жазылған «Кім қол қойды» беті қосылады.",
     "Ваша подпись будет внутри этого PDF, а в конце добавится страница «Кто подписал» с вашим именем и временем подписи."),
    ("Your name is added next to {}'s on the “Who signed” page.",
     "Атыңыз «Кім қол қойды» бетіне, мына адамның қасына қосылады: {}.",
     "Ваше имя добавится на страницу «Кто подписал», рядом с: {}."),
    ("Your signature is added inside this PDF, next to {}'s.",
     "Қолыңыз осы PDF-тің ішіне, мына адамның қолының қасына қосылады: {}.",
     "Ваша подпись добавится внутрь этого PDF, рядом с подписью: {}."),
    ("Your signature goes inside this XML file.",
     "Қолыңыз осы XML файлдың ішіне қойылады.",
     "Ваша подпись будет внутри этого XML-файла."),
    ("You get one .cms file with the document and your signature inside.",
     "Ішінде құжат пен қолыңыз бар бір .cms файлы шығады.",
     "Вы получите один файл .cms с документом и вашей подписью внутри."),
    ("Your signature joins {}'s in the same file.",
     "Қолыңыз сол файлға, мына адамның қолына қосылады: {}.",
     "Ваша подпись добавится в тот же файл, к подписи: {}."),
    ("This XML file is signed in a way that another signature would break. Ask the sender for a copy without signatures.",
     "Бұл XML файлға тағы бір қол оны бұзатындай етіп қол қойылған. Жіберушіден қолсыз көшірмесін сұраңыз.",
     "Этот XML-файл подписан так, что ещё одна подпись его испортит. Попросите отправителя прислать копию без подписей."),
    ("This .cms holds only signatures, not the document itself. Ask the sender for the .cms with the document inside.",
     "Бұл .cms ішінде тек қолдар бар, құжаттың өзі жоқ. Жіберушіден ішінде құжаты бар .cms сұраңыз.",
     "В этом .cms только подписи, без самого документа. Попросите отправителя прислать .cms с документом внутри."),
    ("Sign this document?",
     "Бұл құжатқа қол қоясыз ба?",
     "Подписать этот документ?"),
    ("Add your signature?",
     "Қолыңызды қосасыз ба?",
     "Добавить вашу подпись?"),
    ("Inside {}",
     "{} ішінде",
     "Внутри {}"),
    ("Already signed by {}",
     "Қол қойған: {}",
     "Уже подписал(а): {}"),
    ("Read it",
     "Оқу",
     "Прочитать"),
    ("Opens in the computer's viewer, to check what you're signing.",
     "Неге қол қойып жатқаныңызды тексеру үшін компьютердегі бағдарламада ашылады.",
     "Откроется в программе на компьютере, чтобы проверить, что вы подписываете."),
    ("Can't reach NCA right now",
     "ҰКО қазір қолжетімсіз",
     "НУЦ сейчас недоступен"),
    ("Nothing was signed. NCA confirms your key and records the official signing time, and it didn't answer. Check the internet connection and try again in a few minutes.",
     "Ештеңеге қол қойылған жоқ. ҰКО кілтіңізді растап, ресми қол қою уақытын жазады, бірақ ол жауап бермеді. Интернетті тексеріп, бірнеше минуттан кейін қайталап көріңіз.",
     "Ничего не подписано. НУЦ подтверждает ключ и фиксирует официальное время подписи, но он не ответил. Проверьте интернет и попробуйте через несколько минут."),
    ("This key can't be opened on this computer anymore.",
     "Бұл кілтті осы компьютерде енді ашу мүмкін емес.",
     "Этот ключ больше нельзя открыть на этом компьютере."),
    ("Remove it in Your keys and add the key file again.",
     "Оны «Сіздің кілттеріңіз» бөлімінен жойып, кілт файлын қайта қосыңыз.",
     "Удалите его в разделе «Ваши ключи» и добавьте файл ключа заново."),
    ("Couldn't sign: {}",
     "Қол қою мүмкін болмады: {}",
     "Не удалось подписать: {}"),
    ("You sign as",
     "Сіз қол қоясыз:",
     "Вы подписываете как"),
    ("Sign with another key",
     "Басқа кілтпен қол қою",
     "Подписать другим ключом"),
    ("This file can't be signed",
     "Бұл файлға қол қою мүмкін емес",
     "Этот файл нельзя подписать"),
    ("Signing…",
     "Қол қойылуда…",
     "Подписание…"),
    ("Try again",
     "Қайталау",
     "Попробовать снова"),
    ("Sign",
     "Қол қою",
     "Подписать"),
    ("Sign {}",
     "{} файлына қол қою",
     "Подписать {}"),
    ("Confirm it's you to sign",
     "Бұл сіз екеніңізді растаңыз",
     "Подтвердите, что это вы"),
    ("Signing time confirmed by NCA, {}",
     "Қол қою уақытын ҰКО растады: {}",
     "Время подписи подтверждено НУЦ: {}"),
    ("Signed",
     "Қол қойылды",
     "Подписано"),
    ("Saved in {}, next to the original",
     "{} қалтасында, түпнұсқаның қасында сақталды",
     "Сохранено в {}, рядом с оригиналом"),
    ("Saved in {}",
     "Сақталған орны: {}",
     "Сохранено в {}"),
    ("Not saved yet.",
     "Әлі сақталмаған.",
     "Ещё не сохранён."),
    ("The signature is inside the file. The boxes on the last page only show who signed; a printed copy is just paper.",
     "Қол файлдың ішінде. Соңғы беттегі жақтаулар тек кім қол қойғанын көрсетеді; басып шығарылған көшірме — жай қағаз.",
     "Подпись находится внутри файла. Рамки на последней странице лишь показывают, кто подписал; распечатка — просто бумага."),
    ("The signature is inside the file. A printed copy is just paper.",
     "Қол файлдың ішінде. Басып шығарылған көшірме — жай қағаз.",
     "Подпись находится внутри файла. Распечатка — просто бумага."),
    ("Send the file, not a printout",
     "Басып шығарылған қағазды емес, файлды жіберіңіз",
     "Отправляйте файл, а не распечатку"),
    ("Copy saved: {}",
     "Көшірмесі сақталды: {}",
     "Копия сохранена: {}"),
    ("Show in folder",
     "Қалтада көрсету",
     "Показать в папке"),
    ("Save a copy elsewhere",
     "Көшірмесін басқа жерге сақтау",
     "Сохранить копию в другом месте"),
    ("Save",
     "Сақтау",
     "Сохранить"),
    ("Done",
     "Дайын",
     "Готово"),
    ("Couldn't save the file: {}",
     "Файлды сақтау мүмкін болмады: {}",
     "Не удалось сохранить файл: {}"),
    ("Hide password",
     "Құпиясөзді жасыру",
     "Скрыть пароль"),
    ("Show password",
     "Құпиясөзді көрсету",
     "Показать пароль"),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `t("...")` and `tf("...")` text in the window's code.
    fn texts() -> Vec<(String, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gui");
        let mut out = vec![];
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_none_or(|x| x != "rs") || p.ends_with("text.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap();
            let b = src.as_bytes();
            let file = p.file_name().unwrap().to_string_lossy().into_owned();
            for (at, _) in src.match_indices('(') {
                let mut j = at;
                while j > 0 && (b[j - 1].is_ascii_alphanumeric() || b[j - 1] == b'_') {
                    j -= 1;
                }
                if !matches!(&src[j..at], "t" | "tf") || (j > 0 && b[j - 1] == b'.') {
                    continue;
                }
                let mut start = at + 1;
                while b[start].is_ascii_whitespace() {
                    start += 1;
                }
                if b[start] != b'"' {
                    continue;
                }
                start += 1;
                let mut e = start;
                while b[e] != b'"' {
                    e += if b[e] == b'\\' { 2 } else { 1 };
                }
                out.push((file.clone(), src[start..e].replace("\\\"", "\"")));
            }
        }
        out
    }

    #[test]
    fn every_text_is_translated() {
        let texts = texts();
        assert!(texts.len() > 100, "found only {}", texts.len());
        let mut missing = vec![];
        for (file, s) in &texts {
            match TABLE.iter().find(|r| r.0 == s) {
                None => missing.push(format!("{file}: {s}")),
                Some(r) => {
                    let n = s.matches("{}").count();
                    assert!(
                        r.1.matches("{}").count() == n && r.2.matches("{}").count() == n,
                        "placeholders differ: {s}"
                    );
                    assert!(!r.1.is_empty() && !r.2.is_empty(), "empty: {s}");
                }
            }
        }
        missing.sort();
        missing.dedup();
        assert!(missing.is_empty(), "not in TABLE:\n{}", missing.join("\n"));
    }

    #[test]
    fn no_unused_texts() {
        let texts: Vec<String> = texts().into_iter().map(|t| t.1).collect();
        let unused: Vec<&str> = TABLE
            .iter()
            .map(|r| r.0)
            .filter(|e| !texts.iter().any(|t| t == e))
            .collect();
        assert!(unused.is_empty(), "unused: {unused:#?}");
    }

    #[test]
    fn dates_and_plurals() {
        assert_eq!(ru_form(1), 0);
        assert_eq!(ru_form(3), 1);
        assert_eq!(ru_form(11), 2);
        assert_eq!(ru_form(22), 1);
        assert_eq!(ru_form(25), 2);
    }
}
