//! kzsigner command line; with no arguments it opens the window.
//!
//! On Windows this is one console program, so a terminal waits for it and gets its output and
//! exit code. Its manifest (build.rs) asks for no console of its own when started from
//! Explorer (`consoleAllocationPolicy` "detached", Windows 11 24H2 and later), so double-clicking
//! shows only the window. Older Windows ignore that and open a console first; the window then
//! lets it go at once (a brief flash).

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kzsigner::cert::Cert;
use kzsigner::{Engine, Error, output};

const HELP: &str = "\
Usage: kzsigner [-hV] [COMMAND | FILE]
Sign and verify .cms files, signed PDFs and document cards with Kazakhstan NCA RK
keys, locally, without NCALayer.
Run without arguments, or with just a FILE, to open the desktop window.
Network is used only with --tsa (NCA timestamp) and --ocsp (NCA revocation check).
  -h, --help      Show this help message and exit.
  -V, --version   Print version information and exit.
Commands:
  gui      Open the desktop window (default).
  sign     Sign FILE into FILE.cms (or inside a PDF, or into a document card).
  verify   Check every signature in a .cms, signed PDF or document card.
           Exit code 0 only if all are valid.
  extract  Write out the document embedded in a .cms or document card.
  info     Show the certificate inside a key file.
Run 'kzsigner COMMAND --help' for a command's options.
";

const HELP_SIGN: &str = "\
Usage: kzsigner sign [-hV] [--detached | --pdf | --card [--qr] [--lang=LANG] [--ocsp[=URL]]]
                     -k=KEY.p12 [-p=PASSWORD] [--alias=ALIAS] [-o=OUT] [--tsa[=URL]]
                     [--data=ORIGINAL] [--trust=CA.cer]... FILE
Sign FILE into FILE.cms.
If FILE is already a .cms, your signature is ADDED to it (co-signing).
      FILE                 Document, or .cms to co-sign.
  -k, --key=KEY.p12        Your key file.
  -p, --password=PASSWORD  Key password (or env KZSIGNER_PASSWORD; prompted otherwise).
      --alias=ALIAS        Key alias, if the file holds several keys.
  -o, --out=OUT            Output file.
      --detached           Do not embed the document in the .cms.
      --pdf                Sign a PDF inside the PDF (PAdES), into FILE-signed.pdf; it
                           still opens in any PDF viewer. A signed PDF gets one more.
      --card               Make a document card (карточка электронного документа, the
                           ddcard format SIGEX uses), FILE.card.pdf: a PDF anyone can
                           open, with the document's pages, a page per signature, and the
                           document and its .cms signatures attached. Signing a card adds
                           your signature to it. Always timestamped (NCA TSA by default).
      --qr                 With --card: also print each signature as QR codes.
      --lang=LANG          With --card: ru (default), kk, or kk/ru.
                           Adding a signature to a card keeps its language and QR codes.
      --ocsp[=URL]         With --card: OCSP service for the answer kept in the signature
                           (default http://ocsp.pki.gov.kz).
      --tsa[=URL]          Add a timestamp (default http://tsp.pki.gov.kz:80).
      --data=ORIGINAL      Original document, to co-sign a detached .cms.
      --trust=CA.cer       Extra trusted CA certificate (repeatable), on top of NCA RK's.
";

const HELP_VERIFY: &str = "\
Usage: kzsigner verify [-hV] [--json] [--qr] [--data=ORIGINAL] [--ocsp[=URL]] [--trust=CA.cer]... FILE
Check every signature in a .cms, a signed PDF or a document card. Exit code 0 only if all
are valid. A card's signatures are checked against the document inside it, and without
--ocsp the OCSP answers kept in them are reported.
      FILE              .cms, signed PDF, or document card.
      --data=ORIGINAL   Original document, for a detached .cms or with --qr.
      --qr              FILE is the text of scanned QR codes from a card's signature
                        pages, one code per line, in any order; needs --data.
      --ocsp[=URL]      Check revocation online (default http://ocsp.pki.gov.kz).
      --json            Machine-readable output.
      --trust=CA.cer    Extra trusted CA certificate (repeatable), on top of NCA RK's.
";

const HELP_EXTRACT: &str = "\
Usage: kzsigner extract [-hV] [-o=OUT] FILE
Write out the document embedded in a .cms, or the original document in a document card.
      FILE            .cms or document card.
  -o, --out=OUT   Output file (default: FILE without .cms; for a card, the document's own
                  name next to the card).
";

const HELP_INFO: &str = "\
Usage: kzsigner info [-hV] -k=KEY.p12 [-p=PASSWORD] [--alias=ALIAS] [--trust=CA.cer]...
Show the certificate inside a key file.
  -k, --key=KEY.p12        Your key file.
  -p, --password=PASSWORD  Key password (or env KZSIGNER_PASSWORD; prompted otherwise).
      --alias=ALIAS        Key alias, if the file holds several keys.
      --trust=CA.cer       Extra trusted CA certificate (repeatable), on top of NCA RK's.
";

const HELP_GUI: &str = "\
Usage: kzsigner gui [-hV] [--trust=CA.cer]... [FILE]
Open the desktop window (default).
      FILE             A document to sign, a .cms to check, or a key file.
      --trust=CA.cer   Extra trusted CA certificate (repeatable), on top of NCA RK's.
";

/// A failure: a message for the user, or a usage mistake (exit code 2) with the help to show.
enum Fail {
    User(String),
    Usage(String, &'static str),
}

impl From<Error> for Fail {
    fn from(e: Error) -> Fail {
        Fail::User(e.0)
    }
}

impl From<lexopt::Error> for Fail {
    fn from(e: lexopt::Error) -> Fail {
        Fail::Usage(e.to_string(), "")
    }
}

type R<T> = std::result::Result<T, Fail>;

fn read(p: &Path) -> R<Vec<u8>> {
    std::fs::read(p).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Fail::User(format!("file not found: {}", p.display())),
        _ => Fail::User(format!("{}: {e}", p.display())),
    })
}

fn write(p: &Path, data: &[u8]) -> R<()> {
    std::fs::write(p, data).map_err(|e| Fail::User(format!("could not write {}: {e}", p.display())))
}

#[derive(Default)]
struct Opts {
    file: Option<PathBuf>,
    key: Option<PathBuf>,
    password: Option<String>,
    alias: Option<String>,
    trust: Vec<PathBuf>,
    out: Option<PathBuf>,
    data: Option<PathBuf>,
    detached: bool,
    pdf: bool,
    card: bool,
    qr: bool,
    lang: Option<String>,
    json: bool,
    tsa: Option<String>,
    ocsp: Option<String>,
}

/// Parses a command's options; prints help or version and returns None when asked to.
fn parse(mut p: lexopt::Parser, cmd: &str, help: &'static str) -> R<Option<Opts>> {
    use lexopt::prelude::*;
    let mut o = Opts::default();
    let allowed = |names: &[&str]| names.contains(&cmd);
    while let Some(arg) = p.next()? {
        match arg {
            Short('h') | Long("help") => {
                print!("{help}");
                return Ok(None);
            }
            Short('V') | Long("version") => {
                print_version();
                return Ok(None);
            }
            Short('k') | Long("key") if allowed(&["sign", "info"]) => {
                o.key = Some(p.value()?.into())
            }
            Short('p') | Long("password") if allowed(&["sign", "info"]) => {
                o.password = Some(p.value()?.string()?)
            }
            Long("alias") if allowed(&["sign", "info"]) => o.alias = Some(p.value()?.string()?),
            Long("trust") if allowed(&["sign", "info", "verify", "gui"]) => {
                o.trust.push(p.value()?.into())
            }
            Short('o') | Long("out") if allowed(&["sign", "extract"]) => {
                o.out = Some(p.value()?.into())
            }
            Long("data") if allowed(&["sign", "verify"]) => o.data = Some(p.value()?.into()),
            Long("detached") if allowed(&["sign"]) => o.detached = true,
            Long("pdf") if allowed(&["sign"]) => o.pdf = true,
            Long("card") if allowed(&["sign"]) => o.card = true,
            Long("qr") if allowed(&["sign", "verify"]) => o.qr = true,
            Long("lang") if allowed(&["sign"]) => o.lang = Some(p.value()?.string()?),
            Long("json") if allowed(&["verify"]) => o.json = true,
            Long("tsa") if allowed(&["sign"]) => {
                o.tsa = Some(optional_url(&mut p, kzsigner::DEFAULT_TSA_URL)?)
            }
            Long("ocsp") if allowed(&["verify", "sign"]) => {
                o.ocsp = Some(optional_url(&mut p, kzsigner::DEFAULT_OCSP_URL)?)
            }
            Value(v) if o.file.is_none() && allowed(&["sign", "verify", "extract", "gui"]) => {
                o.file = Some(v.into())
            }
            other => return Err(Fail::Usage(other.unexpected().to_string(), help)),
        }
    }
    Ok(Some(o))
}

/// `--opt=URL`, `--opt URL` (when the next argument is a URL), or just `--opt` for the default.
fn optional_url(p: &mut lexopt::Parser, default: &str) -> R<String> {
    use lexopt::ValueExt;
    if let Some(v) = p.optional_value() {
        return Ok(v.string()?);
    }
    let next = p.try_raw_args().and_then(|mut raw| {
        let v = raw.peek()?.to_str()?.to_string();
        (v.starts_with("http://") || v.starts_with("https://")).then(|| {
            raw.next();
            v
        })
    });
    Ok(next.unwrap_or_else(|| default.to_string()))
}

fn print_version() {
    println!("kzsigner {}", kzsigner::version());
    println!("Crypto: {}", kzsigner::crypto_version());
}

fn engine(o: &Opts) -> R<Engine> {
    let mut certs = Vec::new();
    for t in &o.trust {
        certs.push(
            Cert::parse_any(&read(t)?).map_err(|e| Fail::User(format!("{}: {e}", t.display())))?,
        );
    }
    Ok(Engine::new(certs))
}

fn password(o: &Opts) -> R<String> {
    if let Some(p) = o
        .password
        .clone()
        .or_else(|| std::env::var("KZSIGNER_PASSWORD").ok())
    {
        return Ok(p);
    }
    if !std::io::stdin().is_terminal() {
        return Err(Fail::User(
            "No password given (use -p or KZSIGNER_PASSWORD).".into(),
        ));
    }
    rpassword::prompt_password("Key password: ")
        .map_err(|e| Fail::User(format!("could not read the password: {e}")))
}

fn need<'a, T>(v: &'a Option<T>, what: &str, help: &'static str) -> R<&'a T> {
    v.as_ref()
        .ok_or_else(|| Fail::Usage(format!("Missing required {what}"), help))
}

fn open_key(e: &Engine, o: &Opts, help: &'static str) -> R<kzsigner::p12::Key> {
    let k = read(need(&o.key, "option: '--key=KEY.p12'", help)?)?;
    Ok(e.open_key(&k, &password(o)?, o.alias.as_deref())?)
}

fn sign(o: Opts) -> R<u8> {
    let file = need(&o.file, "parameter: 'FILE'", HELP_SIGN)?.clone();
    let e = engine(&o)?;
    let k = open_key(&e, &o, HELP_SIGN)?;
    if o.qr && !o.card {
        return Err(Fail::Usage("--qr needs --card".into(), HELP_SIGN));
    }
    if [o.detached, o.pdf, o.card].iter().filter(|x| **x).count() > 1 {
        return Err(Fail::Usage(
            "choose one of --detached, --pdf and --card".into(),
            HELP_SIGN,
        ));
    }
    let lang = match o.lang.as_deref() {
        None => None,
        Some(l) => Some(kzsigner::pdf::card::CardLang::parse(l).ok_or_else(|| {
            Fail::Usage(
                format!("unknown --lang {l} (use ru, kk or kk/ru)"),
                HELP_SIGN,
            )
        })?),
    };
    let input = read(&file)?;
    if o.pdf && !e.is_pdf(&input) {
        return Err(Fail::User(format!("{} is not a PDF file.", file.display())));
    }
    let original = o.data.as_deref().map(read).transpose()?;
    let r = if o.card {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "document".into());
        e.sign_card(
            &input,
            &name,
            &k,
            o.tsa.as_deref().unwrap_or(kzsigner::DEFAULT_TSA_URL),
            o.ocsp.as_deref().unwrap_or(kzsigner::DEFAULT_OCSP_URL),
            lang,
            o.qr.then_some(true),
        )?
    } else if o.pdf {
        e.sign_pdf(&input, &k, o.tsa.as_deref())?
    } else {
        e.sign(
            &input,
            &k,
            o.detached,
            o.tsa.as_deref(),
            true,
            original.as_deref(),
        )?
    };
    let out = o.out.clone().unwrap_or_else(|| {
        if r.cosigned {
            file.clone()
        } else if o.card {
            PathBuf::from(format!("{}.card.pdf", file.display()))
        } else if o.pdf {
            signed_pdf_name(&file)
        } else {
            PathBuf::from(format!("{}.cms", file.display()))
        }
    });
    let overwrite = r.cosigned && out == file;
    let bak = PathBuf::from(format!("{}.bak", file.display()));
    if overwrite {
        std::fs::copy(&file, &bak)
            .map_err(|err| Fail::User(format!("could not write {}: {err}", bak.display())))?;
    }
    write(&out, &r.cms)?;
    for w in &r.warnings {
        println!("Warning: {w}");
    }
    let who = e.describe(&k.cert);
    println!(
        "{} by {}",
        if r.cosigned {
            "Signature added"
        } else {
            "Signed"
        },
        who.get("CN").unwrap_or("?")
    );
    println!(
        "Output: {}  ({} signature{}{})",
        out.display(),
        r.signer_count,
        if r.signer_count == 1 { "" } else { "s" },
        if r.timestamped {
            ", with timestamp"
        } else {
            ""
        }
    );
    if overwrite {
        println!("Previous version saved as {}", bak.display());
    }
    Ok(0)
}

/// document.pdf -> document-signed.pdf
fn signed_pdf_name(file: &Path) -> PathBuf {
    let stem = file
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    file.with_file_name(format!("{stem}-signed.pdf"))
}

fn verify(o: Opts) -> R<u8> {
    let file = need(&o.file, "parameter: 'FILE'", HELP_VERIFY)?;
    let e = engine(&o)?;
    let cms = read(file)?;
    let original = o.data.as_deref().map(read).transpose()?;
    let r = if o.qr {
        let doc = need(
            &original,
            "option with --qr: '--data=ORIGINAL'",
            HELP_VERIFY,
        )?;
        e.verify_qr(&String::from_utf8_lossy(&cms), doc, o.ocsp.as_deref())?
    } else {
        e.verify(&cms, original.as_deref(), o.ocsp.as_deref())?
    };
    if o.json {
        println!("{}", output::json(&r));
    } else {
        let data = o.data.as_ref().map(|d| d.display().to_string());
        print!("{}", output::text(&r, data.as_deref()));
    }
    Ok(if r.valid { 0 } else { 1 })
}

fn extract(o: Opts) -> R<u8> {
    let file = need(&o.file, "parameter: 'FILE'", HELP_EXTRACT)?;
    let data = read(file)?;
    let e = Engine::new(vec![]);
    let card = e.card_original(&data);
    let content = match &card {
        Some((_, c)) => c.clone(),
        None => e.extract(&data)?,
    };
    let out = match &o.out {
        Some(p) => p.clone(),
        None if card.is_some() => {
            let name = card.as_ref().map(|c| c.0.as_str()).unwrap_or_default();
            // only the name, never a path from inside the card
            let name = name
                .rsplit(['/', '\\'])
                .next()
                .map(str::to_string)
                .filter(|n| !n.is_empty() && n != "." && n != "..")
                .unwrap_or_else(|| "document".into());
            let mut p = file.with_file_name(name);
            if p.exists() {
                p = PathBuf::from(format!("{}.extracted", p.display()));
            }
            p
        }
        None => {
            let n = file.to_string_lossy();
            let mut p = if n.to_lowercase().ends_with(".cms") {
                PathBuf::from(&n[..n.len() - 4])
            } else {
                PathBuf::from(format!("{n}.original"))
            };
            if p.exists() {
                p = PathBuf::from(format!("{}.extracted", p.display()));
            }
            p
        }
    };
    write(&out, &content)?;
    println!("Extracted {} bytes to {}", content.len(), out.display());
    Ok(0)
}

fn info(o: Opts) -> R<u8> {
    let e = engine(&o)?;
    let k = open_key(&e, &o, HELP_INFO)?;
    let s = e.describe(&k.cert);
    let others = if k.other_aliases.is_empty() {
        String::new()
    } else {
        format!("   (other keys in file: [{}])", k.other_aliases.join(", "))
    };
    let f = |x: &Option<String>| x.clone().unwrap_or_default();
    println!("Alias:        {}{others}", k.alias);
    println!("Subject:      {}", f(&s.subject_dn));
    println!("Issuer:       {}", f(&s.issuer_dn));
    println!("Serial:       {}", f(&s.serial_hex));
    println!(
        "Valid:        {} .. {}",
        kzsigner::time::fmt(s.not_before),
        kzsigner::time::fmt(s.not_after)
    );
    println!("Key type:     {}", f(&s.algorithm));
    if !s.cert_types.is_empty() {
        println!("NCA type:     {}", s.cert_types.join("/"));
    }
    println!("Trust:        {}", f(&s.chain_status));
    for w in e.key_warnings(&k.cert) {
        println!("Warning:      {w}");
    }
    Ok(0)
}

#[cfg(feature = "gui")]
fn gui(o: Opts) -> R<u8> {
    let e = engine(&o)?;
    kzsigner::gui::run(e, o.file).map_err(Fail::User)?;
    Ok(0)
}

#[cfg(not(feature = "gui"))]
fn gui(_: Opts) -> R<u8> {
    Err(Fail::User(
        "This build of kzsigner has no window; use the commands (see --help).".into(),
    ))
}

/// Whether a window can be shown.
fn display_available() -> bool {
    cfg!(feature = "gui")
        && (cfg!(any(windows, target_os = "macos"))
            || std::env::var_os("DISPLAY").is_some()
            || std::env::var_os("WAYLAND_DISPLAY").is_some())
}

fn run() -> R<u8> {
    if std::env::args_os().len() <= 1 {
        if display_available() {
            hide_console();
            return gui(Opts::default());
        }
        print!("{HELP}");
        return Ok(0);
    }
    use lexopt::prelude::*;
    let mut p = lexopt::Parser::from_env();
    let cmd = match p.next()? {
        Some(Short('h') | Long("help")) => {
            print!("{HELP}");
            return Ok(0);
        }
        Some(Short('V') | Long("version")) => {
            print_version();
            return Ok(0);
        }
        Some(Value(v)) => v.string()?,
        Some(other) => return Err(Fail::Usage(other.unexpected().to_string(), HELP)),
        None => return Ok(0),
    };
    let (help, f): (&'static str, fn(Opts) -> R<u8>) = match cmd.as_str() {
        "sign" => (HELP_SIGN, sign),
        "verify" => (HELP_VERIFY, verify),
        "extract" => (HELP_EXTRACT, extract),
        "info" => (HELP_INFO, info),
        "gui" => (HELP_GUI, gui),
        // "Open with kzsigner" on a file
        _ if p.next()?.is_none() && Path::new(&cmd).is_file() && display_available() => {
            hide_console();
            return gui(Opts {
                file: Some(cmd.into()),
                ..Default::default()
            });
        }
        _ => return Err(Fail::Usage(format!("Unmatched argument: '{cmd}'"), HELP)),
    };
    match parse(p, &cmd, help)? {
        Some(o) => f(o),
        None => Ok(0),
    }
}

/// Windows before 11 24H2 opens a console for kzsigner when it is started from Explorer. That
/// console is kzsigner's alone (a terminal's is shared with the shell): close it so only the
/// window stays. From a terminal, or with no console at all (24H2 and later), nothing happens.
fn hide_console() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
        let mut ids = [0u32; 2];
        if GetConsoleProcessList(ids.as_mut_ptr(), 2) == 1 {
            FreeConsole();
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(Fail::User(m)) => {
            eprintln!("Error: {m}");
            ExitCode::from(1)
        }
        Err(Fail::Usage(m, help)) => {
            eprintln!("{m}");
            eprint!("{help}");
            ExitCode::from(2)
        }
    }
}
