//! kzsigner command line; with no arguments it opens the window.
//!
//! On Windows this is a GUI program, so double-clicking it shows no console window. For the
//! commands it attaches to the console of whatever started it; `kzsigner.com` (the console
//! launcher in src/bin/kzsigner-console.rs) makes `kzsigner ...` in a terminal wait for it.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kzsigner::cert::Cert;
use kzsigner::{Engine, Error, output};

const HELP: &str = "\
Usage: kzsigner [-hV] [COMMAND | FILE]
Sign and verify .cms files with Kazakhstan NCA RK keys, locally, without NCALayer.
Run without arguments, or with just a FILE, to open the desktop window.
Network is used only with --tsa (NCA timestamp) and --ocsp (NCA revocation check).
  -h, --help      Show this help message and exit.
  -V, --version   Print version information and exit.
Commands:
  gui      Open the desktop window (default).
  sign     Sign FILE into FILE.cms.
  verify   Check every signature in a .cms. Exit code 0 only if all are valid.
  extract  Write out the document embedded in a .cms.
  info     Show the certificate inside a key file.
Run 'kzsigner COMMAND --help' for a command's options.
";

const HELP_SIGN: &str = "\
Usage: kzsigner sign [-hV] [--detached] -k=KEY.p12 [-p=PASSWORD] [--alias=ALIAS]
                     [-o=OUT] [--tsa[=URL]] [--data=ORIGINAL] [--trust=CA.cer]... FILE
Sign FILE into FILE.cms.
If FILE is already a .cms, your signature is ADDED to it (co-signing).
      FILE                 Document, or .cms to co-sign.
  -k, --key=KEY.p12        Your key file.
  -p, --password=PASSWORD  Key password (or env KZSIGNER_PASSWORD; prompted otherwise).
      --alias=ALIAS        Key alias, if the file holds several keys.
  -o, --out=OUT            Output file.
      --detached           Do not embed the document in the .cms.
      --tsa[=URL]          Add a timestamp (default http://tsp.pki.gov.kz:80).
      --data=ORIGINAL      Original document, to co-sign a detached .cms.
      --trust=CA.cer       Extra trusted CA certificate (repeatable), on top of NCA RK's.
";

const HELP_VERIFY: &str = "\
Usage: kzsigner verify [-hV] [--json] [--data=ORIGINAL] [--ocsp[=URL]] [--trust=CA.cer]... FILE.cms
Check every signature in a .cms. Exit code 0 only if all are valid.
      FILE.cms
      --data=ORIGINAL   Original document, for a detached .cms.
      --ocsp[=URL]      Check revocation online (default http://ocsp.pki.gov.kz).
      --json            Machine-readable output.
      --trust=CA.cer    Extra trusted CA certificate (repeatable), on top of NCA RK's.
";

const HELP_EXTRACT: &str = "\
Usage: kzsigner extract [-hV] [-o=OUT] FILE.cms
Write out the document embedded in a .cms.
      FILE.cms
  -o, --out=OUT   Output file (default: FILE without .cms).
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
            Long("json") if allowed(&["verify"]) => o.json = true,
            Long("tsa") if allowed(&["sign"]) => {
                o.tsa = Some(optional_url(&mut p, kzsigner::DEFAULT_TSA_URL)?)
            }
            Long("ocsp") if allowed(&["verify"]) => {
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
    let input = read(&file)?;
    let original = o.data.as_deref().map(read).transpose()?;
    let r = e.sign(
        &input,
        &k,
        o.detached,
        o.tsa.as_deref(),
        true,
        original.as_deref(),
    )?;
    let out = o.out.clone().unwrap_or_else(|| {
        if r.cosigned {
            file.clone()
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

fn verify(o: Opts) -> R<u8> {
    let file = need(&o.file, "parameter: 'FILE.cms'", HELP_VERIFY)?;
    let e = engine(&o)?;
    let cms = read(file)?;
    let original = o.data.as_deref().map(read).transpose()?;
    let r = e.verify(&cms, original.as_deref(), o.ocsp.as_deref())?;
    if o.json {
        println!("{}", output::json(&r));
    } else {
        let data = o.data.as_ref().map(|d| d.display().to_string());
        print!("{}", output::text(&r, data.as_deref()));
    }
    Ok(if r.valid { 0 } else { 1 })
}

fn extract(o: Opts) -> R<u8> {
    let file = need(&o.file, "parameter: 'FILE.cms'", HELP_EXTRACT)?;
    let content = Engine::new(vec![]).extract(&read(file)?)?;
    let out = match &o.out {
        Some(p) => p.clone(),
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

/// Windows: a GUI program has no console of its own. Attach to the parent's (the terminal, or
/// kzsigner.com) so output, prompts and Ctrl+C work, keeping any redirected handles.
fn attach_console() {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{
            ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
            STD_OUTPUT_HANDLE, SetStdHandle,
        };
        let ids = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
        let before = ids.map(|i| GetStdHandle(i));
        if AttachConsole(ATTACH_PARENT_PROCESS) != 0 {
            for (i, h) in ids.into_iter().zip(before) {
                if !h.is_null() && h as isize != -1 {
                    SetStdHandle(i, h);
                }
            }
        }
    }
}

fn main() -> ExitCode {
    if std::env::args_os().len() > 1 {
        attach_console();
    }
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
