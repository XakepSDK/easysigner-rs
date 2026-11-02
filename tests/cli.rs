//! The command line's option checks: each option only where it means something, `sign --hash`
//! without file options, and the names `extract` and `info` give.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(p: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(p)
        .display()
        .to_string()
}

/// Runs kzsigner in `dir`; returns (success, stdout + stderr).
fn kz(dir: &Path, args: &[&str], password: Option<&str>) -> (bool, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_kzsigner"));
    c.args(args)
        .current_dir(dir)
        .env_remove("KZSIGNER_PASSWORD");
    if let Some(p) = password {
        c.env("KZSIGNER_PASSWORD", p);
    }
    let o = c.output().unwrap();
    (
        o.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
    )
}

/// A work folder, removed when dropped.
struct Work(PathBuf);

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl std::ops::Deref for Work {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

fn work(name: &str) -> Work {
    let d = std::env::temp_dir().join(format!("kzsigner-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("doc.txt"), b"hello").unwrap();
    Work(d)
}

#[test]
fn options_only_where_they_mean_something() {
    let d = work("options");
    let refused = [
        ("verify", &["-k", "x"][..]),
        ("verify", &["-p", "x"]),
        ("verify", &["--alias", "x"]),
        ("extract", &["--trust", "x"]),
        ("verify", &["-o", "x"]),
        ("extract", &["--data", "x"]),
        ("verify", &["--stamp"]),
        ("verify", &["--stamp-page", "1"]),
        ("verify", &["--stamp-at", "br"]),
        ("verify", &["--stamp-lang", "ru"]),
        ("verify", &["--stamp-logo", "x"]),
        ("verify", &["--level", "LT"]),
        ("verify", &["--detached"]),
        ("verify", &["--pdf"]),
        ("verify", &["--hash", "00"]),
        ("sign", &["--alg", "sha256"]),
        ("verify", &["--xml"]),
        ("verify", &["--card"]),
        ("extract", &["--qr"]),
        ("verify", &["--lang", "ru"]),
        ("sign", &["--json"]),
        ("verify", &["--tsa"]),
        ("extract", &["--ocsp"]),
        ("info", &["doc.txt"]),
        ("verify", &["doc.txt", "doc.txt"]),
    ];
    for (cmd, opts) in refused {
        let mut args = vec![cmd];
        args.extend(opts);
        let (ok, out) = kz(&d, &args, Some("Qwerty12"));
        assert!(!ok, "{args:?} was accepted: {out}");
        assert!(
            out.contains("unexpected") || out.contains("invalid option"),
            "{args:?}: {out}"
        );
    }
    let (ok, out) = kz(
        &d,
        &["sign", "--stamp-page", "0", "doc.txt"],
        Some("Qwerty12"),
    );
    assert!(
        !ok && out.contains("--stamp-page needs a page number"),
        "{out}"
    );
    let (ok, out) = kz(&d, &["verify", "missing.cms"], None);
    assert!(!ok && out.contains("file not found: missing.cms"), "{out}");
}

#[test]
fn hash_signing_takes_no_file_options() {
    let d = work("hash");
    let key = fixture("keys/alice_gost2015.p12");
    let hash = "00".repeat(64);
    for extra in [
        &["doc.txt"][..],
        &["--pdf"],
        &["--xml"],
        &["--card"],
        &["--data", "doc.txt"],
        &["--stamp"],
        &["--stamp-logo", "doc.txt"],
        &["--qr"],
        &["--lang", "ru"],
    ] {
        let mut args = vec!["sign", "-k", &key, "--hash", &hash];
        args.extend(extra);
        let (ok, out) = kz(&d, &args, Some("Qwerty12"));
        assert!(
            !ok && out.contains("--hash signs a hash"),
            "{extra:?}: {out}"
        );
    }
}

#[test]
fn info_and_passwords() {
    let d = work("info");
    let key = fixture("keys/alice_gost2015.p12");
    let (ok, out) = kz(&d, &["info", "-k", &key, "-p", "Qwerty12"], None);
    assert!(ok, "{out}");
    assert!(out.contains("NCA type:     SIGNATURE"), "{out}");
    assert!(out.contains("Key type:     GOST 34.10-2015 (512)"), "{out}");
    let (ok, out) = kz(&d, &["info", "-k", &key], None);
    assert!(!ok && out.contains("No password given"), "{out}");
    let (ok, out) = kz(
        &d,
        &["info", "-k", &key, "--alias", "nobody"],
        Some("Qwerty12"),
    );
    assert!(!ok && out.contains("No key with alias 'nobody'"), "{out}");
}

#[test]
fn extracted_file_names() {
    let d = work("extracted");
    let key = fixture("keys/alice_gost2015.p12");
    let ca = fixture("keys/ca_gost2015.cer");
    let (ok, out) = kz(
        &d,
        &["sign", "-k", &key, "--trust", &ca, "doc.txt"],
        Some("Qwerty12"),
    );
    assert!(ok, "{out}");
    std::fs::copy(d.join("doc.txt.cms"), d.join("other.p7s")).unwrap();
    std::fs::copy(d.join("doc.txt.cms"), d.join("new.cms")).unwrap();
    // FILE.cms gives FILE, or FILE.extracted when FILE is there; anything else FILE.original
    for (file, out) in [
        ("doc.txt.cms", "doc.txt.extracted"),
        ("new.cms", "new"),
        ("other.p7s", "other.p7s.original"),
    ] {
        let (ok, o) = kz(&d, &["extract", file], None);
        assert!(ok, "{file}: {o}");
        assert_eq!(std::fs::read(d.join(out)).unwrap(), b"hello", "{file}");
    }
}
