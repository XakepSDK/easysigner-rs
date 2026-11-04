//! Files taken out of signed files, opened for reading or shown in the file manager.

use super::*;

impl App {
    /// Opens the document to sign for reading: the file itself, or the document inside a
    /// signed file (a .cms or a card), taken out into a private temporary folder. For a
    /// detached .cms, the original chosen beside it.
    pub fn view_doc(&mut self, ctx: &egui::Context, doc: PathBuf) {
        let original = self.sign.sign_original.clone();
        self.view_file(ctx, doc, original, ViewFor::Sign(self.sign.doc_request));
    }

    /// Opens `doc` for reading, or the document inside it when it is signed (`original` for a
    /// detached .cms). `id`: the choice it is for.
    pub(super) fn view_file(
        &mut self,
        ctx: &egui::Context,
        doc: PathBuf,
        original: Option<PathBuf>,
        id: ViewFor,
    ) {
        let dir = self.dialogs.view_dir();
        self.background(ctx, move |e| {
            let r = (|| -> Result<PathBuf, String> {
                let data =
                    std::fs::read(&doc).map_err(|err| format!("{}: {err}", doc.display()))?;
                // what the file is, from its content (the background check may still be running)
                let signed = e.is_signed_cms(&data) || e.card_original(&data).is_some();
                if !signed {
                    return Ok(doc);
                }
                let (name, content) = match taken_out(e, &doc, &data) {
                    Ok(x) => x,
                    // detached: the document is the original chosen beside it
                    Err(_) if e.is_signed_cms(&data) => {
                        return original.ok_or_else(|| tr("Choose the signed document.").into());
                    }
                    Err(err) => return Err(err),
                };
                write_for_viewing(&dir, &viewable_name(&name, &content), &content)
            })();
            Msg::ToView(id, r)
        });
    }
}

/// The name for the document taken out of signed `file`: a card's document keeps its own name
/// (only the name, never a path inside the card), "x.pdf.cms" gives "x.pdf", anything else
/// "<name>.original".
pub(super) fn original_name(file: &Path, card_name: Option<&str>) -> String {
    let n = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let card_name = card_name
        .and_then(|n| n.rsplit(['/', '\\']).next())
        .filter(|n| !n.is_empty() && *n != "." && *n != "..");
    if let Some(c) = card_name {
        // no Windows stream names (a.exe:b.pdf), reserved characters or control characters
        c.chars()
            .map(|ch| {
                if ch.is_control() || "<>:\"|?*".contains(ch) || is_bidi_control(ch) {
                    '_'
                } else {
                    ch
                }
            })
            .collect()
    } else if n.to_lowercase().ends_with(".cms") {
        n[..n.len() - 4].to_string()
    } else {
        format!("{n}.original")
    }
}

/// The document inside a signed file (a card's original, or a .cms's content), with its name.
pub(super) fn taken_out(e: &Engine, file: &Path, data: &[u8]) -> Result<(String, Vec<u8>), String> {
    match e.card_original(data) {
        Some((name, d)) => Ok((original_name(file, Some(&name)), d)),
        None => Ok((original_name(file, None), e.extract(data).map_err(|x| x.0)?)),
    }
}

/// `name` with an extension a viewer understands, guessed from the content when it has none
/// that helps ("contract" from contract.cms holding a PDF gives "contract.pdf").
pub(super) fn viewable_name(name: &str, data: &[u8]) -> String {
    let ext = Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase());
    if ext.is_some_and(|e| e != "original") {
        return name.to_string();
    }
    let guess = if data.starts_with(b"%PDF") {
        "pdf"
    } else if data.starts_with(b"\x89PNG") {
        "png"
    } else if data.starts_with(b"\xff\xd8\xff") {
        "jpg"
    } else if data.starts_with(b"PK\x03\x04") {
        "zip"
    } else if std::str::from_utf8(data).is_ok() {
        "txt"
    } else {
        return name.to_string();
    };
    format!("{name}.{guess}")
}

/// Writes `data` as `name` in a fresh folder under `dir`, readable only by this user; copies
/// made for earlier viewing are removed first.
pub(super) fn write_for_viewing(dir: &Path, name: &str, data: &[u8]) -> Result<PathBuf, String> {
    let fail = |p: &Path, err: std::io::Error| format!("{}: {err}", p.display());
    // a viewer may still hold an old copy open (Windows): then it stays until next time
    let _ = std::fs::remove_dir_all(dir);
    let sub = dir.join(time::now_ms().to_string());
    std::fs::create_dir_all(&sub).map_err(|err| fail(&sub, err))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for d in [dir, sub.as_path()] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))
                .map_err(|err| fail(d, err))?;
        }
    }
    let out = sub.join(name);
    std::fs::write(&out, data).map_err(|err| fail(&out, err))?;
    // Mark of the Web: the document came from someone else, so Office and other viewers open
    // it in Protected View. A file system without streams (FAT, a network share) just skips it.
    #[cfg(windows)]
    {
        let mut zone = out.clone().into_os_string();
        zone.push(":Zone.Identifier");
        let _ = std::fs::write(zone, b"[ZoneTransfer]\r\nZoneId=3\r\n");
    }
    Ok(out)
}

/// Unicode bidirectional controls, which can make "fdp.exe" look like "exe.pdf" in a name.
fn is_bidi_control(ch: char) -> bool {
    matches!(ch, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// The types "Open the document" hands to the system's viewer: documents and pictures, never
/// anything the system would run (a program, a shortcut, a script, an installer, a page with
/// scripts, an Office file with macros). A signed file can carry any file under any name, and
/// a valid signature says nothing about whether it is safe to run.
const VIEWABLE: &[&str] = &[
    "pdf", "txt", "xml", "csv", "rtf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods",
    "odp", "png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "webp", "zip",
];

/// Refuses to open `f` unless its type is one of [`VIEWABLE`].
pub(super) fn check_viewable(f: &Path) -> Result<(), String> {
    let ext = f
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if VIEWABLE.contains(&ext.as_str()) {
        return Ok(());
    }
    let kind = if ext.is_empty() {
        tr("a file of unknown type").to_string()
    } else {
        format!(".{ext}")
    };
    Err(trf(
        "kzsigner opens only documents and pictures, and this is {}. Save it and open it yourself only if you trust whoever sent it: a valid signature does not make a file safe to run.",
        &[&kind],
    ))
}

/// Opens `f` with the program the system uses for its type.
pub(super) fn open_with_system(f: &Path) -> std::io::Result<()> {
    // the shell's own file handler: no command line parsing of the path (explorer splits
    // at commas)
    #[cfg(windows)]
    let child = std::process::Command::new("rundll32")
        .arg("url.dll,FileProtocolHandler")
        .arg(f)
        .spawn()?;
    #[cfg(target_os = "macos")]
    let child = std::process::Command::new("open").arg(f).spawn()?;
    #[cfg(not(any(windows, target_os = "macos")))]
    let child = std::process::Command::new("xdg-open").arg(f).spawn()?;
    // reap it when it ends
    std::thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
    });
    Ok(())
}

/// Opens the folder with `f` in the system's file manager.
pub(super) fn show_in_folder(f: &Path) {
    // explorer wants /select,"C:\a b\c.cms" as one argument, quoted only around the path
    #[cfg(windows)]
    let r = {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("explorer")
            .raw_arg(format!("/select,\"{}\"", f.display()))
            .spawn()
    };
    #[cfg(target_os = "macos")]
    let r = std::process::Command::new("open").arg("-R").arg(f).spawn();
    #[cfg(not(any(windows, target_os = "macos")))]
    let r = std::process::Command::new("xdg-open")
        .arg(f.parent().unwrap_or(Path::new(".")))
        .spawn();
    let _ = r;
}
