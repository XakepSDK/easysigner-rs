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
                    return for_viewing(&dir, &doc, &data);
                }
                let (name, content) = match taken_out(e, &doc, &data) {
                    Ok(x) => x,
                    // detached: the document is the original chosen beside it
                    Err(_) if e.is_signed_cms(&data) => {
                        let original = original
                            .ok_or_else(|| tr("Choose the signed document.").to_string())?;
                        let data = std::fs::read(&original)
                            .map_err(|err| format!("{}: {err}", original.display()))?;
                        return for_viewing(&dir, &original, &data);
                    }
                    Err(err) => return Err(err),
                };
                write_for_viewing(&dir, &viewable_name(&name, &content)?, &content)
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

/// What `data` really is, from its content alone: the extension to open it with. None for
/// anything that is not a document or picture kzsigner hands to a viewer (programs, scripts,
/// shortcuts, Office files with macros, unknown formats). The extension chosen decides which
/// program opens the file, so text is always opened as .txt (a web page or script inside shows
/// as text in a text editor) or as .xml when it is XML and not a web page. `claimed` (the
/// name's own extension, lowercase) only picks between spellings and formats the content
/// can't tell apart: jpg/jpeg, tif/tiff, and doc/xls/ppt for old Office files.
pub(super) fn sniff(data: &[u8], claimed: &str) -> Option<&'static str> {
    let pick = |options: &[&'static str]| {
        options
            .iter()
            .copied()
            .find(|o| *o == claimed)
            .unwrap_or(options[0])
    };
    let head = &data[..data.len().min(1024)];
    // PDF readers accept up to 1 KB of anything before the header
    if head.windows(5).any(|w| w == b"%PDF-") {
        return Some("pdf");
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("png");
    }
    if data.starts_with(b"\xff\xd8\xff") {
        return Some(pick(&["jpg", "jpeg"]));
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("gif");
    }
    if data.starts_with(b"II*\0") || data.starts_with(b"MM\0*") {
        return Some(pick(&["tif", "tiff"]));
    }
    if data.len() > 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        return Some("webp");
    }
    if data.starts_with(b"{\\rtf") {
        return Some("rtf");
    }
    // old Office files (OLE compound files); Office blocks macros in a file marked as
    // downloaded, which every copy kzsigner makes is
    if data.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        return Some(pick(&["doc", "xls", "ppt"]));
    }
    if data.starts_with(b"PK\x03\x04") {
        return sniff_zip(data);
    }
    // text: no NUL or other control bytes below tab, in UTF-8 or a single-byte encoding
    // (windows-1251 and the like)
    if data.iter().all(|b| *b >= 0x09) {
        return Some(if is_plain_xml(head) { "xml" } else { "txt" });
    }
    None
}

/// XML that is not a web page (HTML, SVG, XHTML, or XML with a stylesheet), which a browser
/// opening a .xml file would render and run scripts in.
fn is_plain_xml(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head).to_lowercase();
    let t = text.trim_start_matches('\u{feff}').trim_start();
    t.starts_with('<')
        && ![
            "<html",
            "<!doctype",
            "<svg",
            "xhtml",
            "<script",
            "xml-stylesheet",
        ]
        .iter()
        .any(|m| t.contains(m))
}

/// A zip: a Word, Excel or PowerPoint file (without macros), an OpenDocument file, or a plain
/// zip.
fn sniff_zip(data: &[u8]) -> Option<&'static str> {
    let z = zip::ZipArchive::new(std::io::Cursor::new(data)).ok()?;
    // a name that can't be read could hide anything: refused
    let names: Vec<String> = z
        .file_names()
        .map(|n| n.map(|n| n.to_lowercase()))
        .collect::<Result<_, _>>()
        .ok()?;
    let has = |n: &str| names.iter().any(|x| x == n);
    // macros (Office keeps them in vbaProject.bin): never opened from here
    if names.iter().any(|n| n.ends_with("vbaproject.bin")) {
        return None;
    }
    if has("[content_types].xml") {
        return if has("word/document.xml") {
            Some("docx")
        } else if has("xl/workbook.xml") {
            Some("xlsx")
        } else if has("ppt/presentation.xml") {
            Some("pptx")
        } else {
            None
        };
    }
    if has("mimetype") {
        let mut z = z;
        let mut m = String::new();
        use std::io::Read as _;
        z.by_name("mimetype")
            .ok()?
            .take(100)
            .read_to_string(&mut m)
            .ok()?;
        return match m.trim() {
            "application/vnd.oasis.opendocument.text" => Some("odt"),
            "application/vnd.oasis.opendocument.spreadsheet" => Some("ods"),
            "application/vnd.oasis.opendocument.presentation" => Some("odp"),
            _ => None,
        };
    }
    Some("zip")
}

/// `name` with the extension of what `data` really is ("contract.exe" holding a PDF gives
/// "contract.exe.pdf"); an error for anything that is not a document or picture.
pub(super) fn viewable_name(name: &str, data: &[u8]) -> Result<String, String> {
    let ext = Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match sniff(data, &ext) {
        Some(real) if real == ext => Ok(name.to_string()),
        Some(real) => Ok(format!("{name}.{real}")),
        None => Err(not_viewable()),
    }
}

/// The file to open for reading `path` (holding `data`): itself when its name already says
/// what it is, otherwise a copy named for its real type.
pub(super) fn for_viewing(dir: &Path, path: &Path, data: &[u8]) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "document".into());
    let wanted = viewable_name(&name, data)?;
    if wanted == name {
        Ok(path.to_path_buf())
    } else {
        write_for_viewing(dir, &wanted, data)
    }
}

fn not_viewable() -> String {
    tr("kzsigner opens only documents and pictures, and this file is neither (or is an Office file with macros). Save it and open it yourself only if you trust whoever sent it: a valid signature does not make a file safe to run.").into()
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
    "pdf", "txt", "xml", "rtf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp",
    "png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "webp", "zip",
];

/// A last check before a file goes to the system's viewer: its name must end in one of
/// [`VIEWABLE`] (what [`viewable_name`] gives a file whose content it recognised).
pub(super) fn check_viewable(f: &Path) -> Result<(), String> {
    let ext = f
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if VIEWABLE.contains(&ext.as_str()) {
        Ok(())
    } else {
        Err(not_viewable())
    }
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
