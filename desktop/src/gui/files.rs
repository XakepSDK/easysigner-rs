//! Files taken out of signed files, opened for reading or shown in the file manager.

use std::io::{Read, Seek, SeekFrom};

use std::path::{Path, PathBuf};

use super::text::t;
use kzsigner::time;

/// How much of a file's start is read to tell what it is (what `infer` itself reads).
const HEAD: u64 = 8192;

/// Up to [`HEAD`] bytes from the start of `r`.
fn read_head(r: &mut (impl Read + Seek)) -> std::io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(0))?;
    let mut head = Vec::new();
    r.take(HEAD).read_to_end(&mut head)?;
    Ok(head)
}

/// What the content of `r` really is: the extension to open it with. None for anything that
/// is not a document or picture kzsigner hands to a viewer (programs, scripts, shortcuts,
/// Office files with macros, unknown formats). The type comes from the `infer` crate (magic
/// numbers); zips are then checked by their table of contents, and text by every byte, both
/// read from `r` as needed rather than loaded whole.
///
/// The extension chosen decides which program opens the file, so text is always opened as
/// .txt (a web page or script inside shows as text in a text editor), or as .xml when it is
/// XML and not a web page. `claimed` (the name's own extension, lowercase) only picks between
/// spellings and formats the content can't tell apart: jpg/jpeg, tif/tiff, and doc/xls/ppt
/// for old Office files.
pub(super) fn sniff(
    r: &mut (impl Read + Seek),
    claimed: &str,
) -> std::io::Result<Option<&'static str>> {
    let pick = |options: &[&'static str]| {
        options
            .iter()
            .copied()
            .find(|o| *o == claimed)
            .unwrap_or(options[0])
    };
    let head = read_head(r)?;
    let Some(kind) = infer::get(&head) else {
        return text_kind(r, &head);
    };
    Ok(match kind.mime_type() {
        "application/pdf" => Some("pdf"),
        "image/png" => Some("png"),
        "image/jpeg" => Some(pick(&["jpg", "jpeg"])),
        "image/gif" => Some("gif"),
        "image/bmp" => Some("bmp"),
        "image/tiff" => Some(pick(&["tif", "tiff"])),
        "image/webp" => Some("webp"),
        "text/rtf" | "application/rtf" => Some("rtf"),
        // old Office files (OLE compound files); without reading the whole file `infer`
        // can't tell Word from Excel. Office blocks macros in a file marked as downloaded,
        // which every copy kzsigner makes is.
        "application/msword" | "application/vnd.ms-excel" | "application/vnd.ms-powerpoint" => {
            Some(pick(&["doc", "xls", "ppt"]))
        }
        // Office, OpenDocument or a plain zip: told apart (and macros found) by the zip's
        // table of contents, since `infer` only sees the first entries
        "application/zip"
        | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        | "application/vnd.oasis.opendocument.text"
        | "application/vnd.oasis.opendocument.spreadsheet"
        | "application/vnd.oasis.opendocument.presentation" => zip_kind(r),
        // text `infer` names (HTML, XML, shell scripts): shown as text
        _ if kind.matcher_type() == infer::MatcherType::Text => return text_kind(r, &head),
        // programs, libraries, installers, other archives, fonts, media: not opened
        _ => None,
    })
}

/// Text, checked byte by byte without holding it all: no NUL or other control bytes below
/// tab, in UTF-8 or a single-byte encoding (windows-1251 and the like).
fn text_kind(r: &mut (impl Read + Seek), head: &[u8]) -> std::io::Result<Option<&'static str>> {
    r.seek(SeekFrom::Start(0))?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf[..n].iter().any(|b| *b < 0x09) {
            return Ok(None);
        }
    }
    Ok(Some(if is_plain_xml(head) { "xml" } else { "txt" }))
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

/// A zip, from its table of contents (read from the end of the file, not the whole file): a
/// Word, Excel or PowerPoint file, an OpenDocument file, or a plain zip; None with macros.
fn zip_kind(r: &mut (impl Read + Seek)) -> Option<&'static str> {
    r.seek(SeekFrom::Start(0)).ok()?;
    let mut z = zip::ZipArchive::new(r).ok()?;
    // a name that can't be read could hide anything: refused
    let names: Vec<String> = z
        .file_names()
        .map(|n| n.map(|n| n.to_lowercase()))
        .collect::<Result<_, _>>()
        .ok()?;
    let has = |n: &str| names.iter().any(|x| x == n);
    // macros: Office keeps them in vbaProject.bin, OpenDocument in Basic/ or Scripts/
    if names.iter().any(|n| {
        n.ends_with("vbaproject.bin") || n.starts_with("basic/") || n.starts_with("scripts/")
    }) {
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
        let mut m = String::new();
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

/// `name` with the extension of what `r` really holds ("contract.exe" holding a PDF gives
/// "contract.exe.pdf"); an error for anything that is not a document or picture.
pub(super) fn viewable_name(name: &str, r: &mut (impl Read + Seek)) -> Result<String, String> {
    let ext = Path::new(name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    match sniff(r, &ext).map_err(|e| e.to_string())? {
        Some(real) if real == ext => Ok(name.to_string()),
        Some(real) => Ok(format!("{name}.{real}")),
        None => Err(not_viewable()),
    }
}

/// The file to open for reading `path` (open as `f`): itself when its name already says what
/// it is, otherwise a copy named for its real type.
pub(super) fn for_viewing(
    dir: &Path,
    path: &Path,
    mut f: std::fs::File,
) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "document".into());
    let wanted = viewable_name(&name, &mut f)?;
    if wanted == name {
        Ok(path.to_path_buf())
    } else {
        f.seek(SeekFrom::Start(0))
            .map_err(|err| format!("{}: {err}", path.display()))?;
        write_for_viewing(dir, &wanted, f)
    }
}

fn not_viewable() -> String {
    t("kzsigner opens only documents and pictures, and this file is neither (or is an Office file with macros). Save it and open it yourself only if you trust whoever sent it: a valid signature does not make a file safe to run.").into()
}

/// Copies `data` to `name` in a fresh folder under `dir`, readable only by this user; copies
/// made for earlier viewing are removed first.
pub(super) fn write_for_viewing(
    dir: &Path,
    name: &str,
    mut data: impl Read,
) -> Result<PathBuf, String> {
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
    let mut file = std::fs::File::create(&out).map_err(|err| fail(&out, err))?;
    std::io::copy(&mut data, &mut file).map_err(|err| fail(&out, err))?;
    drop(file);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_for_documents_to_view() {
        let ok = |n: &str, d: &[u8]| viewable_name(n, &mut std::io::Cursor::new(d)).unwrap();
        assert_eq!(ok("contract.pdf", b"%PDF-1.7"), "contract.pdf");
        assert_eq!(ok("contract", b"%PDF-1.7"), "contract.pdf");
        assert_eq!(
            ok("a.p7s.original", "текст".as_bytes()),
            "a.p7s.original.txt"
        );
    }

    /// A zip holding `names` (each with empty content).
    fn zip_of(names: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (n, d) in names {
            z.start_file(*n, zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(d).unwrap();
        }
        z.finish().unwrap().into_inner()
    }

    #[test]
    fn the_content_decides_how_a_file_is_opened() {
        let name = |n: &str, d: &[u8]| viewable_name(n, &mut std::io::Cursor::new(d));
        // a program, whatever it is called, is never opened
        let exe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff";
        for n in ["a.exe", "a.pdf", "a.docx", "a.txt", "noext"] {
            assert!(name(n, exe).is_err(), "{n}");
        }
        assert!(name("a.bin", &[0, 1, 2, 3]).is_err());
        // a document under a dangerous name gets its real type added
        assert_eq!(name("invoice.exe", b"%PDF-1.7").unwrap(), "invoice.exe.pdf");
        assert_eq!(
            name("a.lnk", b"\x89PNG\r\n\x1a\n....").unwrap(),
            "a.lnk.png"
        );
        // scripts and pages are text, shown as text, never run or rendered
        assert_eq!(
            name("a.hta", b"<html><script>x()</script>").unwrap(),
            "a.hta.txt"
        );
        assert_eq!(name("a.js", b"WScript.Shell").unwrap(), "a.js.txt");
        assert_eq!(name("a.xml", b"<svg onload='x()'/>").unwrap(), "a.xml.txt");
        assert_eq!(name("a.csv", b"=cmd|' /c calc'!A1").unwrap(), "a.csv.txt");
        assert_eq!(
            name("a.xml", b"<?xml version='1.0'?><doc/>").unwrap(),
            "a.xml"
        );
        assert_eq!(name("data", b"\xef\xbb\xbf<doc/>").unwrap(), "data.xml");
        // windows-1251 text
        assert_eq!(
            name("a.txt", &[0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2]).unwrap(),
            "a.txt"
        );
        // Office files by what the zip holds, refused with macros
        let docx = zip_of(&[("[Content_Types].xml", b""), ("word/document.xml", b"")]);
        assert_eq!(name("a.docx", &docx).unwrap(), "a.docx");
        assert_eq!(name("a.exe", &docx).unwrap(), "a.exe.docx");
        let xlsx = zip_of(&[("[Content_Types].xml", b""), ("xl/workbook.xml", b"")]);
        assert_eq!(name("a.docx", &xlsx).unwrap(), "a.docx.xlsx");
        let docm = zip_of(&[
            ("[Content_Types].xml", b""),
            ("word/document.xml", b""),
            ("word/vbaProject.bin", b""),
        ]);
        assert!(name("a.docx", &docm).is_err());
        let odt = zip_of(&[("mimetype", b"application/vnd.oasis.opendocument.text")]);
        assert_eq!(name("a.odt", &odt).unwrap(), "a.odt");
        assert_eq!(
            name("a.jar", &zip_of(&[("x.class", b"")])).unwrap(),
            "a.jar.zip"
        );
        // old Office files keep the claimed one of doc/xls/ppt
        let ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest";
        assert_eq!(name("a.xls", ole).unwrap(), "a.xls");
        assert_eq!(name("a.exe", ole).unwrap(), "a.exe.doc");
    }

    /// Counts the bytes read through it.
    struct Counting<R> {
        inner: R,
        read: usize,
    }

    impl<R: std::io::Read> std::io::Read for Counting<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.read += n;
            Ok(n)
        }
    }

    impl<R: std::io::Seek> std::io::Seek for Counting<R> {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    #[test]
    fn a_large_document_is_not_read_whole() {
        // a Word file with a 20 MB picture inside: only its start and table of contents are read
        let big = vec![7u8; 20 << 20];
        let docx = zip_of(&[
            ("[Content_Types].xml", b""),
            ("word/media/image1.png", &big),
            ("word/document.xml", b""),
        ]);
        let mut r = Counting {
            inner: std::io::Cursor::new(&docx),
            read: 0,
        };
        assert_eq!(viewable_name("a.docx", &mut r).unwrap(), "a.docx");
        assert!(r.read < 1 << 20, "read {} bytes", r.read);
        // a PDF (it might be a card) and other documents: just the start
        let mut pdf = b"%PDF-1.7\n".to_vec();
        pdf.extend(&big);
        let mut r = Counting {
            inner: std::io::Cursor::new(&pdf),
            read: 0,
        };
        assert_eq!(viewable_name("a.pdf", &mut r).unwrap(), "a.pdf");
        assert!(r.read <= 8192, "read {} bytes", r.read);
    }

    #[test]
    fn only_documents_are_opened() {
        for ok in [
            "a.pdf", "a.PDF", "b.docx", "c.xlsx", "d.txt", "e.jpg", "f.zip", "g.xml",
        ] {
            assert!(check_viewable(Path::new(ok)).is_ok(), "{ok}");
        }
        for bad in [
            "a.exe", "a.lnk", "a.hta", "a.csv", "a.html", "a.docm", "a.pdf.", "noext",
        ] {
            assert!(check_viewable(Path::new(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn viewing_copies_are_private_and_replaced() {
        let dir = std::env::temp_dir().join(format!("kzsigner-view-test-{}", std::process::id()));
        let a = write_for_viewing(&dir, "a.txt", &b"one"[..]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = write_for_viewing(&dir, "b.txt", &b"two"[..]).unwrap();
        assert!(!a.exists() && std::fs::read(&b).unwrap() == b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
