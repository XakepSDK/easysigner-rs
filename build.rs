//! Windows: the icon and version details shown by Explorer (assets/kzsigner.ico), and a
//! manifest asking for no console window when started from Explorer (Windows 11 24H2+).

/// https://learn.microsoft.com/windows/console/console-allocation-policy
const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <application>
    <windowsSettings>
      <consoleAllocationPolicy xmlns="http://schemas.microsoft.com/SMI/2024/WindowsSettings">detached</consoleAllocationPolicy>
    </windowsSettings>
  </application>
</assembly>
"#;

fn main() {
    println!("cargo:rerun-if-changed=assets/kzsigner.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut res = winresource::WindowsResource::new();
    res.set_manifest(MANIFEST);
    res.set_icon("assets/kzsigner.ico")
        .set("FileDescription", "kzsigner - NCA RK signatures")
        .set("ProductName", "kzsigner")
        .set("ProductVersion", &version)
        .set("FileVersion", &version)
        .set("OriginalFilename", "kzsigner.exe")
        .set("LegalCopyright", "kzsigner contributors");
    if let Err(e) = res.compile() {
        panic!("Windows resources: {e}");
    }
}
