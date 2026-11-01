//! Windows: the icon and version details shown by Explorer (assets/kzsigner.ico).

fn main() {
    println!("cargo:rerun-if-changed=assets/kzsigner.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut res = winresource::WindowsResource::new();
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
