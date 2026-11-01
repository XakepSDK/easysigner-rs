//! Windows console launcher, shipped as `kzsigner.com` next to `kzsigner.exe`.
//!
//! kzsigner.exe is a GUI program (no console window flashes when it is double-clicked), so a
//! terminal would not wait for it. Typing `kzsigner ...` in cmd or PowerShell finds the .com
//! first; it runs kzsigner.exe with the same arguments and console, waits, and returns its exit
//! code.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::process::{Command, ExitCode};
    let exe = match std::env::current_exe() {
        Ok(p) => p.with_file_name("kzsigner.exe"),
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(1);
        }
    };
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut cmd = Command::new(&exe);
    cmd.args(&args);
    if args.is_empty() {
        // just the window: no need to keep the terminal busy
        return match cmd.spawn() {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: could not start {}: {e}", exe.display());
                ExitCode::from(1)
            }
        };
    }
    // Ctrl+C goes to kzsigner.exe too (same console); wait for it to finish instead of exiting
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(None, 1);
    }
    match cmd.status() {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1).clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("Error: could not start {}: {e}", exe.display());
            ExitCode::from(1)
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("kzsigner-console is only needed on Windows; run kzsigner instead.");
    std::process::exit(2);
}
