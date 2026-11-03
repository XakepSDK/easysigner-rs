//! Helpers shared by the command-line tests.

/// Signing and checking go online by default; the tests stay offline unless a test names a
/// server or needs one (--card, --level), or says `--network` (dropped here).
pub fn offline_unless_asked(args: &mut Vec<String>) {
    let Some(cmd) = args.first().cloned() else {
        return;
    };
    let keep = args.iter().any(|a| a == "--network");
    args.retain(|a| a != "--network");
    let given: Vec<String> = args.clone();
    let has = |p: &str| given.iter().any(|a| a.starts_with(p));
    if keep || has("--card") || has("--level") || has("--offline") || has("--help") {
        return;
    }
    if cmd == "sign" && !has("--tsa") && !has("--no-tsa") {
        args.push("--no-tsa".into());
    }
    if (cmd == "sign" || cmd == "verify") && !has("--ocsp") && !has("--no-ocsp") {
        args.push("--no-ocsp".into());
    }
}
