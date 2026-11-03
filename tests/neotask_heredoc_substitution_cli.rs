//! Neotask fork (dev-igbgn): an unquoted heredoc delimiter expands `$(...)`
//! before the program reads its body, so a destructive substitution in it runs.
//! Upstream's library-level rows for this shape (repro_277, repro_393 and the
//! cross-pack #277 control) fail on v0.16.0 and are excluded from the fork's CI
//! profile; this keeps the verdict enforced through the binary as the Gateway
//! calls it.

use std::process::Command;

fn verdict(command: &str) -> (i32, String) {
    let home = tempfile::tempdir().expect("temp home");
    let output = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .args(["--robot", "--no-policy-files", "test", "--", command])
        .current_dir(home.path())
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .env("DCG_NO_UPDATE_CHECK", "1")
        .output()
        .expect("run dcg");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    (output.status.code().unwrap_or(-1), stdout)
}

#[test]
fn an_expanding_heredoc_substitution_is_denied_and_a_quoted_one_is_data() {
    for command in [
        "git commit -F - <<EOF\n$(rm -rf /tmp/x)\nEOF",
        "git commit -F - <<EOF\n$(rm -rf ~/project)\nEOF",
        "git commit -F - <<EOF\n$(git reset --hard)\nEOF",
    ] {
        let (code, stdout) = verdict(command);
        assert_eq!(code, 1, "{command:?} must be denied: {stdout}");
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("robot JSON");
        assert_eq!(json["decision"], "deny", "{command:?}: {stdout}");
    }
    let quoted = "git commit -F - <<'EOF'\n$(rm -rf ~/project)\nEOF";
    let (code, stdout) = verdict(quoted);
    assert_eq!(
        code, 0,
        "{quoted:?} is a literal body and must be allowed: {stdout}"
    );
}
