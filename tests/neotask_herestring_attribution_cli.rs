//! Neotask fork (dev-6fcypx): a rule id is the key an allowlist entry names, so
//! a SQL payload on a database client's here-string must be named by that
//! client's own pack, as on its `-e`/`-c` flag and heredoc. Through the binary
//! the heredoc evaluation decoded a keyword index built for another pack order,
//! and named mysql's payload with postgresql's rule and psql's and sqlite3's with
//! mysql's (still denied); the order guard (dev-h3yib1) closes it.

use std::process::Command;

fn rule_id(command: &str, dialect: &str) -> (i32, String) {
    let home = tempfile::tempdir().expect("temp home");
    let output = Command::new(env!("CARGO_BIN_EXE_dcg"))
        .args([
            "--robot",
            "--no-policy-files",
            "test",
            "--with-packs",
            "database.mysql,database.postgresql,database.sqlite",
            "--dialect",
            dialect,
            "--",
            command,
        ])
        .current_dir(home.path())
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .env("DCG_NO_UPDATE_CHECK", "1")
        .output()
        .expect("run dcg");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("robot JSON");
    (
        output.status.code().unwrap_or(-1),
        json["rule_id"].as_str().unwrap_or_default().to_string(),
    )
}

#[test]
fn a_here_string_payload_is_named_by_its_own_client_pack() {
    for (command, pack) in [
        ("mysql <<< \"DROP DATABASE prod\"", "database.mysql:"),
        ("psql <<< \"DROP DATABASE prod\"", "database.postgresql:"),
        (
            "sqlite3 app.db <<< \"DROP TABLE users\"",
            "database.sqlite:",
        ),
    ] {
        for dialect in ["posix", "unknown"] {
            let (code, rule) = rule_id(command, dialect);
            assert_eq!(code, 1, "{command:?} must be denied under {dialect}");
            assert!(
                rule.starts_with(pack),
                "{command:?} under {dialect} was named {rule:?}, not by {pack}"
            );
        }
    }
}
