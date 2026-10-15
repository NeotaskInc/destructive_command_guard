//! `--no-policy-files` / `DCG_NO_POLICY_FILES=1`: a policy file that the guarded
//! agent can write (project or user config, allowlists, allow-once entries)
//! never turns a deny into an allow, while the caller's own flags still apply.
//!
//! Every case first proves that its planted file does allow the command
//! without the switch, so a deny with the switch shows the file was ignored.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn dcg_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop();
    path.pop();
    path.push(format!("dcg{}", std::env::consts::EXE_SUFFIX));
    path
}

struct Fixture {
    _root: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    system_allowlist: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temp root");
        let base = root.path().canonicalize().expect("canonical temp root");
        let repo = base.join("repo");
        let home = base.join("home");
        std::fs::create_dir_all(repo.join(".git")).expect("create .git marker");
        std::fs::create_dir_all(home.join("xdg")).expect("create xdg dir");
        Self {
            _root: root,
            repo,
            system_allowlist: base.join("system-allowlist.toml"),
            home,
        }
    }

    fn plant(&self, path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        std::fs::write(path, contents).expect("write planted file");
    }

    fn user_dcg_dir(&self) -> PathBuf {
        self.home.join(".config").join("dcg")
    }

    fn run(&self, switch: Switch, command: &str) -> Output {
        let mut cmd = Command::new(dcg_binary());
        cmd.arg("--robot");
        if switch == Switch::Flag {
            cmd.arg("--no-policy-files");
        }
        cmd.args(["test", "--with-packs", "database.postgresql", command])
            .current_dir(&self.repo)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("xdg"))
            .env("DCG_ALLOWLIST_SYSTEM_PATH", &self.system_allowlist)
            .env("DCG_NO_UPDATE_CHECK", "1")
            .env_remove("DCG_CONFIG")
            .env_remove("DCG_ALLOW_ONCE_PATH")
            .env_remove("DCG_NO_POLICY_FILES");
        if switch == Switch::Env {
            cmd.env("DCG_NO_POLICY_FILES", "1");
        }
        cmd.output().expect("run dcg")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Switch {
    Off,
    Flag,
    Env,
}

fn decision(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e})\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_planted_policy_is_ignored(fixture: &Fixture, command: &str, rule_id: &str) {
    let baseline = fixture.run(Switch::Off, command);
    assert_eq!(
        (
            baseline.status.code(),
            decision(&baseline)["decision"].clone()
        ),
        (Some(0), serde_json::json!("allow")),
        "the planted file must allow `{command}` without the switch, or this case proves nothing"
    );

    for switch in [Switch::Flag, Switch::Env] {
        let output = fixture.run(switch, command);
        let json = decision(&output);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{switch:?}: `{command}` must stay denied\nstdout: {json}"
        );
        assert_eq!(json["decision"], "deny", "{switch:?}: {json}");
        assert_eq!(json["rule_id"], rule_id, "{switch:?}: {json}");
    }
}

#[test]
fn project_allowlist_is_ignored() {
    let fixture = Fixture::new();
    fixture.plant(
        &fixture.repo.join(".dcg").join("allowlist.toml"),
        "[[allow]]\nrule = \"core.filesystem:redirect-truncate-root-home\"\nreason = \"planted\"\n",
    );
    assert_planted_policy_is_ignored(
        &fixture,
        "echo x > /etc/passwd",
        "core.filesystem:redirect-truncate-root-home",
    );
}

#[test]
fn project_config_cannot_disable_a_default_pack() {
    let fixture = Fixture::new();
    fixture.plant(
        &fixture.repo.join(".dcg.toml"),
        "[packs]\ndisabled = [\"system.disk\"]\n",
    );
    assert_planted_policy_is_ignored(&fixture, "mkfs.ext4 /dev/sda", "system.disk:mkfs");
}

#[test]
fn project_config_cannot_disable_packs_the_caller_enabled() {
    let fixture = Fixture::new();
    fixture.plant(
        &fixture.repo.join(".dcg.toml"),
        "[packs]\ndisabled = [\"database\"]\n",
    );
    assert_planted_policy_is_ignored(&fixture, "dropdb prod", "database.postgresql:dropdb-cli");
}

#[test]
fn project_config_allow_override_is_ignored() {
    let fixture = Fixture::new();
    fixture.plant(
        &fixture.repo.join(".dcg.toml"),
        "[overrides]\nallow = [\"rm -rf /etc\"]\n",
    );
    assert_planted_policy_is_ignored(&fixture, "rm -rf /etc", "core.filesystem:rm-rf-root-home");
}

#[test]
fn system_allowlist_is_ignored() {
    let fixture = Fixture::new();
    fixture.plant(
        &fixture.system_allowlist,
        "[[allow]]\nrule = \"core.filesystem:redirect-truncate-root-home\"\nreason = \"planted\"\n",
    );
    assert_planted_policy_is_ignored(
        &fixture,
        "echo x > /etc/passwd",
        "core.filesystem:redirect-truncate-root-home",
    );
}

// The user layers resolve through the home directory, which only follows
// $HOME on Unix (Windows uses the known-folder API).
#[cfg(unix)]
#[test]
fn user_allowlist_is_ignored() {
    let fixture = Fixture::new();
    fixture.plant(
        &fixture.user_dcg_dir().join("allowlist.toml"),
        "[[allow]]\nrule = \"core.filesystem:redirect-truncate-root-home\"\nreason = \"planted\"\n",
    );
    assert_planted_policy_is_ignored(
        &fixture,
        "echo x > /etc/hosts",
        "core.filesystem:redirect-truncate-root-home",
    );
}

#[cfg(unix)]
#[test]
fn user_config_allow_override_is_ignored() {
    let fixture = Fixture::new();
    fixture.plant(
        &fixture.user_dcg_dir().join("config.toml"),
        "[overrides]\nallow = [\"rm -rf /etc\"]\n",
    );
    assert_planted_policy_is_ignored(&fixture, "rm -rf /etc", "core.filesystem:rm-rf-root-home");
}

#[cfg(unix)]
#[test]
fn allow_once_entry_is_ignored() {
    let fixture = Fixture::new();
    let entry = serde_json::json!({
        "schema_version": 1,
        "source_short_code": "000000",
        "source_full_hash": "planted",
        "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "scope_kind": "project",
        "scope_path": "/",
        "command_raw": "rm -rf /",
        "command_redacted": "rm -rf /",
        "reason": "planted",
        "single_use": false,
        "consumed_at": null,
        "force_allow_config": true,
    });
    fixture.plant(
        &fixture.user_dcg_dir().join("allow_once.jsonl"),
        &format!("{entry}\n"),
    );
    assert_planted_policy_is_ignored(&fixture, "rm -rf /", "core.filesystem:rm-rf-root-home");
}

#[test]
fn switch_keeps_ordinary_verdicts() {
    let fixture = Fixture::new();
    for switch in [Switch::Off, Switch::Flag, Switch::Env] {
        let allowed = fixture.run(switch, "ls -la");
        assert_eq!(allowed.status.code(), Some(0), "{switch:?}");
        let denied = fixture.run(switch, "git reset --hard");
        assert_eq!(denied.status.code(), Some(1), "{switch:?}");
        assert_eq!(
            decision(&denied)["rule_id"],
            "core.git:reset-hard",
            "{switch:?}"
        );
    }
}
