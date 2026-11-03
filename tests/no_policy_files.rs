//! `--no-policy-files` / `DCG_NO_POLICY_FILES=1`: a policy file that the guarded
//! agent can write (project or user config, allowlists, allow-once entries)
//! never turns a deny into an allow, while the caller's own flags still apply.
//!
//! Every case first proves that its planted file does allow the command
//! without the switch, so a deny with the switch shows the file was ignored.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

struct Fixture {
    _root: tempfile::TempDir,
    repo: PathBuf,
    home: PathBuf,
    system_allowlist: PathBuf,
    /// `DCG_CONFIG`: how a caller makes a project's own policy trusted.
    selected_config: std::cell::RefCell<Option<PathBuf>>,
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
            selected_config: std::cell::RefCell::new(None),
        }
    }

    /// Select a config file through `DCG_CONFIG`. Selecting the repository's
    /// `.dcg.toml` is what makes its project policy trusted.
    fn select_config(&self, path: &Path) {
        *self.selected_config.borrow_mut() = Some(path.to_path_buf());
    }

    fn plant(&self, path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        std::fs::write(path, contents).expect("write planted file");
    }

    #[cfg(unix)]
    /// The user layers live under XDG_CONFIG_HOME, which `run` sets.
    fn user_dcg_dir(&self) -> PathBuf {
        self.home.join("xdg").join("dcg")
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(dcg_binary());
        cmd.current_dir(&self.repo)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("xdg"))
            .env("DCG_ALLOWLIST_SYSTEM_PATH", &self.system_allowlist)
            .env("DCG_NO_UPDATE_CHECK", "1")
            .env_remove("DCG_CONFIG")
            .env_remove("DCG_ALLOW_ONCE_PATH")
            .env_remove("DCG_NO_POLICY_FILES");
        if let Some(path) = self.selected_config.borrow().as_ref() {
            cmd.env("DCG_CONFIG", path);
        }
        cmd
    }

    fn run(&self, switch: Switch, command: &str) -> Output {
        let mut cmd = self.command();
        cmd.arg("--robot");
        if switch == Switch::Flag {
            cmd.arg("--no-policy-files");
        }
        if switch == Switch::Env {
            cmd.env("DCG_NO_POLICY_FILES", "1");
        }
        cmd.args(["test", "--with-packs", "database.postgresql", command]);
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
    fixture.plant(&fixture.repo.join(".dcg.toml"), "");
    fixture.select_config(&fixture.repo.join(".dcg.toml"));
    assert_planted_policy_is_ignored(
        &fixture,
        "echo x > /etc/hosts",
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
    fixture.select_config(&fixture.repo.join(".dcg.toml"));
    assert_planted_policy_is_ignored(&fixture, "mkfs.ext4 /dev/sda", "system.disk:mkfs");
}

#[test]
fn project_config_cannot_disable_packs_the_caller_enabled() {
    let fixture = Fixture::new();
    fixture.plant(
        &fixture.repo.join(".dcg.toml"),
        "[packs]\ndisabled = [\"database\"]\n",
    );
    fixture.select_config(&fixture.repo.join(".dcg.toml"));
    // Since upstream 0.16 a trusted config can no longer disable a pack the
    // caller enables with --with-packs, so the caller's pack decides in every
    // switch state.
    for switch in [Switch::Off, Switch::Flag, Switch::Env] {
        let output = fixture.run(switch, "dropdb prod");
        let json = decision(&output);
        assert_eq!(output.status.code(), Some(1), "{switch:?}: {json}");
        assert_eq!(json["rule_id"], "database.postgresql:dropdb-cli", "{switch:?}: {json}");
    }
}

#[test]
fn project_config_allow_override_is_ignored() {
    let fixture = Fixture::new();
    fixture.plant(
        &fixture.repo.join(".dcg.toml"),
        "[overrides]\nallow = [\"rm -rf /etc\"]\n",
    );
    fixture.select_config(&fixture.repo.join(".dcg.toml"));
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
        "echo x > /etc/hosts",
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

/// An allow-once grant is only honored when it is real: the hook's denial
/// records a pending exception and `dcg allow-once <code>` redeems it. The
/// switched runs come first and must not consume the single-use grant, so the
/// final run without the switch proves the grant was live throughout.
#[cfg(unix)]
#[test]
fn allow_once_grant_is_ignored() {
    use std::io::Write as _;

    let fixture = Fixture::new();
    let command = "git reset --hard HEAD~1";
    let hook_input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": fixture.repo,
    });
    let mut hook = fixture
        .command()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn dcg hook");
    hook.stdin
        .take()
        .expect("hook stdin")
        .write_all(hook_input.to_string().as_bytes())
        .expect("write hook input");
    let denial = hook.wait_with_output().expect("dcg hook");
    let denial_text = String::from_utf8_lossy(&denial.stdout);
    let code: String = denial_text
        .split("allow-once ")
        .nth(1)
        .unwrap_or_else(|| panic!("the hook's denial names an allow-once code: {denial_text}"))
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    assert_eq!(code.len(), 6, "allow-once code in: {denial_text}");
    let redeemed = fixture
        .command()
        .args(["allow-once", &code, "--yes"])
        .output()
        .expect("dcg allow-once");
    assert!(
        redeemed.status.success(),
        "redeem the grant: {}",
        String::from_utf8_lossy(&redeemed.stderr)
    );

    for switch in [Switch::Flag, Switch::Env] {
        let output = fixture.run(switch, command);
        let json = decision(&output);
        assert_eq!(output.status.code(), Some(1), "{switch:?}: {json}");
        assert_eq!(json["rule_id"], "core.git:reset-hard", "{switch:?}: {json}");
    }
    let baseline = fixture.run(Switch::Off, command);
    assert_eq!(
        (baseline.status.code(), decision(&baseline)["decision"].clone()),
        (Some(0), serde_json::json!("allow")),
        "the grant must allow `{command}` without the switch, or this case proves nothing"
    );
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
