//! dev-igbgn.2 / dev-igbgn.4 / dev-qgoxf1: the whole-command decisions the
//! no-regression gate checks. v0.6.7-neotask.3 denied each `deny` row; the
//! evaluator splits a compound command into segments, so a segment's own
//! temp exemption decides it.
use destructive_command_guard::config::Config;
use destructive_command_guard::evaluator::evaluate_command;
use destructive_command_guard::load_default_allowlists;
use destructive_command_guard::packs::REGISTRY;
use std::collections::HashSet;

fn allowed(cmd: &str) -> bool {
    let config = Config::default();
    let enabled: HashSet<String> = ["core.git", "core.filesystem"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let keywords = REGISTRY.collect_enabled_keywords(&enabled);
    let overrides = config.overrides.compile();
    let allowlists = load_default_allowlists();
    evaluate_command(cmd, &config, &keywords, &overrides, &allowlists).is_allowed()
}

#[test]
fn a_temp_root_delete_or_an_unbounded_perl_unlink_is_denied() {
    for cmd in [
        "echo done; find /tmp -delete",
        "true && find /tmp -delete",
        "find /tmp -delete",
        "find /var/tmp/ -delete",
        "perl -e \"unlink glob('*')\"",
        "perl -w -e \"unlink glob('*')\"",
        "perl -i.bak -e \"unlink glob('*')\"",
        "perl '-e' \"unlink glob('*')\"",
        "perl -e 'unlink $f'",
        "find /tmp/* -delete",
        "rm -rf /tmp/*",
        "rm -rf /tmp/.*",
        "echo done; rm -rf /tmp/*",
    ] {
        assert!(!allowed(cmd), "must deny: {cmd}");
    }
}

#[test]
fn temp_scratch_below_the_root_stays_allowed() {
    for cmd in [
        "find /tmp/foo -delete",
        "echo done; find /tmp/foo -delete",
        "find /tmp/.cache -name '*.log' -delete",
        "perl -e 'unlink \"/tmp/x/scratch\"'",
        "echo done; unlink /tmp/scratch",
        "rm -rf /tmp/build/*",
        "rm -rf /tmp/sigtest* 2>/dev/null",
        "perl -e 'use File::Temp qw(tempfile); my ($fh, $n) = tempfile(UNLINK => 1)'",
    ] {
        assert!(allowed(cmd), "must allow: {cmd}");
    }
}
