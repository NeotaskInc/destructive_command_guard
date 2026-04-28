//! Escalation message formatting for the graduated response system.
//!
//! Renders distinct messages for Warning, SoftBlock, and HardBlock levels
//! with clear visual distinction, occurrence counts, and remediation steps.
//! Works in both TTY and non-TTY (plain text) environments.

use crate::evaluator::GraduatedResponse;
use std::fmt::Write;

/// Information needed to format an escalation message.
#[derive(Debug, Clone)]
pub struct EscalationContext<'a> {
    /// The command that triggered the response.
    pub command: &'a str,
    /// Pattern identifier (e.g., "core.git:reset-hard").
    pub pattern_id: Option<&'a str>,
    /// Severity label (e.g., "Critical", "High").
    pub severity_label: Option<&'a str>,
    /// The reason the command was flagged.
    pub reason: Option<&'a str>,
    /// Whether the bypass was applied (--force).
    pub was_bypassed: bool,
}

/// Format an escalation message for the given graduated response level.
///
/// Returns a plain-text message suitable for stderr output.
/// Each level has distinct formatting:
/// - **Warning**: informational, command is allowed
/// - **SoftBlock**: command denied, shows bypass instructions
/// - **HardBlock**: command denied, shows allowlist instructions
#[must_use]
pub fn format_escalation_message(
    response: &GraduatedResponse,
    ctx: &EscalationContext<'_>,
) -> String {
    match response {
        GraduatedResponse::Warning { occurrence } => format_warning(*occurrence, ctx),
        GraduatedResponse::SoftBlock { occurrence } => format_soft_block(*occurrence, ctx),
        GraduatedResponse::HardBlock { total_occurrences } => {
            format_hard_block(*total_occurrences, ctx)
        }
    }
}

fn format_warning(occurrence: u32, ctx: &EscalationContext<'_>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "WARNING: Potentially dangerous command detected");
    let _ = writeln!(out);
    let _ = writeln!(out, "  Command: {}", ctx.command);
    if let Some(pattern) = ctx.pattern_id {
        let _ = writeln!(out, "  Pattern: {pattern}");
    }
    if let Some(severity) = ctx.severity_label {
        let _ = writeln!(out, "  Severity: {severity}");
    }
    if let Some(reason) = ctx.reason {
        let _ = writeln!(out, "  Reason: {reason}");
    }
    let _ = writeln!(out);
    let ordinal = ordinal_suffix(occurrence);
    let _ = writeln!(
        out,
        "  This is your {occurrence}{ordinal} attempt this session. Command allowed."
    );
    let _ = writeln!(out, "  Future attempts may be blocked.");
    out
}

fn format_soft_block(occurrence: u32, ctx: &EscalationContext<'_>) -> String {
    let mut out = String::new();
    if ctx.was_bypassed {
        let _ = writeln!(
            out,
            "SOFT BLOCK BYPASSED (--force): Repeated dangerous command"
        );
    } else {
        let _ = writeln!(out, "SOFT BLOCK: Repeated dangerous command");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "  Command: {}", ctx.command);
    if let Some(pattern) = ctx.pattern_id {
        let _ = writeln!(out, "  Pattern: {pattern}");
    }
    if let Some(severity) = ctx.severity_label {
        let _ = writeln!(out, "  Severity: {severity}");
    }
    if let Some(reason) = ctx.reason {
        let _ = writeln!(out, "  Reason: {reason}");
    }
    let _ = writeln!(out, "  Occurrences: {occurrence} this session");
    let _ = writeln!(out);
    if ctx.was_bypassed {
        let _ = writeln!(out, "  Command allowed via --force bypass.");
    } else {
        let _ = writeln!(
            out,
            "  This command was warned previously and is now soft-blocked."
        );
        let _ = writeln!(out, "  To proceed: dcg test --force \"{}\"", ctx.command);
        let _ = writeln!(out, "  Or allowlist: dcg allow-once \"{}\"", ctx.command);
    }
    out
}

fn format_hard_block(total_occurrences: u32, ctx: &EscalationContext<'_>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "BLOCKED: Command blocked after repeated attempts");
    let _ = writeln!(out);
    let _ = writeln!(out, "  Command: {}", ctx.command);
    if let Some(pattern) = ctx.pattern_id {
        let _ = writeln!(out, "  Pattern: {pattern}");
    }
    if let Some(severity) = ctx.severity_label {
        let _ = writeln!(out, "  Severity: {severity}");
    }
    if let Some(reason) = ctx.reason {
        let _ = writeln!(out, "  Reason: {reason}");
    }
    let _ = writeln!(out, "  Occurrences: {total_occurrences} this session");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  This command has been blocked due to repeated attempts."
    );
    let _ = writeln!(out, "  Hard blocks cannot be bypassed with --force.");
    if let Some(pattern) = ctx.pattern_id {
        let _ = writeln!(
            out,
            "  To allowlist this rule: dcg allow \"{pattern}\" -r \"reason\""
        );
    }
    out
}

fn ordinal_suffix(n: u32) -> &'static str {
    match n % 100 {
        11..=13 => "th",
        _ => match n % 10 {
            1 => "st",
            2 => "nd",
            3 => "rd",
            _ => "th",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx(command: &str) -> EscalationContext<'_> {
        EscalationContext {
            command,
            pattern_id: Some("core.git:reset-hard"),
            severity_label: Some("High"),
            reason: Some("Destroys uncommitted work"),
            was_bypassed: false,
        }
    }

    #[test]
    fn warning_contains_command_and_pattern() {
        let msg = format_escalation_message(
            &GraduatedResponse::Warning { occurrence: 1 },
            &test_ctx("git reset --hard"),
        );
        assert!(msg.contains("WARNING:"));
        assert!(msg.contains("git reset --hard"));
        assert!(msg.contains("core.git:reset-hard"));
        assert!(msg.contains("High"));
        assert!(msg.contains("Destroys uncommitted work"));
        assert!(msg.contains("1st attempt"));
        assert!(msg.contains("Command allowed"));
    }

    #[test]
    fn warning_ordinals() {
        let ctx = test_ctx("cmd");
        let msg1 = format_warning(1, &ctx);
        assert!(msg1.contains("1st attempt"));
        let msg2 = format_warning(2, &ctx);
        assert!(msg2.contains("2nd attempt"));
        let msg3 = format_warning(3, &ctx);
        assert!(msg3.contains("3rd attempt"));
        let msg4 = format_warning(4, &ctx);
        assert!(msg4.contains("4th attempt"));
        let msg11 = format_warning(11, &ctx);
        assert!(msg11.contains("11th attempt"));
        let msg21 = format_warning(21, &ctx);
        assert!(msg21.contains("21st attempt"));
    }

    #[test]
    fn soft_block_shows_bypass_instructions() {
        let msg = format_escalation_message(
            &GraduatedResponse::SoftBlock { occurrence: 2 },
            &test_ctx("docker system prune"),
        );
        assert!(msg.contains("SOFT BLOCK:"));
        assert!(msg.contains("docker system prune"));
        assert!(msg.contains("Occurrences: 2"));
        assert!(msg.contains("dcg test --force"));
        assert!(msg.contains("dcg allow-once"));
        assert!(!msg.contains("BYPASSED"));
    }

    #[test]
    fn soft_block_bypassed_shows_force_message() {
        let mut ctx = test_ctx("docker system prune");
        ctx.was_bypassed = true;
        let msg = format_escalation_message(&GraduatedResponse::SoftBlock { occurrence: 2 }, &ctx);
        assert!(msg.contains("BYPASSED"));
        assert!(msg.contains("--force"));
        assert!(msg.contains("Command allowed via --force bypass"));
        assert!(!msg.contains("To proceed:"));
    }

    #[test]
    fn hard_block_shows_allowlist_instructions() {
        let msg = format_escalation_message(
            &GraduatedResponse::HardBlock {
                total_occurrences: 5,
            },
            &test_ctx("rm -rf /"),
        );
        assert!(msg.contains("BLOCKED:"));
        assert!(msg.contains("rm -rf /"));
        assert!(msg.contains("Occurrences: 5"));
        assert!(msg.contains("cannot be bypassed"));
        assert!(msg.contains("dcg allow"));
    }

    #[test]
    fn hard_block_no_force_instruction() {
        let msg = format_escalation_message(
            &GraduatedResponse::HardBlock {
                total_occurrences: 3,
            },
            &test_ctx("git reset --hard"),
        );
        assert!(!msg.contains("dcg test --force"));
        assert!(msg.contains("cannot be bypassed with --force"));
    }

    #[test]
    fn minimal_context_no_panic() {
        let ctx = EscalationContext {
            command: "rm -rf /",
            pattern_id: None,
            severity_label: None,
            reason: None,
            was_bypassed: false,
        };
        let msg = format_escalation_message(&GraduatedResponse::Warning { occurrence: 1 }, &ctx);
        assert!(msg.contains("rm -rf /"));
        assert!(msg.contains("WARNING:"));
        assert!(!msg.contains("Pattern:"));
        assert!(!msg.contains("Severity:"));
    }

    #[test]
    fn all_levels_produce_nonempty_output() {
        let ctx = test_ctx("test cmd");
        for response in [
            GraduatedResponse::Warning { occurrence: 1 },
            GraduatedResponse::SoftBlock { occurrence: 2 },
            GraduatedResponse::HardBlock {
                total_occurrences: 3,
            },
        ] {
            let msg = format_escalation_message(&response, &ctx);
            assert!(!msg.is_empty(), "empty output for {:?}", response);
            assert!(msg.contains("test cmd"));
        }
    }

    #[test]
    fn ordinal_suffix_edge_cases() {
        assert_eq!(ordinal_suffix(0), "th");
        assert_eq!(ordinal_suffix(1), "st");
        assert_eq!(ordinal_suffix(2), "nd");
        assert_eq!(ordinal_suffix(3), "rd");
        assert_eq!(ordinal_suffix(4), "th");
        assert_eq!(ordinal_suffix(11), "th");
        assert_eq!(ordinal_suffix(12), "th");
        assert_eq!(ordinal_suffix(13), "th");
        assert_eq!(ordinal_suffix(21), "st");
        assert_eq!(ordinal_suffix(22), "nd");
        assert_eq!(ordinal_suffix(23), "rd");
        assert_eq!(ordinal_suffix(100), "th");
        assert_eq!(ordinal_suffix(101), "st");
        assert_eq!(ordinal_suffix(111), "th");
        assert_eq!(ordinal_suffix(112), "th");
        assert_eq!(ordinal_suffix(113), "th");
    }
}
