//! Neotask fork rule (dev-igbgn): interpreter code that builds its module or
//! function name at run time and writes a protected or dynamic path.
//!
//! Upstream reads interpreter code in its own language, which is what keeps
//! `node -e "x.match(/<p>/)"` from reading as a redirect. It cannot follow a
//! name it never sees, though: `__import__('os').system(...)`,
//! `require('child' + '_process')` and `new Function("return req"+"uire")`
//! reach a shell with no recognizable sink, so `echo x > /etc/passwd` inside
//! them is allowed. The fork's v0.6.7 base denied these by reading every
//! redirect in the raw text. This rule keeps that block for exactly the
//! obfuscated case: inline interpreter code, a run-time-built import or
//! function, and a truncating write to a protected or dynamic target, all in
//! the raw command. It only turns an allow into a deny.

use crate::evaluator::EvaluationResult;
use crate::packs::Severity;
use crate::packs::regex_engine::LazyCompiledRegex;

pub(crate) const PACK_ID: &str = "core.filesystem";
pub(crate) const PATTERN_NAME: &str = "neotask-dynamic-exec-redirect";

/// An interpreter that runs code it was handed inline or on stdin.
static INTERPRETER: LazyCompiledRegex = LazyCompiledRegex::new(
    r"(?:^|[\s;&|(`$])(?:\S*/)?(?:python[0-9.]*|pypy[0-9.]*|node|nodejs|deno|bun)(?=\s|$)",
);

/// A module, function or source name the code assembles at run time.
static DYNAMIC: LazyCompiledRegex = LazyCompiledRegex::new(
    r#"__import__\s*\(|\bimportlib\b|\bgetattr\s*\(|\bnew\s+Function\b|(?<![.\w])Function\s*\(|\brequire\s*\(\s*(?:[^'"`\s)]|['"`][^'"`]*['"`]\s*\+)|(?<![.\w])eval\s*\(|(?<![.\w])exec\s*\("#,
);

/// A truncating write to a system or home path, or to a path held in a variable.
static PROTECTED_WRITE: LazyCompiledRegex = LazyCompiledRegex::new(
    r#"(?<![<>=-])(?:&>|>&|[0-9]*>\|?)\s*['"\\]?(?!/dev/(?:null|zero|full|tty|stdout|stderr)\b)(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|\b)|~|\$\{?[A-Za-z_])"#,
);

/// Whether `command` runs interpreter code that assembles a name at run time and
/// writes a protected or dynamic path.
#[must_use]
pub(crate) fn matches(command: &str) -> bool {
    INTERPRETER.is_match(command) && DYNAMIC.is_match(command) && PROTECTED_WRITE.is_match(command)
}

/// The deny this rule returns.
#[must_use]
pub(crate) fn denial() -> EvaluationResult {
    EvaluationResult::denied_by_pack_pattern(
        PACK_ID,
        PATTERN_NAME,
        "interpreter code assembles a module or function name at run time and writes a system, home or variable path; \
         dcg cannot see which command runs, so the write is treated as the shell redirect it spells.",
        Some(
            "The code builds an import, require or function from pieces (`__import__(...)`, \
             `require('child' + '_process')`, `new Function(...)`), so no sink is visible to analysis, \
             and it writes a protected or dynamic target. Name the module directly, or write to a path \
             under the working directory.",
        ),
        Severity::Critical,
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn refuses_obfuscated_execution_that_writes_a_protected_path() {
        for command in [
            "python3 -c \"__import__('os').system('echo x > /etc/passwd')\"",
            "node -e \"const m = require('child' + '_process'); m.execSync('echo x > /etc/passwd')\"",
            "node -e 'new Function(\"return req\"+\"uire\")()(\"child_\"+\"process\").execSync(\"echo x > $T\")'",
        ] {
            assert!(matches(command), "{command}");
        }
    }

    #[test]
    fn leaves_literal_data_and_plain_writes_to_the_other_rules() {
        for command in [
            "node -e \"const ok = html.includes('</p>') && /<p>/.test(html)\"",
            "python3 -c \"print('a>b')\"",
            "python3 -c \"__import__('json').dumps({'a': 1})\"",
            "python3 -c \"getattr(x, 'y')\" > /dev/null",
            "node -e \"require(name)\" > out.txt",
        ] {
            assert!(!matches(command), "{command}");
        }
    }
}
