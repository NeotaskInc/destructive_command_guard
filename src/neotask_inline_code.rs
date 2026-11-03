//! Neotask fork rule (dev-igbgn): interpreter code whose text spells a
//! truncating write to a system, home or variable path.
//!
//! Upstream reads inline interpreter code in its own language, which is what
//! keeps `node -e "x.match(/<p>/)"` from reading as a redirect. It cannot see
//! a sink the code builds at run time, though: `__import__('os').system(...)`,
//! `globalThis['req'+'uire']`, `Kernel.send(:sys + 'tem', ...)`, Perl's
//! `&$f(...)`, PHP's `$f(...)` and Lua's `os['exe'..'cute']` all reach a shell
//! with no recognizable sink, so `echo x > /etc/passwd` inside them is
//! allowed. Run-time names cannot be enumerated, so the rule does not try:
//! the fork's v0.6.7 base denied every one of them by reading the redirect in
//! the raw text, and this rule keeps that deny for code handed to an
//! interpreter. It reads only the command's quoted text and heredoc bodies, so
//! a real redirect outside the code stays upstream's decision, and it only
//! turns an allow into a deny.

use crate::evaluator::EvaluationResult;
use crate::packs::Severity;
use crate::packs::regex_engine::LazyCompiledRegex;

pub(crate) const PACK_ID: &str = "core.filesystem";
pub(crate) const PATTERN_NAME: &str = "neotask-inline-code-redirect";

/// An interpreter that runs code it was handed inline or on stdin.
static INTERPRETER: LazyCompiledRegex = LazyCompiledRegex::new(
    r"(?:^|[\s;&|(`$])(?:\S*/)?(?:python[0-9.]*|pypy[0-9.]*|node|nodejs|deno|bun|ruby[0-9.]*|jruby|perl[0-9.]*|php[0-9.]*|lua[0-9.]*|luajit|g?awk|mawk|nawk)(?=\s|$)",
);

/// A truncating write to a system or home path, or to a path held in a named
/// variable (`$1`, an awk field, is not one).
static PROTECTED_WRITE: LazyCompiledRegex = LazyCompiledRegex::new(
    r#"(?<![<>=-])(?:&>|>&|[0-9]*>\|?)\s*['"\\]?(?!/dev/(?:null|zero|full|tty|stdout|stderr)\b)(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|\b)|~|\$\{?[A-Za-z_])"#,
);

/// Whether `command` hands an interpreter code whose text writes a protected or
/// variable path.
#[must_use]
pub(crate) fn matches(command: &str) -> bool {
    INTERPRETER.is_match(command) && PROTECTED_WRITE.is_match(&code_text(command))
}

/// Separates quoted words in [`code_text`]; not whitespace, so a write cannot
/// be assembled from a `>` in one word and a path in the next.
const WORD_BREAK: char = '\u{1f}';

/// Where inline code lives: the quoted words of the command's shell lines, and
/// the bodies of heredocs fed to Ruby. Unquoted text (including a real
/// redirect after the code) and other heredoc bodies are left out: upstream
/// reads heredoc programs for every other interpreter this rule names.
fn code_text(command: &str) -> String {
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum Quote {
        None,
        Single,
        Double,
        AnsiC,
    }
    let (shell, ruby_bodies) = split_heredocs(command);
    let mut text = String::new();
    let mut quote = Quote::None;
    let mut chars = shell.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Quote::None, '\\') => {
                chars.next();
            }
            (Quote::None, '\'') => quote = Quote::Single,
            (Quote::None, '"') => quote = Quote::Double,
            (Quote::None, '$') if chars.peek() == Some(&'\'') => {
                chars.next();
                quote = Quote::AnsiC;
            }
            (Quote::None, _) => {}
            (Quote::Single, '\'') | (Quote::Double, '"') | (Quote::AnsiC, '\'') => {
                quote = Quote::None;
                text.push(WORD_BREAK);
            }
            (Quote::Double | Quote::AnsiC, '\\') => {
                if let Some(next) = chars.next() {
                    text.push(next);
                }
            }
            _ => text.push(c),
        }
    }
    text.push(WORD_BREAK);
    text.push_str(&ruby_bodies);
    text
}

/// Splits a command into its shell lines and the bodies of heredocs whose
/// opening line runs Ruby (delimiter lines go with neither).
fn split_heredocs(command: &str) -> (String, String) {
    static RUBY: LazyCompiledRegex =
        LazyCompiledRegex::new(r"(?:^|[\s;&|(`$])(?:\S*/)?(?:ruby[0-9.]*|jruby)(?=\s|$)");
    let mut shell = String::new();
    let mut ruby_bodies = String::new();
    let mut pending: Vec<(String, bool)> = Vec::new();
    for line in command.split('\n') {
        if let Some((delimiter, ruby)) = pending.first() {
            if line.trim_start_matches('\t') == delimiter {
                pending.remove(0);
            } else if *ruby {
                ruby_bodies.push_str(line);
                ruby_bodies.push('\n');
            }
            continue;
        }
        shell.push_str(line);
        shell.push('\n');
        let ruby = RUBY.is_match(line);
        pending.extend(heredoc_delimiters(line).into_iter().map(|d| (d, ruby)));
    }
    (shell, ruby_bodies)
}

/// The delimiters of the heredocs a line opens (`<<EOF`, `<<-'EOF'`, `<< "EOF"`),
/// skipping here-strings (`<<<`).
fn heredoc_delimiters(line: &str) -> Vec<String> {
    let mut delimiters = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find("<<") {
        rest = &rest[at + 2..];
        if let Some(after) = rest.strip_prefix('<') {
            rest = after.trim_start_matches('<');
            continue;
        }
        let word = rest.strip_prefix('-').unwrap_or(rest).trim_start();
        let (delimiter, remainder) = match word.chars().next() {
            Some(open @ ('\'' | '"')) => {
                let body = &word[1..];
                body.find(open)
                    .map_or((body, ""), |end| (&body[..end], &body[end + 1..]))
            }
            _ => {
                let word = word.strip_prefix('\\').unwrap_or(word);
                let end = word
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(word.len());
                (&word[..end], &word[end..])
            }
        };
        if !delimiter.is_empty() {
            delimiters.push(delimiter.to_owned());
        }
        rest = remainder;
    }
    delimiters
}

/// The deny this rule returns.
#[must_use]
pub(crate) fn denial() -> EvaluationResult {
    EvaluationResult::denied_by_pack_pattern(
        PACK_ID,
        PATTERN_NAME,
        "interpreter code writes a system, home or variable path; dcg cannot prove which command the code runs, \
         so the write is treated as the shell redirect it spells.",
        Some(
            "Code can build its sink at run time (`Kernel.send(:sys + 'tem', ...)`, `globalThis['req'+'uire']`, \
             `$f = 'sys'.'tem'; $f(...)`), so a write to a protected or variable path inside inline code is \
             denied whatever calls it. Write to a path under the working directory instead.",
        ),
        Severity::Critical,
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::matches;

    /// The shapes v0.16 allows and the fork's v0.6.7 base denied (dev-igbgn,
    /// FuchsiaHare's C1): each builds its sink at run time.
    #[test]
    fn refuses_interpreter_code_that_writes_a_protected_path() {
        for command in [
            "python3 -c \"__import__('os').system('echo x > /etc/passwd')\"",
            "node -e \"const m = require('child' + '_process'); m.execSync('echo x > /etc/passwd')\"",
            "node -e 'new Function(\"return req\"+\"uire\")()(\"child_\"+\"process\").execSync(\"echo x > $T\")'",
            "ruby -e \"Kernel.send(:sys + 'tem', 'echo x > /etc/passwd')\"",
            "ruby -e \"Kernel.send(('sys'+'tem').to_sym, 'echo x > /etc/passwd')\"",
            "perl -e \"my \\$f = 'sys'.'tem'; &\\$f('echo x > /etc/passwd')\"",
            "perl -e \"eval 'sys'.'tem(q{echo x > /etc/passwd})'\"",
            "php -r \"\\$f = 'sys'.'tem'; \\$f('echo x > /etc/passwd');\"",
            "lua -e \"os['exe'..'cute']('echo x > /etc/passwd')\"",
            "python3 -c \"__builtins__.__dict__['__imp'+'ort__']('os').system('echo x > /etc/passwd')\"",
            "node -e \"globalThis['req'+'uire']('child_process').execSync('echo x > /etc/passwd')\"",
            "ruby -e \"Kernel.send(:sys + 'tem', 'echo x > $T')\"",
            "php -r '$f = \"sys\".\"tem\"; $f(\"echo x > $T\");'",
            "awk '{print > \"/etc/passwd\"}' f",
            "ruby - <<'EOF'\nKernel.send(:sys + 'tem', 'echo x > ~/.bashrc')\nEOF",
        ] {
            assert!(matches(command), "{command}");
        }
    }

    #[test]
    fn leaves_literal_data_and_real_redirects_to_upstream() {
        for command in [
            "node -e \"const ok = html.includes('</p>') && /<p>/.test(html)\"",
            "bash -lc 'node -e \"console.log(html.match(/<table>/))\"'",
            "python3 -c \"print('a>b')\"",
            "python3 -c 'print(\"<td>/</td>\")'",
            "python3 gen.py > ~/out.json",
            "python3 -c 'print(1)' > \"$LOG\"",
            "ruby -e 'puts [1, 2].select { |v| v > 1 }'",
            "awk '{ if ($1 > $2) print }' data.txt",
            "lua -e 'print(2 > 1)'",
            "python3 -c \"getattr(x, 'y')\" > /dev/null",
            "node -e \"require(name)\" > out.txt",
            "grep -E 'a > /etc' notes.txt",
            "cat > check_html.py <<'EOF'\nprint(re.findall(r'<(\\w+)[^>]*>/', s))\nEOF",
            // Heredoc programs for other interpreters are upstream's to read.
            "python3 - <<'PY'\nold = ''\nnew = ('echo $(date)\\n' '(task >\"$W/out.log\")\\n' + old)\nPY",
            "perl <<'PERL'\nprint <<'DATA';\nopen(FH, '>', '/etc/shadow');\nDATA\nPERL",
            // A `>` and a path in separate quoted words are not one write.
            "python3 -c 'import sys; print(sys.argv)' '>' '/etc/hosts'",
        ] {
            assert!(!matches(command), "{command}");
        }
    }
}
