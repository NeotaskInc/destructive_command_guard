//! Neotask fork rule (dev-igbgn): inline code whose quoted text spells a
//! write (a truncating or appending redirect, `tee` or `dd of=`) to a system,
//! home or variable path.
//!
//! Upstream reads inline interpreter code in its own language, which is what
//! keeps `node -e "x.match(/<p>/)"` from reading as a redirect. It cannot see
//! a sink the code builds at run time, though: `__import__('os').system(...)`,
//! `globalThis['req'+'uire']`, `Kernel.send(:sys + 'tem', ...)`, Perl's
//! `&$f(...)`, PHP's `$f(...)`, Lua's `os['exe'..'cute']`, R's
//! `do.call(paste0('sys','tem'), ...)` and Groovy's `[...].execute()` all
//! reach a shell with no recognizable sink, so `echo x > /etc/passwd` inside
//! them is allowed, including when the interpreter is named by a variable.
//! Neither run-time names nor interpreters can be enumerated, so the rule
//! names neither. It judges each segment of a command by its shape: a
//! program given code through a code flag (`-c`, `-e`, `-r`, `--eval`, ...)
//! or an awk program, whose quoted text writes a protected or variable path,
//! is denied, as the fork's v0.6.7 base denied it by reading the raw text.
//!
//! Upstream keeps the decision for what it parses itself: shell scripts
//! (`sh -c`, `ssh`, `su`), whose nested commands the evaluator hands back to
//! this rule one depth down; the `-c`/`-e` text of SQL clients and search
//! tools, which is not shell; quoted data handed to any other program; and
//! heredoc programs, except Ruby's (upstream allows an obfuscated Ruby sink in
//! a heredoc and denies the others). The rule only turns an allow into a deny.

use crate::evaluator::EvaluationResult;
use crate::packs::Severity;
use crate::packs::regex_engine::LazyCompiledRegex;

pub(crate) const PACK_ID: &str = "core.filesystem";
pub(crate) const PATTERN_NAME: &str = "neotask-quoted-redirect";

/// A system or home path, or a path held in a named variable (`$1`, an awk
/// field, is not one), after an optional opening quote or escape.
macro_rules! protected_target {
    () => {
        r#"['"\\]?(?!/dev/(?:null|zero|full|tty|stdout|stderr)\b)(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|\b)|~|\$\{?[A-Za-z_])"#
    };
}

/// A write to a protected target: a truncating or appending redirect, or a
/// sink that writes the path it is given, `tee` (with any flags) and `dd`'s
/// `of=` (dev-65yunv: `echo x >> /etc/passwd` and `tee /etc/passwd` inside
/// code were allowed).
static PROTECTED_WRITE: LazyCompiledRegex = LazyCompiledRegex::new(concat!(
    r#"(?:(?<![<>=-])(?:&>>?|>&|[0-9]*>>?\|?)\s*|(?:^|[\s;&|(`'"])tee(?:\s+-{1,2}[A-Za-z][A-Za-z-]*)*\s+|\bof="#,
    r")",
    protected_target!(),
));

/// A line that runs Ruby, whose heredoc bodies the rule reads.
static RUBY: LazyCompiledRegex =
    LazyCompiledRegex::new(r"(?:^|[\s;&|(`$])(?:\S*/)?(?:ruby[0-9.]*|jruby)(?=\s|$)");

/// Programs whose script upstream parses itself (nested commands come back to
/// this rule one depth down), and programs whose `-c`/`-e` text is not shell.
const UPSTREAM_OWNED: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "ash",
    "fish",
    "busybox",
    "pwsh",
    "powershell",
    "ssh",
    "su",
    "parallel",
    "psql",
    "mysql",
    "mariadb",
    "sqlite3",
    "duckdb",
    "redis-cli",
    "cqlsh",
    "clickhouse-client",
    "mongosh",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "ack",
    "git",
    "gh",
];

/// Words that run the next word as the command.
const WRAPPERS: &[&str] = &[
    "env", "timeout", "nice", "nohup", "command", "exec", "time", "stdbuf", "xargs", "sudo", "doas",
];

/// Long flags that hand a program its code.
const LONG_CODE_FLAGS: &[&str] = &[
    "--eval",
    "--exec",
    "--execute",
    "--command",
    "--run",
    "--script",
];

/// Awk-family programs, which take their program as the first quoted word.
const AWKS: &[&str] = &["awk", "gawk", "mawk", "nawk"];

/// Ends each quoted piece of a word's quoted text; not whitespace, so a write
/// cannot be assembled across pieces.
const WORD_BREAK: char = '\u{1f}';

/// Programs that read stdin as data, never as code.
const TEXT_FILTERS: &[&str] = &[
    "cat",
    "tac",
    "wc",
    "sort",
    "uniq",
    "head",
    "tail",
    "tr",
    "cut",
    "less",
    "more",
    "tee",
    "base64",
    "gzip",
    "xxd",
    "od",
    "sha256sum",
    "sha1sum",
    "md5sum",
    "nl",
    "fold",
    "column",
];

/// One shell word: its text with quotes removed, its quoted parts alone, the
/// unquoted text before its first quote, and whether any of it was quoted.
#[derive(Default)]
struct Word {
    text: String,
    quoted: String,
    prefix: String,
    was_quoted: bool,
}

/// A segment's words, and whether a `|` feeds it the previous segment's output.
struct Segment {
    words: Vec<Word>,
    piped: bool,
}

/// Whether some segment of `command` gives a program inline code whose quoted
/// text writes a protected or variable path (through a code flag, as an awk
/// program, as a here-string, or piped into a program that reads its code from
/// stdin), or a Ruby heredoc does.
#[must_use]
pub(crate) fn matches(command: &str) -> bool {
    let (shell, ruby_bodies) = split_heredocs(command);
    let mut piped_write = false;
    for segment in segments(&shell) {
        if !segment.piped {
            piped_write = false;
        }
        let command = command_of(&segment.words);
        if let Some((name, rest)) = &command {
            if code_words(name, rest)
                .iter()
                .any(|word| writes_protected(word))
            {
                return true;
            }
            if segment.piped && piped_write && reads_code_from_stdin(name, rest) {
                return true;
            }
        }
        piped_write |= segment.words.iter().any(writes_protected);
    }
    PROTECTED_WRITE.is_match(&ruby_bodies)
}

fn writes_protected(word: &Word) -> bool {
    word.was_quoted && PROTECTED_WRITE.is_match(&word.quoted)
}

/// The command word's basename and the words after it, past leading
/// assignments and wrappers; `None` for a shell or another upstream-owned
/// program. A later word naming such a program (`parallel sh -c`,
/// `find -exec bash -c`) owns everything from there on.
fn command_of(segment: &[Word]) -> Option<(&str, Vec<&Word>)> {
    let mut words = segment.iter().peekable();
    // Leading assignments and wrappers (with their options) precede the command word.
    while let Some(word) = words.peek() {
        let name = basename(&word.text);
        if is_assignment(word) || word.text.starts_with('-') && !word.was_quoted {
            words.next();
        } else if WRAPPERS.contains(&name) {
            words.next();
            if name == "timeout" {
                words.next_if(|w| !w.text.starts_with('-'));
            }
        } else {
            break;
        }
    }
    let program = words.next()?;
    let name = basename(&program.text);
    if UPSTREAM_OWNED.contains(&name) {
        return None;
    }
    let rest = words
        .take_while(|word| word.was_quoted || !UPSTREAM_OWNED.contains(&basename(&word.text)))
        .collect();
    Some((name, rest))
}

/// The quoted words a command hands its program as code: the word after each
/// code flag or an `eval` subcommand, a value attached to a code flag
/// (`--eval="..."`, `-e'...'`), a here-string (`<<< "..."`), or an awk
/// program's quoted words.
fn code_words<'a>(name: &str, rest: &[&'a Word]) -> Vec<&'a Word> {
    if AWKS.contains(&name) {
        return rest
            .iter()
            .copied()
            .filter(|word| word.was_quoted)
            .collect();
    }
    let mut code: Vec<&Word> = rest
        .windows(2)
        .filter(|pair| (is_code_flag(pair[0]) || pair[0].text == "<<<") && pair[1].was_quoted)
        .map(|pair| pair[1])
        .collect();
    code.extend(
        rest.iter()
            .copied()
            .filter(|word| word.was_quoted && is_attached_code(word)),
    );
    if rest.first().is_some_and(|word| word.text == "eval") {
        code.extend(rest.get(1).copied().filter(|word| word.was_quoted));
    }
    code
}

/// A word whose unquoted prefix is a code flag or a here-string operator, with
/// the code attached: `--eval="..."`, `-e'...'`, `<<<"..."`.
fn is_attached_code(word: &Word) -> bool {
    let prefix = word.prefix.as_str();
    prefix == "<<<"
        || prefix
            .strip_suffix('=')
            .is_some_and(|flag| LONG_CODE_FLAGS.contains(&flag))
        || is_code_flag(&Word {
            text: prefix.to_owned(),
            ..Word::default()
        })
}

/// Whether a piped-into program reads its code from stdin: no operand, or `-`.
/// Text filters read stdin as data.
fn reads_code_from_stdin(name: &str, rest: &[&Word]) -> bool {
    !TEXT_FILTERS.contains(&name)
        && !AWKS.contains(&name)
        && rest
            .iter()
            .all(|word| word.text == "-" || (!word.was_quoted && word.text.starts_with('-')))
}

/// A flag that hands a program its code: `-c`, `-e`, `-r`, `-E`, a short
/// cluster ending in one (`-ne`, `-Ic`), or a long code flag.
fn is_code_flag(word: &Word) -> bool {
    if word.was_quoted {
        return false;
    }
    let text = word.text.as_str();
    if LONG_CODE_FLAGS.contains(&text) {
        return true;
    }
    text.strip_prefix('-').is_some_and(|cluster| {
        !cluster.starts_with('-')
            && (1..=4).contains(&cluster.len())
            && cluster.chars().all(|c| c.is_ascii_alphabetic())
            && cluster.ends_with(['c', 'e', 'r', 'E'])
    })
}

fn is_assignment(word: &Word) -> bool {
    word.text.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !name.starts_with(|c: char| c.is_ascii_digit())
    })
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// The command's shell lines split into segments at unquoted `;`, `&`, `|`,
/// newlines, parentheses and backticks, each a list of words and whether a
/// pipe (`|` or `|&`, not `||`) feeds it.
fn segments(shell: &str) -> Vec<Segment> {
    #[derive(PartialEq, Eq, Clone, Copy)]
    enum Quote {
        None,
        Single,
        Double,
        AnsiC,
    }
    let mut segments = Vec::new();
    let mut segment: Vec<Word> = Vec::new();
    let mut piped = false;
    let mut word = Word::default();
    let mut in_word = false;
    let mut quote = Quote::None;
    let mut chars = shell.chars().peekable();
    let end_word = |segment: &mut Vec<Word>, word: &mut Word, in_word: &mut bool| {
        if *in_word {
            segment.push(std::mem::take(word));
            *in_word = false;
        }
    };
    let open_quote = |word: &mut Word| {
        if !word.was_quoted {
            word.prefix.clone_from(&word.text);
            word.was_quoted = true;
        }
    };
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Quote::None, '\\') => {
                if let Some(next) = chars.next() {
                    word.text.push(next);
                    in_word = true;
                }
            }
            (Quote::None, '\'') => {
                quote = Quote::Single;
                open_quote(&mut word);
                in_word = true;
            }
            (Quote::None, '"') => {
                quote = Quote::Double;
                open_quote(&mut word);
                in_word = true;
            }
            (Quote::None, '$') if chars.peek() == Some(&'\'') => {
                chars.next();
                quote = Quote::AnsiC;
                open_quote(&mut word);
                in_word = true;
            }
            (Quote::None, ';' | '&' | '|' | '\n' | '(' | ')' | '`') => {
                end_word(&mut segment, &mut word, &mut in_word);
                if !segment.is_empty() {
                    segments.push(Segment {
                        words: std::mem::take(&mut segment),
                        piped,
                    });
                }
                piped = c == '|' && chars.next_if_eq(&'|').is_none();
                if piped {
                    chars.next_if_eq(&'&');
                }
            }
            (Quote::None, c) if c.is_whitespace() => {
                end_word(&mut segment, &mut word, &mut in_word);
            }
            (Quote::None, c) => {
                word.text.push(c);
                in_word = true;
            }
            (Quote::Single, '\'') | (Quote::Double, '"') | (Quote::AnsiC, '\'') => {
                quote = Quote::None;
                word.quoted.push(WORD_BREAK);
            }
            (Quote::Double | Quote::AnsiC, '\\') => {
                if let Some(next) = chars.next() {
                    word.text.push(next);
                    word.quoted.push(next);
                }
            }
            (_, c) => {
                word.text.push(c);
                word.quoted.push(c);
            }
        }
    }
    end_word(&mut segment, &mut word, &mut in_word);
    if !segment.is_empty() {
        segments.push(Segment {
            words: segment,
            piped,
        });
    }
    segments
}

/// Splits a command into its shell lines and the bodies of heredocs whose
/// opening line runs Ruby (delimiter lines go with neither).
fn split_heredocs(command: &str) -> (String, String) {
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
        "inline code writes a system, home or variable path; dcg cannot prove which command the code runs, \
         so the write is treated as the shell redirect it spells.",
        Some(
            "Code can build its sink at run time (`Kernel.send(:sys + 'tem', ...)`, `globalThis['req'+'uire']`, \
             `$f = 'sys'.'tem'; $f(...)`), so a write to a protected or variable path inside code handed to a \
             program through -c, -e, -r or --eval is denied whatever runs it. Write to a path under the working \
             directory instead.",
        ),
        Severity::Critical,
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::matches;

    /// Shapes v0.16 allows and the fork's v0.6.7 base denied (dev-igbgn,
    /// FuchsiaHare's C1 and its carry): each builds its sink at run time or
    /// names its interpreter in a way no list could.
    #[test]
    fn refuses_inline_code_that_writes_a_protected_path() {
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
            "P=python3; $P -c \"__import__('os').system('echo x > /etc/passwd')\"",
            "ruby -e \"Kernel.send(:sys + %q(tem), %q(echo x > /etc/passwd))\"",
            "Rscript -e \"do.call(paste0('sys','tem'), list('echo x > /etc/passwd'))\"",
            "elixir -e \"apply(String.to_atom(\\\"Elixir.Sys\\\" <> \\\"tem\\\"), :cmd, [\\\"sh\\\", [\\\"-c\\\", \\\"echo x > /etc/passwd\\\"]])\"",
            "groovy -e \"['sh','-c','echo x > /etc/passwd'].execute()\"",
            "env FOO=1 timeout 5 node --input-type=module -e 'globalThis[\"req\"+\"uire\"](\"child_process\").execSync(\"echo x > ~/.bashrc\")'",
            "true && sudo python3 -Ic \"__import__('os').system('echo x > /etc/passwd')\"",
            "deno eval \"Deno.run({cmd: ['sh', '-c', 'echo x > /etc/passwd']})\"",
            "ruby - <<'EOF'\nKernel.send(:sys + 'tem', 'echo x > ~/.bashrc')\nEOF",
            // Code on stdin, or attached to its flag (FuchsiaHare's second carry).
            "echo \"__import__('os').system('echo x > /etc/passwd')\" | python3",
            "echo \"__builtins__.__dict__['__imp'+'ort__']('os').system('echo x > /etc/passwd')\" | python3",
            "echo \"do.call(paste0('sys','tem'), list('echo x > /etc/passwd'))\" | Rscript -",
            "echo \"globalThis['req'+'uire']('child_process').execSync('echo x > /etc/passwd')\" | node",
            "node --eval=\"globalThis['req'+'uire']('child_process').execSync('echo x > /etc/passwd')\"",
            "perl -e'my $f = \"sys\".\"tem\"; &$f(\"echo x > /etc/passwd\")'",
            "python3 <<< \"__import__('os').system('echo x > ~/.bashrc')\"",
            "printf '%s' \"Kernel.send(:sys + 'tem', 'echo x > $T')\" | timeout 5 ruby",
            // An append, or a sink that writes the path it is given (dev-65yunv, FuchsiaHare on dev-igbgn).
            "python3 -c \"__import__('os').system('echo x>>/etc/passwd')\"",
            "python3 -c \"__import__('os').system('echo x &>> ~/.bashrc')\"",
            "python3 -c \"__import__('os').system('tee /etc/passwd < /dev/null')\"",
            "node -e \"globalThis['req'+'uire']('child_process').execSync('echo x | tee -a /etc/sudoers')\"",
            "ruby -e \"Kernel.send(:sys + 'tem', 'echo x | tee --append \\\"$HOME/.profile\\\"')\"",
            "perl -e \"my \\$f = 'sys'.'tem'; &\\$f('dd if=/dev/zero of=/etc/hosts count=1')\"",
        ] {
            assert!(matches(command), "{command}");
        }
    }

    #[test]
    fn leaves_literal_data_and_parsed_scripts_to_upstream() {
        for command in [
            "node -e \"const ok = html.includes('</p>') && /<p>/.test(html)\"",
            "python3 -c \"print('a>b')\"",
            "python3 -c 'print(\"<td>/</td>\")'",
            "python3 gen.py > ~/out.json",
            "python3 -c 'print(1)' > \"$LOG\"",
            "ruby -e 'puts [1, 2].select { |v| v > 1 }'",
            "awk '{ if ($1 > $2) print }' data.txt",
            "lua -e 'print(2 > 1)'",
            "node -e \"require(name)\" > out.txt",
            "git commit -m 'fix: compare a > b in sort'",
            "python3 - <<'PY'\nold = ''\nnew = ('echo $(date)\\n' '(task >\"$W/out.log\")\\n' + old)\nPY",
            "perl <<'PERL'\nprint <<'DATA';\nopen(FH, '>', '/etc/shadow');\nDATA\nPERL",
            "python3 -c 'import sys; print(sys.argv)' '>' '/etc/hosts'",
            // Shell scripts, remote scripts and wrappers: upstream parses them.
            "bash -c \"echo > /dev/tcp/172.20.0.2/2222\"",
            "bash -c 'D=/tmp/repro; echo hi > \"$D/x\"'",
            "ssh h 'T=$(mktemp -d); echo x > $T/s'",
            "sudo -D other true; sh -c 'echo x > ~/new-note'",
            "printf '%s\\n' 'echo x > ~/new-note' | sh",
            "sudo true && bash <<'EOF'\necho x > ~/new-note\nEOF",
            "printf '%s\\n' one | parallel sh -c 'echo x > ~/new-note'",
            "find . -name '*.txt' -exec bash -c 'echo x > \"$HOME/new-note\"' \\;",
            // Quoted data handed to a program that is not given code.
            "X='echo > /etc/profile'; $X",
            "mytool --note \"x>~/foo\"",
            "echo 'x > ~/.config/dcg/allow_once.jsonl'",
            "rm -ri ./tree \"/tmp/note > /etc/passwd\"",
            "f=/etc/sudoers; cat <<'DATA'\n> \"$f\"\nDATA",
            "Write-Output 'git>$null reset --hard'",
            // SQL and search patterns are not shell.
            "psql -c 'SELECT 1 where a>/etc/x'",
            "grep -e 'a > /etc/x' notes.txt",
            // Stdin read as data, or a program that reads a script file.
            "echo 'x > ~/note' | cat",
            "echo 'x > ~/note' | tee log.txt",
            "echo 'a > /etc/x' | grep a",
            "echo 'x > ~/note' | python3 tool.py",
            "echo 'x > ~/note' || python3",
            // GNU parallel runs each stdin line as a shell command, which upstream parses.
            "printf '%s\\n' 'echo x > ~/new-note' | parallel",
            "sudo printf '%s\\n' 'echo x > ~/new-note' | parallel",
            // A shift, a tee or dd into the working directory, and reading a protected path are not writes to one.
            "python3 -c 'print(1 >> 2)'",
            "node -e \"require('child_process').execSync('echo x | tee -a ./build.log')\"",
            "python3 -c \"__import__('os').system('dd if=/etc/hostname of=./copy')\"",
            "python3 -c \"__import__('os').system('cat /etc/hosts | tee out.txt')\"",
        ] {
            assert!(!matches(command), "{command}");
        }
    }
}
