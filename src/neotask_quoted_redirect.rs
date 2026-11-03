//! Neotask fork rule (dev-igbgn): inline code whose quoted text spells a
//! write (a truncating or appending redirect, or `tee`) to a system, home or
//! variable path.
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
/// field, is not one), after an optional opening quote (`'`, `"`, `$'`) or
/// escape.
macro_rules! protected_target {
    () => {
        r#"(?:\$?['"]|\\)?(?!/dev/(?:null|zero|full|tty|stdout|stderr)\b)(?:/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|Users|sys|proc|dev|opt)(?:/|\b)|~|\$\{?[A-Za-z_])"#
    };
}

/// A write to a protected target: a truncating or appending redirect, or
/// `tee` by any path, whose every operand is a file it writes: `--`, flags
/// (`-a`, `--output-error=warn`) and other files may come before the protected
/// one (dev-65yunv: `echo x >> /etc/passwd` and `tee /etc/passwd` inside code
/// were allowed; FuchsiaHare's REV on PR #5 found `tee -- /etc/passwd`,
/// `/usr/bin/tee`, `tee ./log /etc/passwd`, the `=value` flag and a quoted
/// earlier file). An operand is one shell word in any quoting: unquoted
/// characters, `\x` escapes (an escaped newline continues the line), `'...'`,
/// `"..."` and `$'...'` in any mix. Operands are separated by spaces or tabs
/// only; an unquoted separator, redirect, newline or a word opening a `#`
/// comment ends the command, so a later command's path, a `<` input and a
/// commented-out path are not targets (Greptile on PR #5). An escaped newline
/// also separates (N4), and the command's name is `tee` however it is quoted:
/// bare or backslashed letters, `'...'`, `"..."`, `$'...'` or an interpreter
/// string's escaped quotes, over any split of the name, with empty quotes
/// between, or a quoted full path (N3, FuchsiaHare on PR #5). `dd of=` is
/// upstream's (`dd-overwrite-*` already denies it, indirect calls included).
static PROTECTED_WRITE: LazyCompiledRegex = LazyCompiledRegex::new(concat!(
    r#"(?:(?<![<>=-])(?:&>>?|>&|[0-9]*>>?\|?)\s*"#,
    r#"|(?:^|[\s;&|(`'"])(?:(?:[^\s;&|()<>`'"]*/)?(?:''|""|\\''\\'|\\"\\")*(?:(?:\\?t\\?e\\?e|'tee'|"tee"|\$'tee'|\\"tee\\"|\\'tee\\')|(?:\\?t\\?e|'te'|"te"|\$'te'|\\"te\\"|\\'te\\')(?:''|""|\\''\\'|\\"\\")*(?:\\?e|'e'|"e"|\$'e'|\\"e\\"|\\'e\\')|(?:\\?t|'t'|"t"|\$'t'|\\"t\\"|\\'t\\')(?:''|""|\\''\\'|\\"\\")*(?:\\?e\\?e|'ee'|"ee"|\$'ee'|\\"ee\\"|\\'ee\\')|(?:\\?t|'t'|"t"|\$'t'|\\"t\\"|\\'t\\')(?:''|""|\\''\\'|\\"\\")*(?:\\?e|'e'|"e"|\$'e'|\\"e\\"|\\'e\\')(?:''|""|\\''\\'|\\"\\")*(?:\\?e|'e'|"e"|\$'e'|\\"e\\"|\\'e\\'))(?:''|""|\\''\\'|\\"\\")*|'[^'\s]*/tee'|"[^"\s]*/tee")"#,
    r#"(?:(?:[ \t]|\\\r?\n)+(?:[^\s;&|()<>`'"\\#]|\\[\s\S]|'[^']*'|"(?:[^"\\]|\\[\s\S])*")"#,
    r#"(?:[^\s;&|()<>`'"\\]|\\[\s\S]|'[^']*'|"(?:[^"\\]|\\[\s\S])*")*)*?(?:[ \t]|\\\r?\n)+"#,
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

/// Runners that launch an interpreter named later in the command (`uv run
/// python …`, `poetry run python …`, `npx node …`). `command_of` parses the
/// launched interpreter, not the runner, so an interpreter option value is not
/// read as a handoff through the runner (dev-tyz9co B1, FuchsiaHare).
const RUNNERS: &[&str] = &[
    "uv", "poetry", "pipx", "pdm", "hatch", "rye", "pipenv", "conda", "npx", "bunx",
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
    let mut program = words.next()?;
    let mut name = basename(&program.text);
    // A runner (`uv run python …`, `poetry run python …`, `npx node …`) launches
    // an interpreter named later: advance to the first argument whose basename is
    // a recognized interpreter and parse from there, so `uv run python -X sh -c`
    // is read like `python -X sh -c` rather than stopping at `sh` (dev-tyz9co B1).
    if RUNNERS.contains(&name) {
        let mut interpreter = None;
        while let Some(word) = words.peek() {
            if recognized_interpreter(basename(&word.text)) {
                interpreter = words.next();
                break;
            }
            words.next();
        }
        if let Some(word) = interpreter {
            program = word;
            name = basename(&program.text);
        }
    }
    if UPSTREAM_OWNED.contains(&name) {
        return None;
    }
    let remaining: Vec<&Word> = words.collect();
    // A recognized interpreter keeps every argument (no handoff stop): it does
    // not hand a later upstream-owned word off to a shell the way `find -exec`
    // or `parallel` do, and `reads_code_from_stdin` needs the script operand so
    // `python3 tool.py` is not read as stdin-code (dev-tyz9co). `code_words`
    // then walks the interpreter's own options to the real inline payload.
    // Every other program keeps the handoff rule.
    let rest: Vec<&Word> = if recognized_interpreter(name) {
        remaining
    } else {
        remaining
            .into_iter()
            .take_while(|word| word.was_quoted || !UPSTREAM_OWNED.contains(&basename(&word.text)))
            .collect()
    };
    Some((name, rest))
}

/// A recognized interpreter whose own options we parse with an arity table
/// ([`takes_value_operand`]) so a value like `sh` in `python3 -X sh -c …` is
/// never read as a script or a handoff.
fn recognized_interpreter(name: &str) -> bool {
    [
        "python", "node", "nodejs", "bun", "deno", "ruby", "irb", "perl", "php",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

/// Whether `flag`, as a bare option word for `name`, takes the next word as its
/// value. Glued forms (`-Xdev`, `-Mstrict`, `--require=x`) carry their value
/// already and match none of these, so they consume nothing extra. Parse-only;
/// never a deny decision (keeps judge-by-shape, dev-igbgn C1 carry).
fn takes_value_operand(name: &str, flag: &str) -> bool {
    if name.starts_with("python") {
        matches!(flag, "-X" | "-W" | "--check-hash-based-pycs")
    } else if name.starts_with("node") || name.starts_with("bun") || name.starts_with("deno") {
        matches!(
            flag,
            "-r" | "--require" | "--import" | "--loader" | "--input-type" | "-C" | "--conditions"
        )
    } else if name.starts_with("ruby") || name.starts_with("irb") {
        matches!(flag, "-I" | "-r" | "-E" | "-C")
    } else if name.starts_with("perl") {
        matches!(flag, "-I" | "-M" | "-m")
    } else {
        false
    }
}

/// An option that ends the interpreter's own option parsing with no inline code
/// to scan: `--`, a lone `-`, or python's module runner `-m`.
fn terminates_options(name: &str, flag: &str) -> bool {
    flag == "--" || flag == "-" || (name.starts_with("python") && flag == "-m")
}

/// The words a recognized interpreter hands to [`code_words`], found by walking
/// its own options: the slice from the first code flag onward, or empty when a
/// script path or terminating option comes first. The value-option check runs
/// before the code-flag check so a value flag that looks like a code flag
/// (node/ruby `-r`, ruby `-E`) consumes its value instead of being scanned.
/// After an UNKNOWN option we keep walking to a code flag rather than treating
/// the next word as a script or handoff (fail closed, FuchsiaHare on
/// dev-tyz9co), so `python3 -Q sh -c '<writes a protected path>'` is still read.
fn interpreter_code_rest<'a>(name: &str, words: &[&'a Word]) -> Vec<&'a Word> {
    let mut index = 0;
    let mut lenient = false;
    while index < words.len() {
        let word = words[index];
        if takes_value_operand(name, &word.text) {
            index += 2;
            continue;
        }
        if names_code_flag(word)
            || is_attached_code(word)
            || word.text == "eval"
            || word.text == "<<<"
        {
            // A code flag, an attached-code word, an `eval` subcommand
            // (`deno eval "<code>"`), or a here-string (`python3 <<< "<code>"`):
            // hand the slice to the shared extractor.
            return words[index..].to_vec();
        }
        if terminates_options(name, &word.text) {
            return Vec::new();
        }
        if word.text.starts_with('-') {
            // An unknown option (including a glued value form): keep scanning for
            // a code flag instead of stopping at a following upstream-owned word.
            lenient = true;
            index += 1;
            continue;
        }
        // A bare word is the script path (terminating) in normal parsing; after
        // an unknown option it may be that option's value, so keep scanning.
        if lenient {
            index += 1;
            continue;
        }
        return Vec::new();
    }
    Vec::new()
}

/// The quoted words a command hands its program as code: the word after each
/// code flag or an `eval` subcommand, a value attached to a code flag
/// (`--eval="..."`, `-e'...'`), a here-string (`<<< "..."`), or an awk
/// program's quoted words.
fn code_words<'a>(name: &str, rest: &[&'a Word]) -> Vec<&'a Word> {
    // For a recognized interpreter, walk its own options to the inline-code
    // slice first (so `-X sh` isn't read as a handoff), then extract the code
    // from that slice with the shared logic.
    if recognized_interpreter(name) {
        let slice = interpreter_code_rest(name, rest);
        return plain_code_words(name, &slice);
    }
    plain_code_words(name, rest)
}

fn plain_code_words<'a>(name: &str, rest: &[&'a Word]) -> Vec<&'a Word> {
    if AWKS.contains(&name) {
        return rest
            .iter()
            .copied()
            .filter(|word| word.was_quoted)
            .collect();
    }
    let mut code: Vec<&Word> = rest
        .windows(2)
        .filter(|pair| (names_code_flag(pair[0]) || pair[0].text == "<<<") && pair[1].was_quoted)
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

/// A code flag in flag position, whether or not the shell word was quoted.
/// Quoting a flag is invisible to the launched program — `python3 '-c' '<code>'`
/// runs the same inline code as the bare `python3 -c '<code>'` — so the flag is
/// judged by its text. (`is_code_flag` itself keeps its quoted-word guard for
/// the here-string/stdin callers, where a quoted operand is data, not a flag.)
fn names_code_flag(word: &Word) -> bool {
    is_code_flag(&Word {
        text: word.text.clone(),
        was_quoted: false,
        ..Word::default()
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
            // A quoted code flag is shell-invisible to the interpreter, so it
            // must not bypass the scan (dev-tyz9co / dev-igbgn.2 bucket-1).
            "python3 '-c' \"__import__('os').system('echo x > /etc/passwd')\"",
            "python3 '-c' '__import__(\"os\").system(\"echo x > /etc/passwd\")'",
            // An interpreter option value (-X sh), a glued option (-Xdev), an
            // unknown option (-Q), quoted options, and node/ruby/perl value
            // options must not drop the following code flag's payload
            // (dev-tyz9co -X <name> -c half; FuchsiaHare #84603).
            "python3 -X sh -c \"__import__('os').system('echo x > /etc/passwd')\"",
            "python3 -W ignore -X dev -c \"__import__('os').system('echo x > /etc/passwd')\"",
            "python3 -Xdev -c \"__import__('os').system('echo x > /etc/passwd')\"",
            "python3 -Q sh -c \"__import__('os').system('echo x > /etc/passwd')\"",
            "python3 '-X' sh '-c' \"__import__('os').system('echo x > /etc/passwd')\"",
            "node -r sh -e \"require('child_process').execSync('echo x > /etc/passwd')\"",
            "node --require=x -e \"require('child_process').execSync('echo x > /etc/passwd')\"",
            "ruby -I sh -e \"system('echo x > /etc/passwd')\"",
            "perl -M strict -e \"system('echo x > /etc/passwd')\"",
            "perl -Mstrict -e \"system('echo x > /etc/passwd')\"",
            // A runner launching the interpreter must not let the -X value drop
            // the code flag either (dev-tyz9co B1, FuchsiaHare).
            "uv run python -X sh -c \"__import__('os').system('echo x > /etc/passwd')\"",
            "uv run -- python -X sh -c \"__import__('os').system('echo x > /etc/passwd')\"",
            "poetry run python -X sh -c \"__import__('os').system('echo x > /etc/passwd')\"",
            "pipx run python -X sh -c \"__import__('os').system('echo x > /etc/passwd')\"",
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
            // tee by its path, after `--`, an `=value` flag or another output file (FuchsiaHare's REV on PR #5).
            "python3 -c \"__import__('os').system('tee -- /etc/passwd < /dev/null')\"",
            "python3 -c \"__import__('os').system('/usr/bin/tee /etc/passwd < /dev/null')\"",
            "python3 -c \"__import__('os').system('tee ./log /etc/passwd < /dev/null')\"",
            "python3 -c \"__import__('os').system('tee -a ./log ~/.bashrc < /dev/null')\"",
            "python3 -c \"__import__('os').system('echo x | tee --output-error=warn /etc/passwd')\"",
            // An earlier operand, or the target, in any quoting (FuchsiaHare's C3 on PR #5).
            r#"python3 -c "__import__('os').system('tee \"./log\" /etc/passwd < /dev/null')""#,
            r#"python3 -c "__import__('os').system(\"tee './log' /etc/passwd < /dev/null\")""#,
            r#"python3 -c 'import os; os.system("tee \"./my log\" -a /etc/passwd < /dev/null")'"#,
            r#"python3 -c "__import__('os').system('tee my\\ log \"-a\" ~/.bashrc < /dev/null')""#,
            r#"python3 -c "__import__('os').system('tee ./a\"b c\"d /etc/passwd < /dev/null')""#,
            r#"python3 -c "__import__('os').system(\"tee ./log $'/etc/passwd' < /dev/null\")""#,
            // N3 and N4 on dev-65yunv: the name in any quoting, and a continuation glued to the target.
            "python3 -c \"__import__('os').system('tee \\\\\n/etc/passwd < /dev/null')\"",
            r#"python3 -c "__import__('os').system('\"tee\" /etc/passwd < /dev/null')""#,
            r#"python3 -c "__import__('os').system(\"'tee' /etc/passwd < /dev/null\")""#,
            r#"python3 -c "__import__('os').system(\"t''ee /etc/passwd < /dev/null\")""#,
            r#"python3 -c "__import__('os').system('\\tee /etc/passwd < /dev/null')""#,
            r#"python3 -c "__import__('os').system('t\"ee\" /etc/passwd < /dev/null')""#,
            r#"python3 -c "__import__('os').system(\"te'e' -a ./log /etc/passwd < /dev/null\")""#,
            r#"python3 -c "__import__('os').system('\"/usr/bin/tee\" /etc/passwd < /dev/null')""#,
            r#"python3 -c 'import os; os.system("\"tee\" /etc/passwd < /dev/null")'"#,
            // An escaped newline continues the command (Greptile on PR #5).
            "python3 -c \"__import__('os').system('tee ./log \\\\\n /etc/passwd < /dev/null')\"",
        ] {
            assert!(matches(command), "{command}");
        }
    }

    #[test]
    fn leaves_literal_data_and_parsed_scripts_to_upstream() {
        for command in [
            // Interpreter options and script paths carry no inline write, and a
            // non-interpreter handoff keeps its own logic (dev-tyz9co -X half).
            "python3 -X sh -c 'print(1)'",
            "python3 -m http.server 8000",
            "python3 -W ignore script.py",
            "node -r ts-node/register app.ts",
            "uv run python script.py",
            "uv run pytest -q tests/",
            "poetry run python -X dev app.py --flag",
            "find . -name '*.py' -exec bash -c 'echo \"$1\"' _ {} \\;",
            "parallel sh -c 'echo {}' ::: a b",
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
            // A shift, a tee into the working directory, and reading a protected path are not writes to one.
            "python3 -c 'print(1 >> 2)'",
            "node -e \"require('child_process').execSync('echo x | tee -a ./build.log')\"",
            // dd is upstream's: `of=` in code is data here (FuchsiaHare's REV on PR #5).
            "python3 -c \"print('of=/etc/hosts')\"",
            // A tee into the working directory, then a later command that names a protected path.
            "python3 -c \"__import__('os').system('echo x | tee ./log; cat /etc/hosts')\"",
            "python3 -c \"__import__('os').system('tee ./log < /etc/hosts')\"",
            "python3 -c \"__import__('os').system('coffee /etc/passwd; guarantee /etc/x')\"",
            // A quoted word that is not tee (N3).
            r#"python3 -c "__import__('os').system('\"teething\" /etc/passwd')""#,
            r#"python3 -c "__import__('os').system('\"tee\"x /etc/passwd')""#,
            r#"python3 -c "print('tee', '/etc/passwd')""#,
            // Quoted text after a tee that is not one of its operands.
            r#"python3 -c "print('tee x', '/etc/passwd')""#,
            r#"python3 -c "__import__('os').system('echo x | tee \"./a b\"; cat /etc/hosts')""#,
            // A comment, or a newline ending the command, after a tee (Greptile on PR #5).
            "python3 -c \"__import__('os').system('printf x | tee ./log # /etc/hosts')\"",
            "python3 -c \"__import__('os').system('printf x | tee ./log\n cat /etc/hosts')\"",
            "python3 -c \"__import__('os').system('cat /etc/hosts | tee out.txt')\"",
        ] {
            assert!(!matches(command), "{command}");
        }
    }
}
