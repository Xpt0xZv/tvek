use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{self, ExitCode};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tvek::error::sanitize_for_terminal;
use tvek::lexer::{
    format_json_into_buf, lint_json_multi_with_options, FormatOptions, DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_OUTPUT_BYTES, MAX_LINT_DIAGNOSTICS,
};
use tvek::lsp::{run_stdio_server, LspConfig};

const VERSION: &str = concat!("tvek ", env!("CARGO_PKG_VERSION"));
const MAX_DIR_DEPTH: usize = 64;
const MAX_DISCOVERED_FILES: usize = 100_000;
const MAX_READ_PREALLOC_BYTES: usize = 16 * 1024 * 1024; // 16 MiB cap on file read pre-allocation
const MAX_RETAINED_WORKER_BUF_CAPACITY: usize = 4 * 1024 * 1024; // 4 MiB RSS cap per worker buffer
const SHRINK_TARGET_CAPACITY: usize = 256 * 1024; // 256 KiB target after shrinking oversized buffer
const TEMP_FILE_MAX_ATTEMPTS: u32 = 64;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const HELP_TEXT: &str = concat!(
    "tvek ",
    env!("CARGO_PKG_VERSION"),
    "\n\
Zero-dependency, ultra-fast RFC 8259 JSON and JSONC linter and formatter

USAGE:
    tvek [OPTIONS] [FILES_OR_DIRS...]
    tvek server [OPTIONS]

ARGS:
    [FILES_OR_DIRS...]       Files or directories to process (defaults to stdin '-')

SUBCOMMANDS:
    server                   Start the Language Server Protocol (LSP) server over stdio

OPTIONS:
    -c, --check              Lint and verify formatting without modifying files
    -l, --lint               Lint syntax only (ignore whitespace/indentation differences)
    -w, --write              Format files in-place atomically when output differs
    -m, --minify             Output compact single-line JSON with whitespace and comments stripped
    -i, --indent <N>         Number of spaces per indentation level (default: 2; 0 for tab)
    -s, --sort-keys          Lexicographically sort object keys at every nesting level
        --strict             Enforce strict RFC 8259 JSON (disallow '//' and '/* */' comments)
        --max-size <BYTES>   Maximum input size in bytes (default: 104857600 / 100 MiB)
        --lsp                Start the Language Server Protocol (LSP) server over stdio
    -q, --quiet              Suppress non-error output
    -v, --version            Print version information and exit
    -h, --help               Print this help message and exit

EXIT CODES:
    0                        Success (all inputs valid and properly formatted)
    1                        Syntax error or formatting check failed
    2                        CLI usage error or file I/O error
"
);

#[derive(Debug, Clone, PartialEq, Eq)]
enum InputTarget {
    Stdin,
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliConfig {
    check: bool,
    lint: bool,
    write: bool,
    quiet: bool,
    max_input_bytes: usize,
    format_opts: FormatOptions,
    targets: Vec<InputTarget>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            check: false,
            lint: false,
            write: false,
            quiet: false,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            format_opts: FormatOptions::default(),
            targets: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ParseAction {
    Run(CliConfig),
    Server(LspConfig),
    Help,
    Version,
}

fn parse_args<I, T>(args: I) -> Result<ParseAction, String>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut iter = args.into_iter().map(Into::into);
    let mut cfg = CliConfig::default();
    let mut positional_only = false;
    let mut explicit_indent = false;
    let mut lsp_mode = false;

    while let Some(os_arg) = iter.next() {
        if positional_only {
            cfg.targets.push(os_arg_to_target(os_arg));
            continue;
        }

        // Check if this argument starts with '-' by inspecting its UTF-8 representation if valid,
        // or treating non-UTF-8 arguments that don't start with '-' as file paths (IMP-03).
        let Some(arg) = os_arg.to_str() else {
            let lossy = os_arg.to_string_lossy();
            if lossy.starts_with('-') && lossy != "-" {
                return Err(format!("Invalid non-UTF-8 option '{}'", lossy));
            }
            cfg.targets.push(InputTarget::Path(PathBuf::from(os_arg)));
            continue;
        };

        if arg == "--" {
            positional_only = true;
            continue;
        }

        if arg == "-" {
            cfg.targets.push(InputTarget::Stdin);
            continue;
        }

        if !arg.starts_with('-') {
            if arg == "server" && cfg.targets.is_empty() && !lsp_mode {
                lsp_mode = true;
                continue;
            }
            cfg.targets.push(InputTarget::Path(PathBuf::from(os_arg)));
            continue;
        }

        if let Some(long) = arg.strip_prefix("--") {
            if let Some((key, val)) = long.split_once('=') {
                match key {
                    "indent" => {
                        cfg.format_opts.indent = parse_indent_value(val)?;
                        explicit_indent = true;
                    }
                    "max-size" => cfg.max_input_bytes = parse_max_size_value(val)?,
                    _ => return Err(format!("Unknown option '--{}'", key)),
                }
                continue;
            }

            match long {
                "check" => cfg.check = true,
                "lint" => cfg.lint = true,
                "write" => cfg.write = true,
                "minify" => cfg.format_opts.minify = true,
                "sort-keys" => cfg.format_opts.sort_keys = true,
                "strict" | "no-comments" => cfg.format_opts.allow_comments = false,
                "quiet" => cfg.quiet = true,
                "lsp" => lsp_mode = true,
                "version" => return Ok(ParseAction::Version),
                "help" => return Ok(ParseAction::Help),
                "indent" => {
                    let val_os = iter.next().ok_or_else(|| {
                        "Option '--indent' requires a numeric value <N>".to_string()
                    })?;
                    let val = val_os
                        .to_str()
                        .ok_or_else(|| "Invalid non-UTF-8 value for '--indent'".to_string())?;
                    cfg.format_opts.indent = parse_indent_value(val)?;
                    explicit_indent = true;
                }
                "max-size" => {
                    let val_os = iter.next().ok_or_else(|| {
                        "Option '--max-size' requires a byte limit <BYTES>".to_string()
                    })?;
                    let val = val_os
                        .to_str()
                        .ok_or_else(|| "Invalid non-UTF-8 value for '--max-size'".to_string())?;
                    cfg.max_input_bytes = parse_max_size_value(val)?;
                }
                _ => return Err(format!("Unknown option '--{}'", long)),
            }
        } else {
            // Short flags (may be combined, e.g. -ms or -i4)
            let shorts = &arg[1..];
            for (idx, ch) in shorts.char_indices() {
                match ch {
                    'c' => cfg.check = true,
                    'l' => cfg.lint = true,
                    'w' => cfg.write = true,
                    'm' => cfg.format_opts.minify = true,
                    's' => cfg.format_opts.sort_keys = true,
                    'q' => cfg.quiet = true,
                    'v' => return Ok(ParseAction::Version),
                    'h' => return Ok(ParseAction::Help),
                    'i' => {
                        let rest = &shorts[idx + ch.len_utf8()..];
                        let val_str = if !rest.is_empty() {
                            rest.to_string()
                        } else {
                            let next_os = iter.next().ok_or_else(|| {
                                "Option '-i' requires a numeric value <N>".to_string()
                            })?;
                            next_os
                                .to_str()
                                .ok_or_else(|| "Invalid non-UTF-8 value for '-i'".to_string())?
                                .to_string()
                        };
                        cfg.format_opts.indent = parse_indent_value(&val_str)?;
                        explicit_indent = true;
                        break;
                    }
                    _ => return Err(format!("Unknown option '-{}'", ch)),
                }
            }
        }
    }

    if lsp_mode {
        if cfg.check || cfg.lint || cfg.write || cfg.quiet || explicit_indent {
            return Err(
                "Options '--check', '--lint', '--write', '--quiet', and '--indent' cannot be used with 'tvek server' / '--lsp'"
                    .to_string(),
            );
        }
        if !cfg.targets.is_empty() {
            return Err(
                "File or directory arguments cannot be passed to 'tvek server' / '--lsp'"
                    .to_string(),
            );
        }
        return Ok(ParseAction::Server(LspConfig {
            sort_keys: cfg.format_opts.sort_keys,
            minify: cfg.format_opts.minify,
            allow_comments: cfg.format_opts.allow_comments,
            max_input_bytes: cfg.max_input_bytes,
        }));
    }

    // ADR-01 / IMP-02: Validate mutually exclusive CLI flags and disallow --write with stdin
    let mode_count = (cfg.check as u8) + (cfg.lint as u8) + (cfg.write as u8);
    if mode_count > 1 {
        return Err(
            "Options '--check', '--lint', and '--write' are mutually exclusive".to_string(),
        );
    }
    if cfg.format_opts.minify && explicit_indent {
        return Err("Options '--minify' and '--indent' cannot be used together".to_string());
    }
    if cfg.write
        && (cfg.targets.is_empty() || cfg.targets.iter().any(|t| matches!(t, InputTarget::Stdin)))
    {
        return Err("Option '--write' cannot be used with stdin ('-')".to_string());
    }

    Ok(ParseAction::Run(cfg))
}

fn os_arg_to_target(os_arg: OsString) -> InputTarget {
    if os_arg.to_str() == Some("-") {
        InputTarget::Stdin
    } else {
        InputTarget::Path(PathBuf::from(os_arg))
    }
}

fn parse_indent_value(val: &str) -> Result<usize, String> {
    let n = val.parse::<usize>().map_err(|_| {
        format!(
            "Invalid indent value '{}': expected non-negative integer",
            val
        )
    })?;
    if n > 64 {
        return Err(format!("Indent value '{}' is too large (maximum is 64)", n));
    }
    Ok(n)
}

fn parse_max_size_value(val: &str) -> Result<usize, String> {
    let n = val.parse::<usize>().map_err(|_| {
        format!(
            "Invalid max-size value '{}': expected positive integer in bytes",
            val
        )
    })?;
    if n == 0 {
        return Err("Option '--max-size' must be greater than 0".to_string());
    }
    Ok(n)
}

/// ADR-04 / IMP-08: Ignore all hidden child directories (`name.starts_with('.')`) and
/// standard build/dependency/vendor directories during recursive directory walks.
fn is_ignored_dir(name: &str) -> bool {
    name.starts_with('.')
        || matches!(
            name,
            "node_modules" | "target" | "dist" | "build" | "vendor" | "__pycache__"
        )
}

fn write_stderr_line(msg: &str) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();
    let _ = writeln!(handle, "{}", msg);
}

/// Iterative directory traversal with an explicit depth cap (`MAX_DIR_DEPTH`),
/// file discovery cap (`MAX_DISCOVERED_FILES`), `DirEntry::file_type()` fast-path (PERF-07),
/// and resilient per-entry error reporting (TVEK-04 / TVEK-07).
fn collect_json_files_in_dir(root_dir: &Path, out: &mut Vec<PathBuf>, has_io_err: &mut bool) {
    collect_json_files_in_dir_with_limit(root_dir, out, MAX_DISCOVERED_FILES, has_io_err);
}

fn collect_json_files_in_dir_with_limit(
    root_dir: &Path,
    out: &mut Vec<PathBuf>,
    max_files: usize,
    has_io_err: &mut bool,
) {
    let mut worklist: Vec<(PathBuf, usize)> = vec![(root_dir.to_path_buf(), 0)];

    while let Some((dir, depth)) = worklist.pop() {
        if depth > MAX_DIR_DEPTH {
            write_stderr_line(&format!(
                "error: Maximum directory recursion depth ({}) exceeded at '{}'",
                MAX_DIR_DEPTH,
                sanitize_for_terminal(&dir.to_string_lossy(), false)
            ));
            *has_io_err = true;
            continue;
        }

        let read_dir = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                write_stderr_line(&format!(
                    "error: Failed to read directory '{}': {}",
                    sanitize_for_terminal(&dir.to_string_lossy(), false),
                    e
                ));
                *has_io_err = true;
                continue;
            }
        };

        let max_dir_entries = max_files.saturating_mul(2).max(1);
        let mut entry_count = 0usize;
        let mut subdirs: Vec<PathBuf> = Vec::new();
        let mut json_files: Vec<PathBuf> = Vec::new();

        for entry_res in read_dir {
            match entry_res {
                Ok(entry) => {
                    if entry_count >= max_dir_entries {
                        write_stderr_line(&format!(
                            "error: Directory entry limit ({}) exceeded in '{}'",
                            max_dir_entries,
                            sanitize_for_terminal(&dir.to_string_lossy(), false)
                        ));
                        *has_io_err = true;
                        return;
                    }
                    entry_count += 1;

                    let ft = match entry.file_type() {
                        Ok(ft) => ft,
                        Err(e) => {
                            let path = entry.path();
                            write_stderr_line(&format!(
                                "error: Failed to inspect '{}': {}",
                                sanitize_for_terminal(&path.to_string_lossy(), false),
                                e
                            ));
                            *has_io_err = true;
                            continue;
                        }
                    };

                    if ft.is_symlink() {
                        continue;
                    }

                    let file_name = entry.file_name();
                    if ft.is_dir() {
                        if let Some(name) = file_name.to_str() {
                            if is_ignored_dir(name) {
                                continue;
                            }
                        }
                        subdirs.push(entry.path());
                    } else if ft.is_file() {
                        if let Some(ext) =
                            Path::new(&file_name).extension().and_then(|e| e.to_str())
                        {
                            if ext.eq_ignore_ascii_case("json") || ext.eq_ignore_ascii_case("jsonc")
                            {
                                json_files.push(entry.path());
                            }
                        }
                    }
                }
                Err(e) => {
                    write_stderr_line(&format!(
                        "error: Failed to read entry in '{}': {}",
                        sanitize_for_terminal(&dir.to_string_lossy(), false),
                        e
                    ));
                    *has_io_err = true;
                }
            }
        }

        json_files.sort();
        for path in json_files {
            if out.len() >= max_files {
                write_stderr_line(&format!(
                    "error: Maximum discovered file limit ({}) exceeded in '{}'",
                    max_files,
                    sanitize_for_terminal(&root_dir.to_string_lossy(), false)
                ));
                *has_io_err = true;
                return;
            }
            out.push(path);
        }

        subdirs.sort();
        for subdir in subdirs.into_iter().rev() {
            worklist.push((subdir, depth + 1));
        }
    }
}

struct WorkerBuffers {
    input: Vec<u8>,
    output: Vec<u8>,
}

impl WorkerBuffers {
    fn new() -> Self {
        Self {
            input: Vec::with_capacity(64 * 1024),
            output: Vec::with_capacity(64 * 1024),
        }
    }

    #[inline]
    fn reset_after_file(&mut self) {
        self.input.clear();
        if self.input.capacity() > MAX_RETAINED_WORKER_BUF_CAPACITY {
            self.input.shrink_to(SHRINK_TARGET_CAPACITY);
        }
        self.output.clear();
        if self.output.capacity() > MAX_RETAINED_WORKER_BUF_CAPACITY {
            self.output.shrink_to(SHRINK_TARGET_CAPACITY);
        }
    }
}

/// Bounded reader that reads at most `max_bytes` from `reader`, returning an error
/// if the stream exceeds `max_bytes` (TVEK-02 / CWE-400).
fn read_reader_bounded<R: Read>(reader: R, max_bytes: usize) -> io::Result<Vec<u8>> {
    read_reader_bounded_with_hint(reader, max_bytes, None)
}

/// Bounded reader with an optional file-size capacity hint to eliminate geometric reallocations (PERF-06).
fn read_reader_bounded_with_hint<R: Read>(
    reader: R,
    max_bytes: usize,
    size_hint: Option<u64>,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    read_reader_bounded_into(reader, max_bytes, size_hint, &mut buf)?;
    Ok(buf)
}

/// Bounded reader that reuses an existing `Vec<u8>` buffer while enforcing `max_bytes` (PERF-06 / PERF-08).
fn read_reader_bounded_into<R: Read>(
    reader: R,
    max_bytes: usize,
    size_hint: Option<u64>,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    buf.clear();
    let limit = (max_bytes as u64).saturating_add(1);
    let initial_cap = match size_hint {
        Some(hint) => (hint as usize)
            .min(max_bytes)
            .min(MAX_READ_PREALLOC_BYTES)
            .saturating_add(1),
        None => 8192.min(max_bytes.saturating_add(1)),
    };
    if buf.capacity() < initial_cap {
        buf.reserve(initial_cap - buf.capacity());
    }
    reader.take(limit).read_to_end(buf)?;
    if buf.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Input exceeds maximum allowed size of {} bytes", max_bytes),
        ));
    }
    Ok(())
}

/// Bounded file reader that opens the file handle first (eliminating path-based TOCTOU),
/// verifies `meta.is_file()` (rejecting FIFOs, sockets, and device nodes), and enforces
/// `max_bytes` with single-allocation buffer reservation (TVEK-02 / TVEK-07 / PERF-06).
#[cfg(test)]
fn read_file_bounded(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    read_file_bounded_into(path, max_bytes, &mut buf)?;
    Ok(buf)
}

/// Bounded file reader into a caller-provided reusable `Vec<u8>` buffer (PERF-08).
fn read_file_bounded_into(path: &Path, max_bytes: usize, buf: &mut Vec<u8>) -> io::Result<()> {
    let file = fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Not a regular file",
        ));
    }
    let file_len = meta.len();
    if file_len > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "File size ({} bytes) exceeds maximum allowed size of {} bytes",
                file_len, max_bytes
            ),
        ));
    }
    read_reader_bounded_into(file, max_bytes, Some(file_len), buf)
}

/// Generates a non-predictable 64-bit token mixing PID, system clock nanoseconds,
/// an atomic counter, and stack address entropy.
fn next_random_token(attempt: u32) -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = process::id() as u64;
    let stack_addr = (&attempt as *const u32) as usize as u64;

    let mut x = nanos
        ^ pid.rotate_left(17)
        ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ stack_addr.rotate_left(31)
        ^ (attempt as u64);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Clears the read-only flag on `perms` without making the file world-writable on Unix.
fn clear_readonly(perms: &mut fs::Permissions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = perms.mode();
        perms.set_mode(mode | 0o200);
    }
    #[cfg(not(unix))]
    {
        perms.set_readonly(false);
    }
}

/// Removes a temporary file, clearing read-only attributes first if necessary on Windows (IMP-03).
fn remove_temp_file(path: &Path) {
    if fs::remove_file(path).is_err() {
        if let Ok(meta) = fs::symlink_metadata(path) {
            let mut perms = meta.permissions();
            if perms.readonly() {
                clear_readonly(&mut perms);
                let _ = fs::set_permissions(path, perms);
                let _ = fs::remove_file(path);
            }
        }
    }
}

/// Verifies that `path` is not a symbolic link and is not marked read-only (TVEK-01 / IMP-03 / R-03).
fn validate_writable_target(path: &Path) -> io::Result<fs::Permissions> {
    let sym_meta = fs::symlink_metadata(path)?;
    if sym_meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Refusing to overwrite symbolic link in-place",
        ));
    }
    let orig_perms = sym_meta.permissions();
    if orig_perms.readonly() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Refusing to overwrite read-only file",
        ));
    }
    Ok(orig_perms)
}

/// Atomically writes `content` to `path` while mitigating TVEK-01 and IMP-03 (ADR-03):
/// 1. Refuses to overwrite symbolic links in-place.
/// 2. Fails fast with `PermissionDenied` if the target file is read-only before creating any temp file.
/// 3. Opens the temporary file with `create_new(true)` (`O_CREAT | O_EXCL`) and random suffix retries.
/// 4. Preserves the target file's original permissions before renaming.
fn write_file_atomically(path: &Path, content: &[u8]) -> io::Result<()> {
    let orig_perms = validate_writable_target(path)?;

    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("output.json");

    let mut created_tmp: Option<(fs::File, PathBuf)> = None;
    for attempt in 0..TEMP_FILE_MAX_ATTEMPTS {
        let token = next_random_token(attempt);
        let candidate = parent.join(format!(".{}.tvek_tmp_{:016x}", file_name, token));
        let mut open_opts = OpenOptions::new();
        open_opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(0o600);
        }
        match open_opts.open(&candidate) {
            Ok(file) => {
                created_tmp = Some((file, candidate));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    let (mut tmp_file, tmp_path) = created_tmp.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Failed to create exclusive temporary file after maximum retries",
        )
    })?;

    let write_and_sync = (|| -> io::Result<()> {
        tmp_file.write_all(content)?;
        tmp_file.sync_all()?;
        let _ = tmp_file.set_permissions(orig_perms.clone());
        Ok(())
    })();

    drop(tmp_file);

    if let Err(e) = write_and_sync {
        remove_temp_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = fs::set_permissions(&tmp_path, orig_perms) {
        remove_temp_file(&tmp_path);
        return Err(e);
    }

    if let Err(rename_err) = fs::rename(&tmp_path, path) {
        remove_temp_file(&tmp_path);
        return Err(rename_err);
    }

    Ok(())
}

fn compute_max_output_bytes(max_input_bytes: usize) -> usize {
    if max_input_bytes == DEFAULT_MAX_INPUT_BYTES {
        DEFAULT_MAX_OUTPUT_BYTES
    } else {
        max_input_bytes.saturating_mul(4).max(64 * 1024)
    }
}

fn process_buffer(
    display_name: &str,
    file_path: Option<&Path>,
    input: &[u8],
    cfg: &CliConfig,
    has_lint_or_check_err: &AtomicBool,
    has_io_err: &AtomicBool,
) {
    let mut out_buf = Vec::new();
    process_buffer_with_output(
        display_name,
        file_path,
        input,
        &mut out_buf,
        cfg,
        has_lint_or_check_err,
        has_io_err,
    );
}

fn process_buffer_with_output(
    display_name: &str,
    file_path: Option<&Path>,
    input: &[u8],
    formatted: &mut Vec<u8>,
    cfg: &CliConfig,
    has_lint_or_check_err: &AtomicBool,
    has_io_err: &AtomicBool,
) {
    let safe_display = sanitize_for_terminal(display_name, false);
    let max_output_bytes = compute_max_output_bytes(cfg.max_input_bytes);

    if cfg.lint {
        let errs = lint_json_multi_with_options(
            input,
            cfg.format_opts.allow_comments,
            max_output_bytes,
            MAX_LINT_DIAGNOSTICS,
        );
        if !errs.is_empty() {
            for err in &errs {
                write_stderr_line(&err.format_diagnostic(&safe_display, input));
            }
            has_lint_or_check_err.store(true, Ordering::Relaxed);
        }
        return;
    }

    if let Err(err) = format_json_into_buf(input, &cfg.format_opts, max_output_bytes, formatted) {
        write_stderr_line(&err.format_diagnostic(&safe_display, input));
        has_lint_or_check_err.store(true, Ordering::Relaxed);
        return;
    }

    if cfg.check {
        if formatted.as_slice() != input {
            if !cfg.quiet {
                write_stderr_line(&format!("Would reformat: {}", safe_display));
            }
            has_lint_or_check_err.store(true, Ordering::Relaxed);
        }
        return;
    }

    if cfg.write {
        if let Some(path) = file_path {
            if let Err(e) = validate_writable_target(path) {
                write_stderr_line(&format!("error: Failed to write '{}': {}", safe_display, e));
                has_io_err.store(true, Ordering::Relaxed);
                return;
            }
            if formatted.as_slice() != input {
                if let Err(e) = write_file_atomically(path, formatted) {
                    write_stderr_line(&format!("error: Failed to write '{}': {}", safe_display, e));
                    has_io_err.store(true, Ordering::Relaxed);
                } else if !cfg.quiet {
                    write_stderr_line(&format!("Formatted {}", safe_display));
                }
            }
            return;
        }
    }

    if !cfg.quiet {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        if let Err(e) = handle.write_all(formatted) {
            write_stderr_line(&format!("error: Failed to write to stdout: {}", e));
            has_io_err.store(true, Ordering::Relaxed);
        }
    }
}

/// Lexically normalizes a path (resolving `.` and `..` against `current_dir` when relative)
/// without performing per-file OS `realpath` / `GetFinalPathNameByHandleW` syscalls (INFO-01 / PERF-07 / TVEK-18).
fn normalize_path_lexical(path: &Path, cwd: Option<&Path>) -> PathBuf {
    let mut components: Vec<Component<'_>> = Vec::new();
    let base_iter = if path.is_relative() {
        cwd.map(|c| c.components())
    } else {
        None
    };

    for comp in base_iter.into_iter().flatten().chain(path.components()) {
        match comp {
            Component::Prefix(_) => {
                components.clear();
                components.push(comp);
            }
            Component::RootDir => {
                if matches!(components.first(), Some(Component::Prefix(_))) {
                    components.truncate(1);
                } else {
                    components.clear();
                }
                components.push(comp);
            }
            Component::CurDir => {}
            Component::ParentDir => match components.last() {
                Some(Component::Normal(_)) => {
                    components.pop();
                }
                Some(Component::RootDir) | Some(Component::Prefix(_)) => {}
                _ => {
                    components.push(comp);
                }
            },
            Component::Normal(_) => {
                components.push(comp);
            }
        }
    }

    let mut out = PathBuf::new();
    for comp in components {
        out.push(comp.as_os_str());
    }
    out
}

#[inline]
fn normalize_case_for_dedup(path: PathBuf) -> PathBuf {
    #[cfg(any(windows, target_os = "macos"))]
    {
        if let Some(s) = path.to_str() {
            return PathBuf::from(s.to_lowercase());
        }
    }
    path
}

#[inline]
fn normalize_os_str_case(name: &OsStr) -> OsString {
    #[cfg(any(windows, target_os = "macos"))]
    {
        if let Some(s) = name.to_str() {
            return OsString::from(s.to_lowercase());
        }
    }
    name.to_os_string()
}

/// Deduplicates file paths while preserving discovery order, preventing concurrent write races
/// when duplicate or aliased paths are passed to `process_file_batch` (TVEK-06 / INFO-01 / PERF-07 / TVEK-18).
/// Caches `fs::canonicalize` per unique parent directory so large batches (> 64 files) resolve
/// parent symlinks/junctions and case-insensitive aliases without O(N) `canonicalize` syscalls.
fn deduplicate_files(files: &[PathBuf]) -> Vec<PathBuf> {
    if files.len() <= 1 {
        return files.to_vec();
    }
    let cwd = env::current_dir().ok();
    let mut parent_cache: HashMap<PathBuf, (PathBuf, bool)> = HashMap::new();
    let mut seen = HashSet::with_capacity(files.len());
    let mut unique = Vec::with_capacity(files.len());

    for path in files {
        let key = if let Some(Component::Normal(file_name)) = path.components().next_back() {
            let raw_parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let (canon_parent, parent_exists) = parent_cache
                .entry(raw_parent.to_path_buf())
                .or_insert_with(|| match fs::canonicalize(raw_parent) {
                    Ok(canon) => (normalize_case_for_dedup(canon), true),
                    Err(_) => (
                        normalize_case_for_dedup(normalize_path_lexical(
                            raw_parent,
                            cwd.as_deref(),
                        )),
                        false,
                    ),
                })
                .clone();

            if parent_exists
                && fs::symlink_metadata(path)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
            {
                match fs::canonicalize(path) {
                    Ok(canon) => normalize_case_for_dedup(canon),
                    Err(_) => canon_parent.join(normalize_os_str_case(file_name)),
                }
            } else {
                canon_parent.join(normalize_os_str_case(file_name))
            }
        } else {
            let resolved = fs::canonicalize(path)
                .unwrap_or_else(|_| normalize_path_lexical(path, cwd.as_deref()));
            normalize_case_for_dedup(resolved)
        };

        if seen.insert(key) {
            unique.push(path.clone());
        }
    }
    unique
}

/// Processes a slice of discovered files in parallel using `std::thread::scope` when
/// multiple files are present and we are in a file-oriented mode (`--lint`, `--check`, `--write`),
/// or sequentially when streaming formatted JSON to stdout so output order stays deterministic (IMP-07).
#[cfg(test)]
fn process_file_batch(
    files: &[PathBuf],
    cfg: &CliConfig,
    has_lint_or_check_err: &AtomicBool,
    has_io_err: &AtomicBool,
) {
    process_file_batch_with_dedup(files, true, cfg, has_lint_or_check_err, has_io_err);
}

fn process_file_batch_with_dedup(
    files: &[PathBuf],
    needs_dedup: bool,
    cfg: &CliConfig,
    has_lint_or_check_err: &AtomicBool,
    has_io_err: &AtomicBool,
) {
    let deduped: Vec<PathBuf>;
    let files = if needs_dedup && files.len() > 1 {
        deduped = deduplicate_files(files);
        deduped.as_slice()
    } else {
        files
    };
    let can_parallelize = files.len() > 1 && (cfg.lint || cfg.check || cfg.write || cfg.quiet);
    let worker_count = if can_parallelize {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(files.len())
    } else {
        1
    };

    if worker_count <= 1 {
        let mut buffers = WorkerBuffers::new();
        for file_path in files {
            process_single_file_with_buffers(
                file_path,
                &mut buffers,
                cfg,
                has_lint_or_check_err,
                has_io_err,
            );
            buffers.reset_after_file();
        }
        return;
    }

    let next_idx = AtomicUsize::new(0);
    thread::scope(|s| {
        for _ in 0..worker_count {
            s.spawn(|| {
                let mut buffers = WorkerBuffers::new();
                loop {
                    let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                    if idx >= files.len() {
                        break;
                    }
                    process_single_file_with_buffers(
                        &files[idx],
                        &mut buffers,
                        cfg,
                        has_lint_or_check_err,
                        has_io_err,
                    );
                    buffers.reset_after_file();
                }
            });
        }
    });
}

fn process_single_file_with_buffers(
    file_path: &Path,
    buffers: &mut WorkerBuffers,
    cfg: &CliConfig,
    has_lint_or_check_err: &AtomicBool,
    has_io_err: &AtomicBool,
) {
    let display = file_path.to_string_lossy();
    match read_file_bounded_into(file_path, cfg.max_input_bytes, &mut buffers.input) {
        Ok(()) => {
            process_buffer_with_output(
                &display,
                Some(file_path),
                &buffers.input,
                &mut buffers.output,
                cfg,
                has_lint_or_check_err,
                has_io_err,
            );
        }
        Err(e) => {
            write_stderr_line(&format!(
                "error: Failed to read '{}': {}",
                sanitize_for_terminal(&display, false),
                e
            ));
            has_io_err.store(true, Ordering::Relaxed);
        }
    }
}

fn main() -> ExitCode {
    let action = match parse_args(env::args_os().skip(1)) {
        Ok(act) => act,
        Err(msg) => {
            eprintln!(
                "error: {}\n\nRun 'tvek --help' for usage information.",
                sanitize_for_terminal(&msg, false)
            );
            return ExitCode::from(2);
        }
    };

    let cfg = match action {
        ParseAction::Help => {
            print!("{}", HELP_TEXT);
            return ExitCode::from(0);
        }
        ParseAction::Version => {
            println!("{}", VERSION);
            return ExitCode::from(0);
        }
        ParseAction::Server(lsp_cfg) => {
            return ExitCode::from(run_stdio_server(lsp_cfg));
        }
        ParseAction::Run(cfg) => cfg,
    };

    let has_lint_or_check_err = AtomicBool::new(false);
    let has_io_err = AtomicBool::new(false);

    let targets = if cfg.targets.is_empty() {
        vec![InputTarget::Stdin]
    } else {
        cfg.targets.clone()
    };

    let path_target_count = targets
        .iter()
        .filter(|t| matches!(t, InputTarget::Path(_)))
        .count();
    // A single root path target walked without following symlinks is guaranteed duplicate-free (PERF-07).
    let needs_dedup = path_target_count > 1;
    let mut seen_root_dirs: HashSet<PathBuf> = HashSet::new();
    let mut pending_files: Vec<PathBuf> = Vec::new();

    for target in &targets {
        match target {
            InputTarget::Stdin => {
                if !pending_files.is_empty() {
                    process_file_batch_with_dedup(
                        &pending_files,
                        needs_dedup,
                        &cfg,
                        &has_lint_or_check_err,
                        &has_io_err,
                    );
                    pending_files.clear();
                }

                let buffer = match read_reader_bounded(io::stdin().lock(), cfg.max_input_bytes) {
                    Ok(buf) => buf,
                    Err(e) => {
                        write_stderr_line(&format!("error: Failed to read from stdin: {}", e));
                        has_io_err.store(true, Ordering::Relaxed);
                        continue;
                    }
                };
                process_buffer(
                    "<stdin>",
                    None,
                    &buffer,
                    &cfg,
                    &has_lint_or_check_err,
                    &has_io_err,
                );
            }
            InputTarget::Path(path) => {
                let display = path.to_string_lossy();
                let safe_target = sanitize_for_terminal(&display, false);
                let meta = match fs::metadata(path) {
                    Ok(m) => m,
                    Err(e) => {
                        write_stderr_line(&format!(
                            "error: Failed to access '{}': {}",
                            safe_target, e
                        ));
                        has_io_err.store(true, Ordering::Relaxed);
                        continue;
                    }
                };

                if meta.is_dir() {
                    if needs_dedup {
                        if let Ok(canon_dir) = fs::canonicalize(path) {
                            if !seen_root_dirs.insert(canon_dir) {
                                continue;
                            }
                        }
                    }
                    let mut dir_io_err = false;
                    collect_json_files_in_dir(path, &mut pending_files, &mut dir_io_err);
                    if dir_io_err {
                        has_io_err.store(true, Ordering::Relaxed);
                    }
                } else {
                    pending_files.push(path.clone());
                }
            }
        }
    }

    if !pending_files.is_empty() {
        process_file_batch_with_dedup(
            &pending_files,
            needs_dedup,
            &cfg,
            &has_lint_or_check_err,
            &has_io_err,
        );
    }

    if has_io_err.load(Ordering::Relaxed) {
        ExitCode::from(2)
    } else if has_lint_or_check_err.load(Ordering::Relaxed) {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_temp_test_dir(label: &str) -> PathBuf {
        let token = next_random_token(0);
        let dir = env::temp_dir().join(format!("tvek_test_{}_{:016x}", label, token));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_tvek_01_atomic_write_and_temp_cleanup() {
        let dir = create_temp_test_dir("atomic_write");
        let target = dir.join("config.json");
        fs::write(&target, b"{\"a\":1}").unwrap();

        let legacy_predictable = dir.join(format!(".config.json.tvek_tmp_{}", process::id()));
        fs::write(&legacy_predictable, b"DO_NOT_CLOBBER").unwrap();

        write_file_atomically(&target, b"{\n  \"a\": 1\n}\n").unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"{\n  \"a\": 1\n}\n");
        assert_eq!(fs::read(&legacy_predictable).unwrap(), b"DO_NOT_CLOBBER");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tvek_02_bounded_reader_and_file_size_limit() {
        let data = b"{\"hello\": \"world\"}";
        assert!(read_reader_bounded(&data[..], 64).is_ok());

        let err = read_reader_bounded(&data[..], 5).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum allowed size"));

        let dir = create_temp_test_dir("bounded_file");
        let file_path = dir.join("large.json");
        fs::write(&file_path, b"{\"key\": \"0123456789\"}").unwrap();

        assert!(read_file_bounded(&file_path, 1024).is_ok());
        let file_err = read_file_bounded(&file_path, 10).unwrap_err();
        assert_eq!(file_err.kind(), io::ErrorKind::InvalidData);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tvek_02_cli_max_size_flag() {
        let act = parse_args(vec!["--max-size", "4096", "file.json"]).unwrap();
        match act {
            ParseAction::Run(cfg) => assert_eq!(cfg.max_input_bytes, 4096),
            _ => panic!("Expected Run"),
        }

        assert!(parse_args(vec!["--max-size=0"]).is_err());

        assert_eq!(compute_max_output_bytes(1024 * 1024), 4 * 1024 * 1024);
        assert_eq!(compute_max_output_bytes(1024), 64 * 1024);
        assert_eq!(
            compute_max_output_bytes(DEFAULT_MAX_INPUT_BYTES),
            DEFAULT_MAX_OUTPUT_BYTES
        );
    }

    #[test]
    fn test_tvek_04_directory_depth_cap() {
        let root = create_temp_test_dir("dir_depth");
        let mut current = root.clone();
        for i in 0..66 {
            current = current.join(format!("d{}", i));
            fs::create_dir_all(&current).unwrap();
        }
        fs::write(current.join("too_deep.json"), b"{}").unwrap();

        let mut files = Vec::new();
        let mut has_io_err = false;
        collect_json_files_in_dir(&root, &mut files, &mut has_io_err);

        assert!(has_io_err, "Expected depth overflow to flag an I/O error");
        assert!(
            files.is_empty(),
            "File beyond MAX_DIR_DEPTH should not be collected"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_imp_02_mutually_exclusive_flags_and_stdin_write_rejection() {
        // Conflicting modes: --lint, --check, --write
        assert!(parse_args(vec!["--lint", "--check", "a.json"]).is_err());
        assert!(parse_args(vec!["--check", "--write", "a.json"]).is_err());
        assert!(parse_args(vec!["-cw", "a.json"]).is_err());
        assert!(parse_args(vec!["-lw", "a.json"]).is_err());

        // Conflicting --minify and --indent
        assert!(parse_args(vec!["--minify", "--indent", "4", "a.json"]).is_err());
        assert!(parse_args(vec!["-m", "-i4", "a.json"]).is_err());

        // --minify with default (implicit) indent is valid
        assert!(parse_args(vec!["--minify", "a.json"]).is_ok());

        // --write with stdin (implicit or explicit '-') is rejected
        assert!(parse_args(vec!["--write"]).is_err());
        assert!(parse_args(vec!["--write", "-"]).is_err());
        assert!(parse_args(vec!["-w", "a.json", "-"]).is_err());
    }

    #[test]
    fn test_imp_03_readonly_target_fails_fast_without_temp_leak() {
        let dir = create_temp_test_dir("readonly_target");
        let target = dir.join("readonly.json");
        fs::write(&target, b"{\"a\":1}").unwrap();

        let mut perms = fs::metadata(&target).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&target, perms.clone()).unwrap();

        let err = write_file_atomically(&target, b"{\n  \"a\": 1\n}\n").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        // Verify no orphaned .tvek_tmp_* files were left behind in `dir`
        let entries: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["readonly.json"]);

        // R-03: Even if a read-only file is already formatted, `process_buffer` in `--write` mode must reject it
        clear_readonly(&mut perms);
        fs::set_permissions(&target, perms.clone()).unwrap();
        let formatted_bytes = b"{\n  \"a\": 1\n}\n";
        fs::write(&target, formatted_bytes).unwrap();
        perms.set_readonly(true);
        fs::set_permissions(&target, perms.clone()).unwrap();

        let cfg = CliConfig {
            write: true,
            quiet: true,
            ..CliConfig::default()
        };
        let lint_err = AtomicBool::new(false);
        let io_err = AtomicBool::new(false);
        process_buffer(
            "readonly.json",
            Some(&target),
            formatted_bytes,
            &cfg,
            &lint_err,
            &io_err,
        );
        assert!(io_err.load(Ordering::Relaxed));

        // Restore write permission for cleanup
        clear_readonly(&mut perms);
        let _ = fs::set_permissions(&target, perms);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_imp_07_parallel_file_batch_processing() {
        let dir = create_temp_test_dir("parallel_batch");
        let mut files = Vec::new();
        for i in 0..8 {
            let p = dir.join(format!("file_{}.json", i));
            fs::write(&p, format!("{{\"b\":{},\"a\":1}}", i)).unwrap();
            files.push(p);
        }

        let cfg = CliConfig {
            check: false,
            lint: false,
            write: true,
            quiet: true,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            format_opts: FormatOptions {
                minify: false,
                indent: 2,
                sort_keys: true,
                allow_comments: true,
            },
            targets: Vec::new(),
        };

        let has_lint_err = AtomicBool::new(false);
        let has_io_err = AtomicBool::new(false);
        process_file_batch(&files, &cfg, &has_lint_err, &has_io_err);

        assert!(!has_lint_err.load(Ordering::Relaxed));
        assert!(!has_io_err.load(Ordering::Relaxed));

        for (i, p) in files.iter().enumerate() {
            let content = String::from_utf8(fs::read(p).unwrap()).unwrap();
            assert_eq!(content, format!("{{\n  \"a\": 1,\n  \"b\": {}\n}}\n", i));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_imp_08_hidden_and_vendor_directory_filtering() {
        let root = create_temp_test_dir("dir_filter");
        let visible_dir = root.join("src");
        let hidden_vscode = root.join(".vscode");
        let dist_dir = root.join("dist");
        let vendor_dir = root.join("vendor");

        fs::create_dir_all(&visible_dir).unwrap();
        fs::create_dir_all(&hidden_vscode).unwrap();
        fs::create_dir_all(&dist_dir).unwrap();
        fs::create_dir_all(&vendor_dir).unwrap();

        let keep_file = visible_dir.join("valid.json");
        fs::write(&keep_file, b"{}").unwrap();
        fs::write(hidden_vscode.join("settings.json"), b"{}").unwrap();
        fs::write(dist_dir.join("bundle.json"), b"{}").unwrap();
        fs::write(vendor_dir.join("pkg.json"), b"{}").unwrap();

        let mut discovered = Vec::new();
        let mut has_io_err = false;
        collect_json_files_in_dir(&root, &mut discovered, &mut has_io_err);

        assert!(!has_io_err);
        assert_eq!(discovered, vec![keep_file]);

        // Explicitly passing the hidden directory `.vscode` as root still processes its files
        let mut explicit_hidden = Vec::new();
        collect_json_files_in_dir(&hidden_vscode, &mut explicit_hidden, &mut has_io_err);
        assert_eq!(explicit_hidden, vec![hidden_vscode.join("settings.json")]);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_tvek_06_deduplicate_aliased_paths_in_parallel_write() {
        let dir = create_temp_test_dir("dedup_parallel");
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        let target = dir.join("shared.json");
        fs::write(&target, b"{\"b\":2,\"a\":1}").unwrap();

        // Pass the same physical file multiple times via exact duplicates and relative `..` aliases
        let alias_via_sub = sub.join("..").join("shared.json");
        let files = vec![
            target.clone(),
            target.clone(),
            alias_via_sub.clone(),
            target.clone(),
        ];

        let deduped = deduplicate_files(&files);
        assert_eq!(deduped.len(), 1);

        let cfg = CliConfig {
            check: false,
            lint: false,
            write: true,
            quiet: true,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            format_opts: FormatOptions {
                minify: false,
                indent: 2,
                sort_keys: true,
                allow_comments: true,
            },
            targets: Vec::new(),
        };

        let has_lint_err = AtomicBool::new(false);
        let has_io_err = AtomicBool::new(false);
        process_file_batch(&files, &cfg, &has_lint_err, &has_io_err);

        assert!(!has_lint_err.load(Ordering::Relaxed));
        assert!(!has_io_err.load(Ordering::Relaxed));
        assert_eq!(
            String::from_utf8(fs::read(&target).unwrap()).unwrap(),
            "{\n  \"a\": 1,\n  \"b\": 2\n}\n"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tvek_07_non_regular_file_rejected_and_discovery_cap() {
        let dir = create_temp_test_dir("discovery_cap");
        for i in 0..5 {
            fs::write(dir.join(format!("f{}.json", i)), b"{}").unwrap();
        }

        // Passing a directory to read_file_bounded must be rejected as not a regular file
        let dir_err = read_file_bounded(&dir, 1024).unwrap_err();
        assert!(
            dir_err.kind() == io::ErrorKind::InvalidInput
                || dir_err.kind() == io::ErrorKind::PermissionDenied
        );

        // Verify discovery cap stops at `max_files = 3` and flags `has_io_err`
        let mut discovered = Vec::new();
        let mut has_io_err = false;
        collect_json_files_in_dir_with_limit(&dir, &mut discovered, 3, &mut has_io_err);
        assert!(has_io_err);
        assert_eq!(discovered.len(), 3);

        // Verify per-directory entry cap stops if a single directory has > max_files * 2 non-JSON entries
        for i in 0..5 {
            fs::write(dir.join(format!("non_json_{}.txt", i)), b"text").unwrap();
        }
        let mut discovered_entry_cap = Vec::new();
        let mut entry_cap_err = false;
        collect_json_files_in_dir_with_limit(
            &dir,
            &mut discovered_entry_cap,
            3,
            &mut entry_cap_err,
        );
        assert!(entry_cap_err);
        assert!(discovered_entry_cap.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cli_server_subcommand_and_flag_validation() {
        assert_eq!(
            parse_args(vec!["server"]).unwrap(),
            ParseAction::Server(LspConfig::default())
        );
        assert_eq!(
            parse_args(vec!["--lsp"]).unwrap(),
            ParseAction::Server(LspConfig::default())
        );
        assert_eq!(
            parse_args(vec![
                "server",
                "--sort-keys",
                "--minify",
                "--strict",
                "--max-size=65536"
            ])
            .unwrap(),
            ParseAction::Server(LspConfig {
                sort_keys: true,
                minify: true,
                allow_comments: false,
                max_input_bytes: 65536,
            })
        );

        // Invalid flag combinations with server mode must fail with usage error
        assert!(parse_args(vec!["server", "--write"]).is_err());
        assert!(parse_args(vec!["server", "--check"]).is_err());
        assert!(parse_args(vec!["server", "--lint"]).is_err());
        assert!(parse_args(vec!["server", "config.json"]).is_err());
        assert!(parse_args(vec!["--lsp", "-w", "config.json"]).is_err());
    }

    #[test]
    fn test_jsonc_directory_discovery_and_lsp() {
        let dir = create_temp_test_dir("jsonc_discovery");
        let json_path = dir.join("a.json");
        let jsonc_path = dir.join("b.jsonc");
        fs::write(&json_path, b"// comment\n{\"a\": 1}\n").unwrap();
        fs::write(&jsonc_path, b"/* block */\n{\"b\": 2}\n").unwrap();

        let mut discovered = Vec::new();
        let mut has_io_err = false;
        collect_json_files_in_dir(&dir, &mut discovered, &mut has_io_err);
        assert!(!has_io_err);
        assert_eq!(discovered, vec![json_path.clone(), jsonc_path.clone()]);

        // Default mode allows comments in .json and .jsonc
        let default_cfg = CliConfig {
            lint: true,
            quiet: true,
            ..CliConfig::default()
        };
        let lint_err = AtomicBool::new(false);
        let io_err = AtomicBool::new(false);
        process_file_batch(&discovered, &default_cfg, &lint_err, &io_err);
        assert!(!lint_err.load(Ordering::Relaxed));
        assert!(!io_err.load(Ordering::Relaxed));

        // --strict (--no-comments) rejects comments
        let act = parse_args(vec!["--lint", "--strict", "b.jsonc"]).unwrap();
        match act {
            ParseAction::Run(strict_cfg) => {
                assert!(!strict_cfg.format_opts.allow_comments);
                let strict_lint_err = AtomicBool::new(false);
                process_file_batch(&discovered, &strict_cfg, &strict_lint_err, &io_err);
                assert!(strict_lint_err.load(Ordering::Relaxed));
            }
            _ => panic!("Expected Run"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tvek_18_windows_drive_prefix_and_parent_cached_dedup() {
        // 1. Verify normalize_path_lexical preserves Windows drive/UNC prefixes across RootDir
        #[cfg(windows)]
        {
            let p_c = normalize_path_lexical(Path::new(r"C:\project\a.json"), None);
            let p_d = normalize_path_lexical(Path::new(r"D:\project\a.json"), None);
            assert_ne!(p_c, p_d);
            assert_eq!(p_c, PathBuf::from(r"C:\project\a.json"));
            assert_eq!(p_d, PathBuf::from(r"D:\project\a.json"));
        }

        // 2. Verify deduplicate_files resolves aliased parent paths even when batch exceeds 64 files
        let dir = create_temp_test_dir("tvek_18_large_batch");
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();

        let mut files = Vec::new();
        for i in 0..70 {
            let p = dir.join(format!("file_{:02}.json", i));
            fs::write(&p, b"{\"a\":1}\n").unwrap();
            files.push(p);
        }
        // Add an alias via `sub/..` to `file_00.json` inside a batch > 64 files
        files.push(sub.join("..").join("file_00.json"));
        #[cfg(any(windows, target_os = "macos"))]
        {
            files.push(dir.join("FILE_00.JSON"));
        }

        let deduped = deduplicate_files(&files);
        assert_eq!(deduped.len(), 70);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_worker_buffers_reuse_and_shrink_cap() {
        let mut buffers = WorkerBuffers::new();
        assert!(buffers.input.capacity() >= 64 * 1024);
        assert!(buffers.output.capacity() >= 64 * 1024);

        // 1. Normal buffer (<= 4 MiB) retains its allocated capacity across files
        buffers.input.resize(512 * 1024, b' ');
        buffers.output.resize(512 * 1024, b' ');
        let retained_in_cap = buffers.input.capacity();
        let retained_out_cap = buffers.output.capacity();
        buffers.reset_after_file();
        assert!(buffers.input.is_empty());
        assert!(buffers.output.is_empty());
        assert_eq!(buffers.input.capacity(), retained_in_cap);
        assert_eq!(buffers.output.capacity(), retained_out_cap);

        // 2. Oversized buffer (> 4 MiB) shrinks back to SHRINK_TARGET_CAPACITY (256 KiB)
        buffers
            .input
            .reserve(MAX_RETAINED_WORKER_BUF_CAPACITY + 1024 * 1024);
        buffers
            .output
            .reserve(MAX_RETAINED_WORKER_BUF_CAPACITY + 1024 * 1024);
        assert!(buffers.input.capacity() > MAX_RETAINED_WORKER_BUF_CAPACITY);
        assert!(buffers.output.capacity() > MAX_RETAINED_WORKER_BUF_CAPACITY);

        buffers.reset_after_file();
        assert!(buffers.input.capacity() <= MAX_RETAINED_WORKER_BUF_CAPACITY);
        assert!(buffers.input.capacity() >= SHRINK_TARGET_CAPACITY);
        assert!(buffers.output.capacity() <= MAX_RETAINED_WORKER_BUF_CAPACITY);
        assert!(buffers.output.capacity() >= SHRINK_TARGET_CAPACITY);
    }
}
