use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tvek::{format_json, lint_json, FormatOptions, DEFAULT_LINE_WIDTH};

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn create_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as u64;
    let dir = env::temp_dir().join(format!("tvek_integ_{}_{}_{:x}_{}", label, pid, nanos, seq));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Deterministic zero-dependency SplitMix64 PRNG for reproducible property/corpus testing.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn gen_range(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            0
        } else {
            (self.next_u64() as usize) % upper
        }
    }

    fn gen_bool(&mut self, num: usize, den: usize) -> bool {
        self.gen_range(den) < num
    }
}

/// Masks JSON string literals (`"..."` -> `"S"`), line comments (`//...` -> `//L`),
/// and block comment interiors (`/*...*/` -> `/*B*/`) while preserving all structural
/// punctuation, whitespace, indentation, and newlines outside `/* ... */` verbatim.
fn mask_outside_block_interiors(formatted: &str) -> String {
    let bytes = formatted.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                out.push_str("\"S\"");
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 2;
                    } else if bytes[i] == b'"' {
                        i += 1;
                        break;
                    } else {
                        i += 1;
                    }
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                out.push_str("//L");
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                out.push_str("/*B*/");
                i += 2;
                while i + 1 < bytes.len() {
                    if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            b => {
                out.push(b as char);
                i += 1;
            }
        }
    }

    out
}

fn assert_structural_blank_line_invariants(formatted: &str, context: &str) {
    assert!(
        lint_json(formatted.as_bytes()).is_ok(),
        "Formatted output failed lint_json ({}):\n{}",
        context,
        formatted
    );
    assert!(
        formatted.ends_with('\n'),
        "Formatted output must end with trailing newline ({})",
        context
    );
    assert!(
        !formatted.contains('\r'),
        "Formatted output must normalize all CR bytes ({})",
        context
    );

    let masked = mask_outside_block_interiors(formatted);

    // 1. Never emit a leading blank line at top-of-file
    assert!(
        !masked.starts_with('\n'),
        "Leading blank line at top-of-file ({}):\n{}",
        context,
        formatted
    );

    // 2. Zero triple newlines (`\n\n\n`) outside `/* ... */` interiors
    assert!(
        !masked.contains("\n\n\n"),
        "Found triple newline outside /* ... */ interior ({}):\nMasked:\n{}\nFull:\n{}",
        context,
        masked,
        formatted
    );

    // 3. Zero whitespace-only lines outside `/* ... */` interiors
    for (line_idx, line) in masked.split('\n').enumerate() {
        if line.trim().is_empty() {
            assert!(
                line.is_empty(),
                "Whitespace-only blank line {:?} at line {} ({}):\n{}",
                line,
                line_idx + 1,
                context,
                formatted
            );
        }
    }

    // 4. Never emit a blank line immediately after `{` or `[` (with or without open inline comments)
    for forbidden in [
        "{\n\n",
        "[\n\n",
        "{ //L\n\n",
        "[ //L\n\n",
        "{ /*B*/\n\n",
        "[ /*B*/\n\n",
    ] {
        assert!(
            !masked.contains(forbidden),
            "Forbidden blank line after container open {:?} ({}):\n{}",
            forbidden,
            context,
            formatted
        );
    }
}

fn random_nl(rng: &mut SplitMix64) -> &'static str {
    if rng.gen_bool(1, 4) {
        "\r\n"
    } else {
        "\n"
    }
}

fn random_ws(rng: &mut SplitMix64) -> &'static str {
    match rng.gen_range(5) {
        0 => "",
        1 => " ",
        2 => "   ",
        3 => "\t",
        _ => " \t ",
    }
}

fn push_standalone_comment_group(
    rng: &mut SplitMix64,
    out: &mut String,
    max_count: usize,
    tag: usize,
) {
    let count = rng.gen_range(max_count + 1);
    for idx in 0..count {
        let nl = random_nl(rng);
        // Randomly inject 1..=3 newlines + arbitrary indentation before/between comments
        let extra_nls = 1 + rng.gen_range(3);
        for _ in 0..extra_nls {
            out.push_str(random_ws(rng));
            out.push_str(nl);
        }
        out.push_str(random_ws(rng));
        match rng.gen_range(4) {
            0 => {
                out.push_str(&format!("// s_{}_{}", tag, idx));
                out.push_str(nl);
            }
            1 => {
                out.push_str(&format!("/* b_{}_{} */", tag, idx));
                if rng.gen_bool(1, 2) {
                    out.push_str(nl);
                }
            }
            2 => {
                // Multiline block comment with internal blank lines that MUST be preserved
                out.push_str(&format!(
                    "/* m_{}_{}_p1{}{}{}   m_{}_{}_p2 */",
                    tag, idx, nl, nl, nl, tag, idx
                ));
                out.push_str(nl);
            }
            _ => {
                out.push_str(&format!("// unicode_🚀_{}_{}", tag, idx));
                out.push_str(nl);
            }
        }
    }
}

fn push_optional_inline_comment(
    rng: &mut SplitMix64,
    out: &mut String,
    allow_line_comment: bool,
    tag: usize,
) -> bool {
    if !rng.gen_bool(2, 5) {
        return false;
    }
    out.push_str(random_ws(rng));
    let choice = if allow_line_comment {
        rng.gen_range(4)
    } else {
        rng.gen_range(2)
    };
    match choice {
        0 => {
            out.push_str(&format!("/* in_{} */", tag));
            if rng.gen_bool(1, 3) {
                out.push(' ');
                out.push_str(&format!("/* in2_{} */", tag));
            }
            false
        }
        1 => {
            let nl = random_nl(rng);
            out.push_str(&format!("/* in_multi_{}_1{}in_multi_{}_2 */", tag, nl, tag));
            true
        }
        _ => {
            let nl = random_nl(rng);
            out.push_str(&format!("// in_line_{}{}", tag, nl));
            true
        }
    }
}

fn generate_random_jsonc_value(
    rng: &mut SplitMix64,
    out: &mut String,
    depth: usize,
    allow_trailing_commas: bool,
    seq: &mut usize,
) {
    *seq += 1;
    let my_tag = *seq;

    let kind = if depth >= 3 {
        rng.gen_range(5) // primitives or empty containers
    } else {
        rng.gen_range(9)
    };

    match kind {
        0 => out.push_str("true"),
        1 => out.push_str("false"),
        2 => out.push_str("null"),
        3 => {
            let nums = ["0", "-0", "42", "-19.75", "1e10", "3.14159e-2"];
            out.push_str(nums[rng.gen_range(nums.len())]);
        }
        4 => {
            let strs = [
                "\"alpha\"",
                "\"/* not a comment */\"",
                "\"// also not a comment\"",
                "\"line\\n\\nbreak\"",
                "\"emoji_🦀\"",
            ];
            out.push_str(strs[rng.gen_range(strs.len())]);
        }
        5 => {
            // Empty object `{}` (with or without comments)
            out.push('{');
            if rng.gen_bool(1, 2) {
                let _ = push_optional_inline_comment(rng, out, true, my_tag);
            }
            push_standalone_comment_group(rng, out, 2, my_tag + 100);
            out.push_str(random_ws(rng));
            out.push('}');
        }
        6 => {
            // Empty array `[]` (with or without comments)
            out.push('[');
            if rng.gen_bool(1, 2) {
                let _ = push_optional_inline_comment(rng, out, true, my_tag);
            }
            push_standalone_comment_group(rng, out, 2, my_tag + 200);
            out.push_str(random_ws(rng));
            out.push(']');
        }
        7 => {
            // Non-empty Object with unsorted + escaped keys and comments in all grammar slots
            out.push('{');
            let _ = push_optional_inline_comment(rng, out, true, my_tag);
            push_standalone_comment_group(rng, out, 2, my_tag + 300);

            let key_pool = [
                "\"z_last\"",
                "\"a_first\"",
                "\"\\u0062_escaped\"",
                "\"m_mid\"",
                "\"d_item\"",
            ];
            let count = 1 + rng.gen_range(4);
            // Pick distinct keys from key_pool rotated by `my_tag`
            for idx in 0..count {
                if idx > 0 {
                    // Trivia before `,`
                    let ended_with_nl = push_optional_inline_comment(rng, out, true, my_tag + idx);
                    push_standalone_comment_group(rng, out, 2, my_tag + idx * 17);
                    out.push_str(random_ws(rng));
                    out.push(',');
                    // Trivia after `,`
                    if !ended_with_nl {
                        let _ = push_optional_inline_comment(rng, out, true, my_tag + idx + 50);
                    }
                    push_standalone_comment_group(rng, out, 2, my_tag + idx * 31);
                }
                out.push_str(random_ws(rng));
                let key_lit = key_pool[(my_tag + idx * 2) % key_pool.len()];
                out.push_str(key_lit);

                // Optional comment between key and `:`
                if rng.gen_bool(1, 3) {
                    out.push_str(" /* pre_colon */ ");
                }
                if rng.gen_bool(1, 5) {
                    push_standalone_comment_group(rng, out, 1, my_tag + idx + 70);
                }
                out.push(':');
                // Optional comment after `:`
                if rng.gen_bool(1, 3) {
                    out.push_str(" /* post_colon */ ");
                }
                if rng.gen_bool(1, 5) {
                    push_standalone_comment_group(rng, out, 1, my_tag + idx + 90);
                }
                out.push_str(random_ws(rng));

                generate_random_jsonc_value(rng, out, depth + 1, allow_trailing_commas, seq);
            }

            if allow_trailing_commas && rng.gen_bool(3, 5) {
                let ended_with_nl = push_optional_inline_comment(rng, out, true, my_tag + 400);
                push_standalone_comment_group(rng, out, 2, my_tag + 401);
                out.push(',');
                if !ended_with_nl {
                    let _ = push_optional_inline_comment(rng, out, true, my_tag + 402);
                }
                push_standalone_comment_group(rng, out, 2, my_tag + 403);
            } else {
                let _ = push_optional_inline_comment(rng, out, true, my_tag + 404);
                push_standalone_comment_group(rng, out, 2, my_tag + 405);
            }

            if !out.ends_with('\n') && rng.gen_bool(1, 2) {
                out.push_str(random_nl(rng));
            }
            out.push_str(random_ws(rng));
            out.push('}');
        }
        _ => {
            // Non-empty Array: half of the time generate a clean scalar array (inline candidate),
            // half of the time inject rich comments/nested values
            if rng.gen_bool(1, 3) {
                out.push('[');
                let len = 1 + rng.gen_range(4);
                for idx in 0..len {
                    if idx > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&format!("{}", idx + 1));
                }
                if allow_trailing_commas && rng.gen_bool(1, 2) {
                    out.push(',');
                }
                out.push(']');
            } else {
                out.push('[');
                let _ = push_optional_inline_comment(rng, out, true, my_tag + 500);
                push_standalone_comment_group(rng, out, 2, my_tag + 501);

                let count = 1 + rng.gen_range(4);
                for idx in 0..count {
                    if idx > 0 {
                        let ended_with_nl =
                            push_optional_inline_comment(rng, out, true, my_tag + 510 + idx);
                        push_standalone_comment_group(rng, out, 2, my_tag + 520 + idx);
                        out.push(',');
                        if !ended_with_nl {
                            let _ =
                                push_optional_inline_comment(rng, out, true, my_tag + 530 + idx);
                        }
                        push_standalone_comment_group(rng, out, 2, my_tag + 540 + idx);
                    }
                    out.push_str(random_ws(rng));
                    generate_random_jsonc_value(rng, out, depth + 1, allow_trailing_commas, seq);
                }

                if allow_trailing_commas && rng.gen_bool(3, 5) {
                    let ended_with_nl = push_optional_inline_comment(rng, out, true, my_tag + 550);
                    push_standalone_comment_group(rng, out, 2, my_tag + 551);
                    out.push(',');
                    if !ended_with_nl {
                        let _ = push_optional_inline_comment(rng, out, true, my_tag + 552);
                    }
                    push_standalone_comment_group(rng, out, 2, my_tag + 553);
                } else {
                    let _ = push_optional_inline_comment(rng, out, true, my_tag + 554);
                    push_standalone_comment_group(rng, out, 2, my_tag + 555);
                }

                if !out.ends_with('\n') && rng.gen_bool(1, 2) {
                    out.push_str(random_nl(rng));
                }
                out.push_str(random_ws(rng));
                out.push(']');
            }
        }
    }
}

fn generate_random_jsonc_document(rng: &mut SplitMix64, allow_fix_syntax: bool) -> String {
    let mut doc = String::with_capacity(512);
    let mut seq = 0usize;

    if allow_fix_syntax && rng.gen_bool(1, 4) {
        doc.push('\u{FEFF}');
    }

    // Root leading comments (including pre-existing blank lines that must collapse)
    if rng.gen_bool(3, 5) {
        if rng.gen_bool(1, 2) {
            doc.push_str("// root_header_0");
            doc.push_str(random_nl(rng));
        }
        push_standalone_comment_group(rng, &mut doc, 3, 1);
    }

    doc.push_str(random_ws(rng));
    generate_random_jsonc_value(rng, &mut doc, 0, allow_fix_syntax, &mut seq);

    // Root trailing inline + standalone EOF comments
    let _ = push_optional_inline_comment(rng, &mut doc, true, 9000);
    push_standalone_comment_group(rng, &mut doc, 3, 9001);

    doc
}

#[test]
fn test_randomized_combinatorial_jsonc_comment_corpus_invariants() {
    let mut rng = SplitMix64::new(0x5EED_C0DE_2026_1115);

    let profiles = [
        (2usize, DEFAULT_LINE_WIDTH),
        (4usize, DEFAULT_LINE_WIDTH),
        (0usize, DEFAULT_LINE_WIDTH), // tabs
        (2usize, 0usize),             // --structural
    ];

    // Part 1: 1,200 valid JSONC documents across all 4 formatting profiles (4,800 runs)
    for case_idx in 0..1200 {
        let doc = generate_random_jsonc_document(&mut rng, false);
        let profile = profiles[case_idx % profiles.len()];
        let stream_opts = FormatOptions {
            indent: profile.0,
            line_width: profile.1,
            sort_keys: false,
            ..FormatOptions::default()
        };
        let sort_opts = FormatOptions {
            indent: profile.0,
            line_width: profile.1,
            sort_keys: true,
            ..FormatOptions::default()
        };

        let ctx = format!(
            "valid_corpus case={} indent={} width={}",
            case_idx, profile.0, profile.1
        );

        let f1 = String::from_utf8(
            format_json(doc.as_bytes(), &stream_opts).unwrap_or_else(|e| {
                panic!("Stream format failed ({}): {:?}\nDoc:\n{}", ctx, e, doc)
            }),
        )
        .unwrap();
        let f2 = String::from_utf8(format_json(f1.as_bytes(), &stream_opts).unwrap()).unwrap();

        // Invariant (a): Streaming idempotency `format(format(doc)) == format(doc)`
        assert_eq!(
            f2, f1,
            "Streaming idempotency violated ({}):\nDoc:\n{}\nPass 1:\n{}\nPass 2:\n{}",
            ctx, doc, f1, f2
        );

        let s1 =
            String::from_utf8(format_json(doc.as_bytes(), &sort_opts).unwrap_or_else(|e| {
                panic!("Sorted format failed ({}): {:?}\nDoc:\n{}", ctx, e, doc)
            }))
            .unwrap();
        let s2 = String::from_utf8(format_json(s1.as_bytes(), &sort_opts).unwrap()).unwrap();
        let stream_of_s1 =
            String::from_utf8(format_json(s1.as_bytes(), &stream_opts).unwrap()).unwrap();

        // Invariant (b): Sorted idempotency and cross-engine convergence
        assert_eq!(
            s2, s1,
            "Sorted idempotency violated ({}):\nDoc:\n{}\nSorted 1:\n{}\nSorted 2:\n{}",
            ctx, doc, s1, s2
        );
        assert_eq!(
            stream_of_s1, s1,
            "Cross-engine convergence `format(format_sorted(doc)) == format_sorted(doc)` violated ({}):\nDoc:\n{}\nSorted:\n{}\nStream(Sorted):\n{}",
            ctx, doc, s1, stream_of_s1
        );

        // Invariant (c): Zero whitespace-only lines and zero `\n\n\n` outside `/* ... */` interiors
        assert_structural_blank_line_invariants(&f1, &format!("{} [stream]", ctx));
        assert_structural_blank_line_invariants(&s1, &format!("{} [sorted]", ctx));
    }

    // Part 2: 400 `--fix` JSONC documents (BOM + trailing commas + tricky comments)
    for fix_idx in 0..400 {
        let doc = generate_random_jsonc_document(&mut rng, true);
        let profile = profiles[fix_idx % profiles.len()];
        let fix_stream_opts = FormatOptions {
            indent: profile.0,
            line_width: profile.1,
            fix: true,
            sort_keys: false,
            ..FormatOptions::default()
        };
        let plain_stream_opts = FormatOptions {
            indent: profile.0,
            line_width: profile.1,
            fix: false,
            sort_keys: false,
            ..FormatOptions::default()
        };
        let fix_sort_opts = FormatOptions {
            indent: profile.0,
            line_width: profile.1,
            fix: true,
            sort_keys: true,
            ..FormatOptions::default()
        };
        let plain_sort_opts = FormatOptions {
            indent: profile.0,
            line_width: profile.1,
            fix: false,
            sort_keys: true,
            ..FormatOptions::default()
        };

        let ctx = format!(
            "fix_corpus case={} indent={} width={}",
            fix_idx, profile.0, profile.1
        );

        let fixed_stream = String::from_utf8(
            format_json(doc.as_bytes(), &fix_stream_opts)
                .unwrap_or_else(|e| panic!("Fix stream failed ({}): {:?}\nDoc:\n{}", ctx, e, doc)),
        )
        .unwrap();
        let plain_after_fix =
            String::from_utf8(format_json(fixed_stream.as_bytes(), &plain_stream_opts).unwrap())
                .unwrap();
        assert_eq!(
            plain_after_fix, fixed_stream,
            "Post-fix stream drift ({})",
            ctx
        );

        let fixed_sorted = String::from_utf8(
            format_json(doc.as_bytes(), &fix_sort_opts)
                .unwrap_or_else(|e| panic!("Fix sorted failed ({}): {:?}\nDoc:\n{}", ctx, e, doc)),
        )
        .unwrap();
        let plain_sorted_after_fix =
            String::from_utf8(format_json(fixed_sorted.as_bytes(), &plain_sort_opts).unwrap())
                .unwrap();
        let plain_stream_of_fixed_sorted =
            String::from_utf8(format_json(fixed_sorted.as_bytes(), &plain_stream_opts).unwrap())
                .unwrap();
        assert_eq!(
            plain_sorted_after_fix, fixed_sorted,
            "Post-fix sorted drift ({})",
            ctx
        );
        assert_eq!(
            plain_stream_of_fixed_sorted, fixed_sorted,
            "Post-fix cross-engine drift ({})",
            ctx
        );

        assert_structural_blank_line_invariants(&fixed_stream, &format!("{} [fix_stream]", ctx));
        assert_structural_blank_line_invariants(&fixed_sorted, &format!("{} [fix_sorted]", ctx));
    }
}

#[test]
fn test_cli_binary_e2e_check_write_fix_and_sort_keys_exit_codes() {
    let bin = env!("CARGO_BIN_EXE_tvek");
    let dir = create_temp_dir("cli_e2e");

    // 1. Missing blank line above standalone comment -> `tvek --check` exits 1
    let file_missing = dir.join("missing.jsonc");
    let raw_missing =
        "// top\n{\n  \"a\": [1, 2], // inline\n  // standalone\n  \"b\": true\n}\n// eof\n";
    let canonical_missing =
        "// top\n{\n  \"a\": [1, 2], // inline\n\n  // standalone\n  \"b\": true\n}\n\n// eof\n";
    fs::write(&file_missing, raw_missing.as_bytes()).unwrap();

    let status_missing = Command::new(bin)
        .args(["--check", "--quiet"])
        .arg(&file_missing)
        .status()
        .unwrap();
    assert_eq!(status_missing.code(), Some(1));

    // 2. Extra blank line between consecutive `//` comments -> `tvek --check` exits 1
    let file_extra_between = dir.join("extra_between.jsonc");
    fs::write(
        &file_extra_between,
        b"{\n  \"a\": 1,\n\n  // c1\n\n  // c2\n  \"b\": 2\n}\n",
    )
    .unwrap();
    let status_extra = Command::new(bin)
        .args(["--check", "--quiet"])
        .arg(&file_extra_between)
        .status()
        .unwrap();
    assert_eq!(status_extra.code(), Some(1));

    // 3. Extra blank line immediately after `{` -> `tvek --check` exits 1
    let file_after_brace = dir.join("after_brace.jsonc");
    fs::write(
        &file_after_brace,
        b"{\n\n  // first key comment\n  \"a\": 1\n}\n",
    )
    .unwrap();
    let status_after_brace = Command::new(bin)
        .args(["--check", "--quiet"])
        .arg(&file_after_brace)
        .status()
        .unwrap();
    assert_eq!(status_after_brace.code(), Some(1));

    // 4. `tvek --write` formats the directory in-place and exits 0
    let status_write = Command::new(bin)
        .args(["--write", "--quiet"])
        .arg(&dir)
        .status()
        .unwrap();
    assert_eq!(status_write.code(), Some(0));
    assert_eq!(
        fs::read_to_string(&file_missing).unwrap(),
        canonical_missing
    );
    assert_eq!(
        fs::read_to_string(&file_extra_between).unwrap(),
        "{\n  \"a\": 1,\n\n  // c1\n  // c2\n  \"b\": 2\n}\n"
    );
    assert_eq!(
        fs::read_to_string(&file_after_brace).unwrap(),
        "{\n  // first key comment\n  \"a\": 1\n}\n"
    );

    // 5. `tvek --check` now exits 0 on the formatted directory, and repeated `--write` is idempotent
    let status_check_ok = Command::new(bin)
        .args(["--check", "--quiet"])
        .arg(&dir)
        .status()
        .unwrap();
    assert_eq!(status_check_ok.code(), Some(0));

    let status_write_again = Command::new(bin)
        .args(["--write", "--quiet"])
        .arg(&dir)
        .status()
        .unwrap();
    assert_eq!(status_write_again.code(), Some(0));
    assert_eq!(
        fs::read_to_string(&file_missing).unwrap(),
        canonical_missing
    );

    // 6. Stdin `--fix --sort-keys` subprocess pipe test
    let mut child = Command::new(bin)
        .args(["--fix", "--sort-keys"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\n  \"z\": 1,\n  // on a\n  \"a\": [1, 2,], // inline a\n  // footer\n}\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "{\n  // on a\n  \"a\": [1, 2], // inline a\n  \"z\": 1\n\n  // footer\n}\n"
    );

    let _ = fs::remove_dir_all(&dir);
}
