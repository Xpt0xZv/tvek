use std::fmt;

pub const MAX_SNIPPET_CHARS: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxError {
    pub message: String,
    pub offset: usize,
    pub line: usize,
    pub col: usize,
}

/// Returns true if `ch` is an unsafe terminal control, format, separator, or bidirectional
/// override character (CWE-150 / CWE-116: ANSI/OSC escape injection, Trojan Source BiDi spoofing,
/// Zl/Zp line-separator injection, and zero-width format characters — TVEK-05 / TVEK-09).
#[inline]
pub fn is_unsafe_terminal_char(ch: char, allow_tab: bool) -> bool {
    if allow_tab && ch == '\t' {
        return false;
    }
    if ch.is_control() {
        return true;
    }
    matches!(
        ch,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

/// Sanitizes untrusted text before printing to stderr by replacing control characters
/// and Unicode BiDi overrides with `\u{FFFD}` (``), preserving 1-to-1 character column width.
pub fn sanitize_for_terminal(input: &str, allow_tab: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if is_unsafe_terminal_char(ch, allow_tab) {
            out.push('\u{FFFD}');
        } else {
            out.push(ch);
        }
    }
    out
}

impl SyntaxError {
    pub fn new(message: impl Into<String>, offset: usize, input: &[u8]) -> Self {
        let mut cursor = LineColCursor::new(input);
        cursor.resolve(message, offset)
    }

    /// Resolves `(line, col)` in-place for a slice of `SyntaxError`s in a single linear $O(N)$
    /// pass over `input` using [`LineColCursor`] (TVEK-21).
    pub fn resolve_in_place(diags: &mut [SyntaxError], input: &[u8]) {
        if diags.is_empty() {
            return;
        }
        if diags.len() == 1 {
            let mut cursor = LineColCursor::new(input);
            let (clamped, line, col) = cursor.position_at(diags[0].offset);
            diags[0].offset = clamped;
            diags[0].line = line;
            diags[0].col = col;
            return;
        }

        // Sort indices by offset so the cursor advances strictly monotonically in O(N) total time
        let mut indices: Vec<usize> = (0..diags.len()).collect();
        indices.sort_by_key(|&idx| diags[idx].offset);

        let mut cursor = LineColCursor::new(input);
        for idx in indices {
            let (clamped, line, col) = cursor.position_at(diags[idx].offset);
            diags[idx].offset = clamped;
            diags[idx].line = line;
            diags[idx].col = col;
        }
    }

    pub fn format_diagnostic(&self, filename: &str, input: &[u8]) -> String {
        const MAX_WINDOW_SCAN_BYTES: usize = 1024;

        let clamped = self.offset.min(input.len());
        let back_search_start = clamped.saturating_sub(MAX_WINDOW_SCAN_BYTES);
        let (prefix_start, is_exact_line_start) = match input[back_search_start..clamped]
            .iter()
            .rposition(|&b| b == b'\n')
        {
            Some(rel_pos) => (back_search_start + rel_pos + 1, true),
            None if back_search_start == 0 => (0, true),
            None => {
                let mut start = back_search_start;
                while start < clamped && (input[start] & 0xC0) == 0x80 {
                    start += 1;
                }
                (start, false)
            }
        };

        // Search forward up to MAX_WINDOW_SCAN_BYTES for `\n`, stripping a single trailing `\r`
        // from `\r\n` so bare `\r` bytes earlier on the line do not truncate the snippet (IMP-01 / TVEK-21).
        let fwd_search_end = (clamped + MAX_WINDOW_SCAN_BYTES).min(input.len());
        let line_end = match input[clamped..fwd_search_end]
            .iter()
            .position(|&b| b == b'\n')
        {
            Some(rel_pos) => {
                let line_end_nl = clamped + rel_pos;
                if line_end_nl > prefix_start && input[line_end_nl - 1] == b'\r' {
                    line_end_nl - 1
                } else {
                    line_end_nl
                }
            }
            None => fwd_search_end,
        };

        let raw_line = &input[prefix_start..line_end];
        let safe_filename = sanitize_for_terminal(filename, false);
        let safe_message = sanitize_for_terminal(&self.message, false);

        // Window long lines around `target_idx` in O(MAX_WINDOW_SCAN_BYTES) time so even huge
        // single-line inputs with 50 diagnostics never rescan the full line (IMP-01 / R-01 / TVEK-21).
        let target_idx = if is_exact_line_start {
            self.col.saturating_sub(1)
        } else {
            let col_end = if clamped > prefix_start
                && input[clamped - 1] == b'\r'
                && input.get(clamped) == Some(&b'\n')
            {
                clamped - 1
            } else {
                clamped
            };
            count_utf8_chunk_chars(&input[prefix_start..col_end])
        };
        let (rendered_line, caret_pad) = window_and_sanitize_line(raw_line, target_idx);

        let line_num_str = self.line.to_string();
        let gutter_pad = " ".repeat(line_num_str.len());

        format!(
            "error: {}\n{}--> {}:{}:{}\n{} |\n{} | {}\n{} | {}^",
            safe_message,
            gutter_pad,
            safe_filename,
            self.line,
            self.col,
            gutter_pad,
            line_num_str,
            rendered_line,
            gutter_pad,
            caret_pad
        )
    }
}

fn count_utf8_chunk_chars(slice: &[u8]) -> usize {
    if slice.is_ascii() {
        return slice.len();
    }
    let mut count = 0usize;
    for chunk in slice.utf8_chunks() {
        count += chunk.valid().chars().count();
        if !chunk.invalid().is_empty() {
            count += 1;
        }
    }
    count
}

/// Stateful monotonic `(line, col)` cursor using 8-byte SWAR newline counting and incremental
/// same-line column accumulation so multi-diagnostic resolution runs in $O(N)$ total time (TVEK-21).
pub struct LineColCursor<'a> {
    input: &'a [u8],
    cur_offset: usize,
    cur_line: usize,
    cur_line_start: usize,
    cur_col_offset: usize,
    cur_col: usize,
}

impl<'a> LineColCursor<'a> {
    #[inline]
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            cur_offset: 0,
            cur_line: 1,
            cur_line_start: 0,
            cur_col_offset: 0,
            cur_col: 1,
        }
    }

    #[inline]
    pub fn resolve(&mut self, message: impl Into<String>, offset: usize) -> SyntaxError {
        let (clamped, line, col) = self.position_at(offset);
        SyntaxError {
            message: message.into(),
            offset: clamped,
            line,
            col,
        }
    }

    pub fn position_at(&mut self, offset: usize) -> (usize, usize, usize) {
        let clamped = offset.min(self.input.len());
        if clamped < self.cur_offset {
            self.cur_offset = 0;
            self.cur_line = 1;
            self.cur_line_start = 0;
            self.cur_col_offset = 0;
            self.cur_col = 1;
        }

        if clamped > self.cur_offset {
            let delta = &self.input[self.cur_offset..clamped];
            let mut nl_count = 0usize;
            let mut i = 0usize;
            while i + 8 <= delta.len() {
                let chunk = u64::from_ne_bytes(delta[i..i + 8].try_into().unwrap());
                let x = chunk ^ 0x0A0A_0A0A_0A0A_0A0A;
                let mask = x.wrapping_sub(0x0101_0101_0101_0101) & !x & 0x8080_8080_8080_8080;
                if mask != 0 {
                    nl_count += mask.count_ones() as usize;
                }
                i += 8;
            }
            while i < delta.len() {
                if delta[i] == b'\n' {
                    nl_count += 1;
                }
                i += 1;
            }

            if nl_count > 0 {
                self.cur_line += nl_count;
                let last_nl_rel = delta.iter().rposition(|&b| b == b'\n').unwrap();
                self.cur_line_start = self.cur_offset + last_nl_rel + 1;
                self.cur_col_offset = self.cur_line_start;
                self.cur_col = 1;
            }
            self.cur_offset = clamped;
        }

        // Exclude a trailing CR only if it is immediately part of a CRLF pair at `clamped`
        let col_end = if clamped > self.cur_line_start
            && self.input[clamped - 1] == b'\r'
            && self.input.get(clamped) == Some(&b'\n')
        {
            clamped - 1
        } else {
            clamped
        };

        if col_end < self.cur_col_offset {
            self.cur_col_offset = self.cur_line_start;
            self.cur_col = 1;
        }

        let col_slice = &self.input[self.cur_col_offset..col_end];
        if col_slice.is_ascii() {
            self.cur_col += col_slice.len();
            self.cur_col_offset = col_end;
            return (clamped, self.cur_line, self.cur_col);
        }

        // `chunk.valid()` is guaranteed to consist of complete UTF-8 codepoints. Only a trailing
        // `chunk.invalid()` right at `col_end` could be an incomplete prefix of a multi-byte
        // codepoint split by `col_end`, so we commit all valid chunks and all non-trailing invalid
        // chunks immediately (TVEK-21).
        let mut committed_bytes = 0usize;
        let mut extra_col = 0usize;

        for chunk in col_slice.utf8_chunks() {
            let valid_str = chunk.valid();
            if !valid_str.is_empty() {
                self.cur_col += valid_str.chars().count();
                committed_bytes += valid_str.len();
            }
            let invalid_bytes = chunk.invalid();
            if !invalid_bytes.is_empty() {
                if committed_bytes + invalid_bytes.len() < col_slice.len() {
                    self.cur_col += 1;
                    committed_bytes += invalid_bytes.len();
                } else {
                    extra_col += 1;
                }
            }
        }
        self.cur_col_offset += committed_bytes;

        (clamped, self.cur_line, self.cur_col + extra_col)
    }
}

fn window_and_sanitize_line(raw_line: &[u8], target_idx: usize) -> (String, String) {
    let half = MAX_SNIPPET_CHARS / 2;
    let win_start = target_idx.saturating_sub(half);

    // Stream via `.utf8_chunks()` and only collect characters up to `win_start + MAX_SNIPPET_CHARS + 1`
    // so we never allocate a full-line String or Vec<char> on huge single-line inputs (R-01).
    let mut window_chars: Vec<char> = Vec::with_capacity(MAX_SNIPPET_CHARS + 2);
    let mut total_seen = 0usize;
    let mut has_trailing_chars = false;

    'chunks: for chunk in raw_line.utf8_chunks() {
        for raw_ch in chunk.valid().chars() {
            let safe_ch = if is_unsafe_terminal_char(raw_ch, true) {
                '\u{FFFD}'
            } else {
                raw_ch
            };
            if total_seen >= win_start {
                if window_chars.len() < MAX_SNIPPET_CHARS {
                    window_chars.push(safe_ch);
                } else {
                    has_trailing_chars = true;
                    break 'chunks;
                }
            }
            total_seen += 1;
        }

        if !chunk.invalid().is_empty() {
            if total_seen >= win_start {
                if window_chars.len() < MAX_SNIPPET_CHARS {
                    window_chars.push('\u{FFFD}');
                } else {
                    has_trailing_chars = true;
                    break 'chunks;
                }
            }
            total_seen += 1;
        }
    }

    let has_leading_chars = win_start > 0;
    let caret_in_window = target_idx.saturating_sub(win_start).min(window_chars.len());

    let mut rendered_line = String::with_capacity(window_chars.len() + 6);
    let mut caret_pad = String::with_capacity(caret_in_window + 3);

    if has_leading_chars {
        rendered_line.push_str("...");
        caret_pad.push_str("   ");
    }

    for (i, &ch) in window_chars.iter().enumerate() {
        rendered_line.push(ch);
        if i < caret_in_window {
            if ch == '\t' {
                caret_pad.push('\t');
            } else {
                caret_pad.push(' ');
            }
        }
    }

    if has_trailing_chars {
        rendered_line.push_str("...");
    }

    (rendered_line, caret_pad)
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (at line {}, column {}, byte {})",
            sanitize_for_terminal(&self.message, false),
            self.line,
            self.col,
            self.offset
        )
    }
}

impl std::error::Error for SyntaxError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tvek_05_terminal_escape_and_bidi_sanitization() {
        let malicious_input = "{\"key\": \"\x1b[31m\x07\u{009B}\u{202E}\",}";
        let err = SyntaxError::new(
            "Trailing comma is not allowed in JSON object",
            malicious_input.len() - 1,
            malicious_input.as_bytes(),
        );
        let malicious_filename = "evil\x1b]0;pwned\x07\u{202E}.json";
        let diag = err.format_diagnostic(malicious_filename, malicious_input.as_bytes());

        assert!(!diag.contains('\x1b'));
        assert!(!diag.contains('\x07'));
        assert!(!diag.contains('\u{009B}'));
        assert!(!diag.contains('\u{202E}'));
        assert!(diag.contains('\u{FFFD}'));
    }

    #[test]
    fn test_imp_01_bare_cr_does_not_truncate_line() {
        // Bare \r inside the line before the offending trailing comma at index 17
        let input = b"{\"a\": 1,\r \"b\": 2,}";
        let comma_offset = 16;
        let err = SyntaxError::new(
            "Trailing comma is not allowed in JSON object",
            comma_offset,
            input,
        );
        let diag = err.format_diagnostic("test.json", input);
        let lines: Vec<&str> = diag.lines().collect();

        // Line 4 is `1 | {"a": 1, "b": 2,}` and Line 5 is `  |                 ^`
        assert!(lines[3].contains("\"b\": 2,}"));
        let snippet_prefix = "1 | ";
        let caret_prefix = "  | ";
        let comma_char_pos = lines[3][snippet_prefix.len()..]
            .chars()
            .position(|c| c == '2')
            .unwrap()
            + 1;
        let caret_char_pos = lines[4][caret_prefix.len()..]
            .chars()
            .position(|c| c == '^')
            .unwrap();
        assert_eq!(comma_char_pos, caret_char_pos);
    }

    #[test]
    fn test_imp_01_invalid_utf8_column_alignment() {
        // Invalid UTF-8 sequences (0xFF, 0xFE) before a syntax error on the same line
        let input = b"{\"a\": \"\xFF\xFE\", !}";
        let bang_offset = 12;
        let err = SyntaxError::new("Unexpected token", bang_offset, input);
        let diag = err.format_diagnostic("bad_utf8.json", input);
        let lines: Vec<&str> = diag.lines().collect();

        let snippet_char_pos = lines[3]["1 | ".len()..]
            .chars()
            .position(|c| c == '!')
            .unwrap();
        let caret_char_pos = lines[4]["  | ".len()..]
            .chars()
            .position(|c| c == '^')
            .unwrap();
        assert_eq!(snippet_char_pos, caret_char_pos);
    }

    #[test]
    fn test_imp_01_long_minified_line_windowing() {
        let mut long_line = String::from("{\"data\":\"");
        for _ in 0..500 {
            long_line.push('a');
        }
        long_line.push_str("\",}");
        let comma_offset = long_line.len() - 2;

        let err = SyntaxError::new(
            "Trailing comma is not allowed in JSON object",
            comma_offset,
            long_line.as_bytes(),
        );
        let diag = err.format_diagnostic("minified.json", long_line.as_bytes());
        let lines: Vec<&str> = diag.lines().collect();

        // Snippet line must be windowed with leading "..." and bounded length
        let snippet = &lines[3]["1 | ".len()..];
        assert!(snippet.starts_with("..."));
        assert!(snippet.chars().count() <= MAX_SNIPPET_CHARS + 6);

        let comma_pos = snippet
            .chars()
            .enumerate()
            .filter(|&(_, c)| c == ',')
            .last()
            .unwrap()
            .0;
        let caret_pos = lines[4]["  | ".len()..]
            .chars()
            .position(|c| c == '^')
            .unwrap();
        assert_eq!(comma_pos, caret_pos);
    }

    #[test]
    fn test_tvek_09_unicode_format_and_separator_sanitization() {
        // Test Zl/Zp (U+2028, U+2029) and zero-width format characters (U+200B, U+200D, U+2060, U+FEFF, U+FFF9..=U+FFFB)
        let input = "{\"k\": \"a\u{2028}b\u{2029}c\u{200B}d\u{200D}e\u{2060}f\u{FEFF}g\u{FFF9}h\u{FFFB}\",}";
        let comma_offset = input.len() - 2;
        let err = SyntaxError::new(
            "Trailing comma is not allowed in JSON object",
            comma_offset,
            input.as_bytes(),
        );
        let diag = err.format_diagnostic("bad\u{2028}\u{200B}name.json", input.as_bytes());

        for forbidden in [
            '\u{2028}', '\u{2029}', '\u{200B}', '\u{200D}', '\u{2060}', '\u{FEFF}', '\u{FFF9}',
            '\u{FFFB}',
        ] {
            assert!(!diag.contains(forbidden));
        }

        // Ensure the diagnostic remains strictly 5 lines (no injected line breaks from U+2028/U+2029)
        let lines: Vec<&str> = diag.lines().collect();
        assert_eq!(lines.len(), 5);
    }

    #[test]
    fn test_tvek_21_non_ascii_cursor_advancement_and_bounded_diagnostic_window() {
        // 1. Verify `LineColCursor::position_at` advances `cur_col_offset` all the way to `col_end`
        // on valid non-ASCII UTF-8 lines instead of staying stuck at `cur_line_start`.
        let mut line = String::from("{\"emoji\":\"🚀\",\"pad\":\"");
        for _ in 0..2500 {
            line.push_str("🚀x");
        }
        let target_offset = line.len();
        line.push_str("\",!,\"tail\":\"");
        for _ in 0..2500 {
            line.push_str("🚀y");
        }
        line.push_str("\"}");

        let bytes = line.as_bytes();
        let mut cursor = LineColCursor::new(bytes);
        let (_, l1, c1) = cursor.position_at(20);
        assert_eq!(l1, 1);
        assert!(c1 > 1);
        assert_eq!(cursor.cur_col_offset, 20);

        let bang_offset = target_offset + 2;
        let (_, l2, c2) = cursor.position_at(bang_offset);
        assert_eq!(l2, 1);
        assert_eq!(cursor.cur_col_offset, bang_offset);

        let single = SyntaxError::new("Unexpected token", bang_offset, bytes);
        assert_eq!((l2, c2), (single.line, single.col));

        // 2. Verify `format_diagnostic` bounded window (> 1024 bytes before and after `bang_offset`)
        // aligns the caret with `!` and includes both leading and trailing `...` ellipses.
        let diag = single.format_diagnostic("huge_non_ascii.json", bytes);
        let diag_lines: Vec<&str> = diag.lines().collect();
        let snippet = &diag_lines[3]["1 | ".len()..];
        assert!(snippet.starts_with("..."));
        assert!(snippet.ends_with("..."));

        let bang_char_pos = snippet.chars().position(|c| c == '!').unwrap();
        let caret_char_pos = diag_lines[4]["  | ".len()..]
            .chars()
            .position(|c| c == '^')
            .unwrap();
        assert_eq!(bang_char_pos, caret_char_pos);
    }
}
