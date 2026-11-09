use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};

use crate::error::sanitize_for_terminal;
use crate::lexer::{
    format_json_with_limit, lint_json_with_limit, FormatOptions, DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_OUTPUT_BYTES,
};

const MAX_HEADER_LINE_BYTES: usize = 4096;
const MAX_HEADERS: usize = 32;
const MAX_OPEN_DOCUMENTS: usize = 1024;
const MAX_URI_BYTES: usize = 4096;
const MAX_TOTAL_DOCUMENT_BYTES: usize = 256 * 1024 * 1024; // 256 MiB aggregate cap across open docs
const MAX_FRAME_PREALLOC_BYTES: usize = 64 * 1024; // 64 KiB cap on initial frame buffer reservation
const MAX_RPC_DEPTH: usize = 32;
const MAX_RPC_NODES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LspConfig {
    pub sort_keys: bool,
    pub minify: bool,
    pub max_input_bytes: usize,
}

impl Default for LspConfig {
    fn default() -> Self {
        Self {
            sort_keys: false,
            minify: false,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
        }
    }
}

/// Runs the LSP server over standard input and standard output.
/// Returns the process exit code (`0` on clean shutdown+exit, `1` on uninitialized exit, `2` on I/O error).
pub fn run_stdio_server(config: LspConfig) -> u8 {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = io::BufWriter::new(stdout.lock());

    match run_server_loop(&mut reader, &mut writer, config) {
        Ok(code) => code,
        Err(e) => {
            let stderr = io::stderr();
            let mut err_lock = stderr.lock();
            let _ = writeln!(
                err_lock,
                "error: LSP server I/O error: {}",
                sanitize_for_terminal(&e.to_string(), false)
            );
            2
        }
    }
}

/// Core LSP message loop parameterized over `BufRead` and `Write` for deterministic unit testing.
pub fn run_server_loop<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    mut config: LspConfig,
) -> io::Result<u8> {
    let host_max_input_bytes = config.max_input_bytes.min(DEFAULT_MAX_INPUT_BYTES);
    config.max_input_bytes = host_max_input_bytes;

    let mut documents: HashMap<String, String> = HashMap::new();
    let mut total_open_bytes: usize = 0;
    let mut initialized = false;
    let mut shutdown_requested = false;

    while let Some(body) = read_lsp_frame(reader, max_frame_size(config.max_input_bytes))? {
        let max_mem = compute_lsp_max_output_bytes(config.max_input_bytes);
        if lint_json_with_limit(&body, max_mem).is_err() {
            let err_resp =
                r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#;
            write_lsp_frame(writer, err_resp)?;
            continue;
        }

        let Some(msg) = parse_rpc_value(&body) else {
            let err_resp =
                r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#;
            write_lsp_frame(writer, err_resp)?;
            continue;
        };

        let id_raw = msg.get_field("id").map(serialize_rpc_value);
        let method = msg.get_field("method").and_then(|v| v.as_str());
        let params = msg.get_field("params");

        let Some(method_name) = method else {
            if let Some(id_str) = id_raw {
                let resp = format!(
                    r#"{{"jsonrpc":"2.0","id":{},"error":{{"code":-32600,"message":"Invalid Request"}}}}"#,
                    id_str
                );
                write_lsp_frame(writer, &resp)?;
            }
            continue;
        };

        if method_name == "exit" {
            return Ok(if shutdown_requested { 0 } else { 1 });
        }

        if shutdown_requested {
            if let Some(id_str) = id_raw {
                let resp = format!(
                    r#"{{"jsonrpc":"2.0","id":{},"error":{{"code":-32600,"message":"Server is shutting down"}}}}"#,
                    id_str
                );
                write_lsp_frame(writer, &resp)?;
            }
            continue;
        }

        // TVEK-13: Enforce LSP 3.17 initialization lifecycle before processing requests or notifications
        if !initialized && method_name != "initialize" {
            if let Some(id_str) = id_raw {
                let resp = format!(
                    r#"{{"jsonrpc":"2.0","id":{},"error":{{"code":-32002,"message":"Server not initialized"}}}}"#,
                    id_str
                );
                write_lsp_frame(writer, &resp)?;
            }
            continue;
        }

        match method_name {
            "initialize" => {
                if initialized {
                    if let Some(id_str) = id_raw {
                        let resp = format!(
                            r#"{{"jsonrpc":"2.0","id":{},"error":{{"code":-32600,"message":"Server is already initialized"}}}}"#,
                            id_str
                        );
                        write_lsp_frame(writer, &resp)?;
                    }
                    continue;
                }
                initialized = true;
                if let Some(init_opts) = params.and_then(|p| p.get_field("initializationOptions")) {
                    apply_initialization_options(&mut config, init_opts, host_max_input_bytes);
                }
                if let Some(id_str) = id_raw {
                    let resp = format!(
                        concat!(
                            r#"{{"jsonrpc":"2.0","id":{},"result":{{"#,
                            r#""capabilities":{{"textDocumentSync":{{"openClose":true,"change":1}},"documentFormattingProvider":true}},"#,
                            r#""serverInfo":{{"name":"tvek","version":"0.1.0"}}"#,
                            r#"}}}}"#
                        ),
                        id_str
                    );
                    write_lsp_frame(writer, &resp)?;
                }
            }
            "initialized" | "$/cancelRequest" | "$/setTrace" => {
                // Standard notifications requiring no response
            }
            "shutdown" => {
                shutdown_requested = true;
                if let Some(id_str) = id_raw {
                    let resp = format!(r#"{{"jsonrpc":"2.0","id":{},"result":null}}"#, id_str);
                    write_lsp_frame(writer, &resp)?;
                }
            }
            "textDocument/didOpen" => {
                if let Some(td) = params.and_then(|p| p.get_field("textDocument")) {
                    if let (Some(uri), Some(text)) = (
                        td.get_field("uri").and_then(|v| v.as_str()),
                        td.get_field("text").and_then(|v| v.as_str()),
                    ) {
                        handle_document_update(
                            writer,
                            &mut documents,
                            &mut total_open_bytes,
                            uri,
                            text,
                            &config,
                        )?;
                    }
                }
            }
            "textDocument/didChange" => {
                if let Some(p) = params {
                    let uri_opt = p
                        .get_field("textDocument")
                        .and_then(|td| td.get_field("uri"))
                        .and_then(|v| v.as_str());
                    let changes_opt = p.get_field("contentChanges").and_then(|v| v.as_array());

                    if let (Some(uri), Some(changes)) = (uri_opt, changes_opt) {
                        if let Some(last_text) = changes
                            .iter()
                            .rev()
                            .find_map(|c| c.get_field("text").and_then(|v| v.as_str()))
                        {
                            handle_document_update(
                                writer,
                                &mut documents,
                                &mut total_open_bytes,
                                uri,
                                last_text,
                                &config,
                            )?;
                        }
                    }
                }
            }
            "textDocument/didClose" => {
                if let Some(uri) = params
                    .and_then(|p| p.get_field("textDocument"))
                    .and_then(|td| td.get_field("uri"))
                    .and_then(|v| v.as_str())
                {
                    if uri.len() <= MAX_URI_BYTES {
                        evict_document(&mut documents, &mut total_open_bytes, uri);
                        let clear_notif = build_publish_diagnostics_notification(uri, None);
                        write_lsp_frame(writer, &clear_notif)?;
                    }
                }
            }
            "textDocument/formatting" => {
                let Some(id_str) = id_raw else {
                    continue;
                };
                let uri_opt = params
                    .and_then(|p| p.get_field("textDocument"))
                    .and_then(|td| td.get_field("uri"))
                    .and_then(|v| v.as_str());

                let Some(uri) = uri_opt else {
                    let resp = format!(r#"{{"jsonrpc":"2.0","id":{},"result":[]}}"#, id_str);
                    write_lsp_frame(writer, &resp)?;
                    continue;
                };

                let Some(doc_text) = documents.get(uri) else {
                    let resp = format!(r#"{{"jsonrpc":"2.0","id":{},"result":[]}}"#, id_str);
                    write_lsp_frame(writer, &resp)?;
                    continue;
                };

                let (tab_size, insert_spaces) = extract_formatting_options(params);
                let indent = if insert_spaces {
                    tab_size.clamp(1, 64)
                } else {
                    0
                };
                let fmt_opts = FormatOptions {
                    minify: config.minify,
                    indent,
                    sort_keys: config.sort_keys,
                };

                let max_out = compute_lsp_max_output_bytes(config.max_input_bytes);
                match format_json_with_limit(doc_text.as_bytes(), &fmt_opts, max_out) {
                    Ok(formatted_bytes) => {
                        if formatted_bytes.as_slice() == doc_text.as_bytes() {
                            let resp =
                                format!(r#"{{"jsonrpc":"2.0","id":{},"result":[]}}"#, id_str);
                            write_lsp_frame(writer, &resp)?;
                        } else if let Ok(formatted_str) = String::from_utf8(formatted_bytes) {
                            let (end_line, end_char) = end_position_utf16(doc_text);
                            let mut escaped_new_text =
                                String::with_capacity(formatted_str.len() + 16);
                            escape_json_string(&formatted_str, &mut escaped_new_text);
                            let resp = format!(
                                concat!(
                                    r#"{{"jsonrpc":"2.0","id":{},"result":[{{"#,
                                    r#""range":{{"start":{{"line":0,"character":0}},"end":{{"line":{},"character":{}}}}},"#,
                                    r#""newText":"{}""#,
                                    r#"}}]}}"#
                                ),
                                id_str, end_line, end_char, escaped_new_text
                            );
                            write_lsp_frame(writer, &resp)?;
                        } else {
                            let resp =
                                format!(r#"{{"jsonrpc":"2.0","id":{},"result":[]}}"#, id_str);
                            write_lsp_frame(writer, &resp)?;
                        }
                    }
                    Err(_) => {
                        let resp = format!(r#"{{"jsonrpc":"2.0","id":{},"result":[]}}"#, id_str);
                        write_lsp_frame(writer, &resp)?;
                    }
                }
            }
            _ => {
                if let Some(id_str) = id_raw {
                    let resp = format!(
                        r#"{{"jsonrpc":"2.0","id":{},"error":{{"code":-32601,"message":"Method not found"}}}}"#,
                        id_str
                    );
                    write_lsp_frame(writer, &resp)?;
                }
            }
        }
    }

    Ok(if shutdown_requested { 0 } else { 1 })
}

fn evict_document(
    documents: &mut HashMap<String, String>,
    total_open_bytes: &mut usize,
    uri: &str,
) {
    if let Some(old_text) = documents.remove(uri) {
        let removed_cost = uri.len().saturating_add(old_text.len());
        *total_open_bytes = total_open_bytes.saturating_sub(removed_cost);
    }
}

/// Inserts or updates a document in the bounded store. If any resource limit is exceeded
/// (`MAX_URI_BYTES`, `config.max_input_bytes`, `MAX_OPEN_DOCUMENTS`, or aggregate memory cap),
/// evicts any stale cached entry for `uri` so subsequent `textDocument/formatting` requests
/// never format stale text (TVEK-10 / TVEK-11).
fn handle_document_update<W: Write>(
    writer: &mut W,
    documents: &mut HashMap<String, String>,
    total_open_bytes: &mut usize,
    uri: &str,
    text: &str,
    config: &LspConfig,
) -> io::Result<()> {
    if uri.len() > MAX_URI_BYTES {
        return Ok(());
    }

    // Evict any prior version first so `total_open_bytes` reflects remaining documents
    // and stale text is never retained if the new update is rejected (TVEK-11).
    evict_document(documents, total_open_bytes, uri);

    let max_aggregate = config
        .max_input_bytes
        .saturating_mul(2)
        .min(MAX_TOTAL_DOCUMENT_BYTES)
        .max(config.max_input_bytes);
    let entry_cost = uri.len().saturating_add(text.len());

    if text.len() > config.max_input_bytes
        || documents.len() >= MAX_OPEN_DOCUMENTS
        || total_open_bytes.saturating_add(entry_cost) > max_aggregate
    {
        let diag = (
            0,
            0,
            0,
            "Document exceeds maximum allowed size or open document capacity".to_string(),
        );
        let notif = build_publish_diagnostics_notification(uri, Some(diag));
        return write_lsp_frame(writer, &notif);
    }

    *total_open_bytes = total_open_bytes.saturating_add(entry_cost);
    documents.insert(uri.to_string(), text.to_string());
    publish_diagnostics_for_doc(writer, uri, text, config)
}

fn max_frame_size(max_input_bytes: usize) -> usize {
    // Allow JSON-RPC envelope + escaped document overhead up to 2x max_input_bytes + 64 KiB,
    // capped at DEFAULT_MAX_OUTPUT_BYTES (256 MiB).
    max_input_bytes
        .saturating_mul(2)
        .saturating_add(64 * 1024)
        .min(DEFAULT_MAX_OUTPUT_BYTES)
}

fn compute_lsp_max_output_bytes(max_input_bytes: usize) -> usize {
    if max_input_bytes == DEFAULT_MAX_INPUT_BYTES {
        DEFAULT_MAX_OUTPUT_BYTES
    } else {
        max_input_bytes.saturating_mul(4).max(64 * 1024)
    }
}

/// Applies client `initializationOptions` while clamping `maxSize` so a client can never
/// raise `max_input_bytes` above the host/CLI ceiling (TVEK-10).
fn apply_initialization_options(
    config: &mut LspConfig,
    init_opts: &RpcValue,
    host_max_input_bytes: usize,
) {
    if let Some(sort_keys) = init_opts
        .get_field("sortKeys")
        .or_else(|| init_opts.get_field("sort_keys"))
        .and_then(|v| v.as_bool())
    {
        config.sort_keys = sort_keys;
    }
    if let Some(minify) = init_opts.get_field("minify").and_then(|v| v.as_bool()) {
        config.minify = minify;
    }
    if let Some(max_size) = init_opts
        .get_field("maxSize")
        .or_else(|| init_opts.get_field("max_size"))
        .and_then(|v| v.as_usize())
    {
        if max_size > 0 {
            config.max_input_bytes = max_size
                .min(host_max_input_bytes)
                .min(DEFAULT_MAX_INPUT_BYTES);
        }
    }
}

fn extract_formatting_options(params: Option<&RpcValue>) -> (usize, bool) {
    let mut tab_size = 2usize;
    let mut insert_spaces = true;

    if let Some(opts) = params.and_then(|p| p.get_field("options")) {
        if let Some(ts) = opts.get_field("tabSize").and_then(|v| v.as_usize()) {
            if ts > 0 {
                tab_size = ts.min(64);
            }
        }
        if let Some(ins) = opts.get_field("insertSpaces").and_then(|v| v.as_bool()) {
            insert_spaces = ins;
        }
    }

    (tab_size, insert_spaces)
}

fn publish_diagnostics_for_doc<W: Write>(
    writer: &mut W,
    uri: &str,
    text: &str,
    config: &LspConfig,
) -> io::Result<()> {
    let max_mem = compute_lsp_max_output_bytes(config.max_input_bytes);
    let diag_opt = match lint_json_with_limit(text.as_bytes(), max_mem) {
        Ok(()) => None,
        Err(err) => {
            let (line_0, char_0) = offset_to_utf16_position(text, err.offset);
            let mut safe_off = err.offset.min(text.len());
            while safe_off > 0 && !text.is_char_boundary(safe_off) {
                safe_off -= 1;
            }
            let char_end = if safe_off < text.len() {
                let ch_len = text[safe_off..]
                    .chars()
                    .next()
                    .map(|c| if c == '\n' || c == '\r' { 0 } else { c.len_utf16() })
                    .unwrap_or(0);
                char_0 + ch_len
            } else {
                char_0
            };
            Some((line_0, char_0, char_end, err.message))
        }
    };

    let notif = build_publish_diagnostics_notification(uri, diag_opt);
    write_lsp_frame(writer, &notif)
}

fn build_publish_diagnostics_notification(
    uri: &str,
    diag: Option<(usize, usize, usize, String)>,
) -> String {
    let mut escaped_uri = String::with_capacity(uri.len());
    escape_json_string(uri, &mut escaped_uri);

    match diag {
        None => format!(
            r#"{{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{{"uri":"{}","diagnostics":[]}}}}"#,
            escaped_uri
        ),
        Some((line, start_char, end_char, message)) => {
            let mut escaped_msg = String::with_capacity(message.len());
            escape_json_string(&message, &mut escaped_msg);
            format!(
                concat!(
                    r#"{{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{{"#,
                    r#""uri":"{}","diagnostics":[{{"#,
                    r#""range":{{"start":{{"line":{},"character":{}}},"end":{{"line":{},"character":{}}}}},"#,
                    r#""severity":1,"source":"tvek","message":"{}""#,
                    r#"}}]}}}}"#
                ),
                escaped_uri, line, start_char, line, end_char, escaped_msg
            )
        }
    }
}

/// Converts a byte offset in `text` into 0-indexed LSP `(line, utf16_character)` coordinates.
/// Safely snaps `byte_offset` down to the nearest valid UTF-8 character boundary so it can never panic (TVEK-13).
pub fn offset_to_utf16_position(text: &str, byte_offset: usize) -> (usize, usize) {
    let clamped = byte_offset.min(text.len());
    let bytes = text.as_bytes();
    let mut line = 0usize;
    let mut line_start = 0usize;

    for (idx, &b) in bytes[..clamped].iter().enumerate() {
        if b == b'\n' {
            line += 1;
            line_start = idx + 1;
        }
    }

    let mut col_end = if clamped > line_start
        && bytes[clamped - 1] == b'\r'
        && bytes.get(clamped) == Some(&b'\n')
    {
        clamped - 1
    } else {
        clamped
    };

    while col_end > line_start && !text.is_char_boundary(col_end) {
        col_end -= 1;
    }

    let line_prefix = &text[line_start..col_end];
    let utf16_col: usize = line_prefix.chars().map(|c| c.len_utf16()).sum();
    (line, utf16_col)
}

/// Computes the 0-indexed LSP `(line, utf16_character)` position at the end of `text`.
fn end_position_utf16(text: &str) -> (usize, usize) {
    offset_to_utf16_position(text, text.len())
}

/// Reads a single `Content-Length` framed JSON-RPC message with strict header and body size caps,
/// duplicate `Content-Length` rejection (TVEK-11), and incremental body allocation (TVEK-10).
pub fn read_lsp_frame<R: BufRead>(
    reader: &mut R,
    max_body_bytes: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut content_length: Option<usize> = None;
    let mut header_count = 0usize;
    let mut line_buf: Vec<u8> = Vec::with_capacity(128);

    loop {
        line_buf.clear();
        let bytes_read = (&mut *reader)
            .take((MAX_HEADER_LINE_BYTES as u64) + 1)
            .read_until(b'\n', &mut line_buf)?;

        if bytes_read == 0 {
            if header_count == 0 && content_length.is_none() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF while reading LSP headers",
            ));
        }

        if line_buf.len() > MAX_HEADER_LINE_BYTES || !line_buf.ends_with(b"\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LSP header line exceeds maximum allowed length",
            ));
        }

        let trimmed = trim_ascii_crlf(&line_buf);
        if trimmed.is_empty() {
            break;
        }

        header_count += 1;
        if header_count > MAX_HEADERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Too many LSP header fields",
            ));
        }

        let header_str = std::str::from_utf8(trimmed).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid UTF-8 in LSP header line",
            )
        })?;

        if let Some((name, val)) = header_str.split_once(':') {
            if name.trim().eq_ignore_ascii_case("Content-Length") {
                if content_length.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Duplicate Content-Length header in LSP frame",
                    ));
                }
                let len = val.trim().parse::<usize>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid Content-Length header value",
                    )
                })?;
                if len > max_body_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "LSP Content-Length ({}) exceeds maximum allowed size ({})",
                            len, max_body_bytes
                        ),
                    ));
                }
                content_length = Some(len);
            }
        }
    }

    let len = content_length.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Missing Content-Length header in LSP frame",
        )
    })?;

    let mut body = Vec::with_capacity(len.min(MAX_FRAME_PREALLOC_BYTES));
    (&mut *reader).take(len as u64).read_to_end(&mut body)?;
    if body.len() != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Unexpected EOF while reading LSP frame body",
        ));
    }
    Ok(Some(body))
}

/// Writes a single `Content-Length` framed JSON-RPC message and flushes the stream.
pub fn write_lsp_frame<W: Write>(writer: &mut W, payload: &str) -> io::Result<()> {
    write!(
        writer,
        "Content-Length: {}\r\n\r\n{}",
        payload.len(),
        payload
    )?;
    writer.flush()
}

fn trim_ascii_crlf(mut bytes: &[u8]) -> &[u8] {
    while let Some(&last) = bytes.last() {
        if last == b'\n' || last == b'\r' {
            bytes = &bytes[..bytes.len() - 1];
        } else {
            break;
        }
    }
    bytes
}

fn escape_json_string(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let code = c as u32;
                let hex = b"0123456789abcdef";
                out.push_str("\\u00");
                out.push(hex[((code >> 4) & 0xF) as usize] as char);
                out.push(hex[(code & 0xF) as usize] as char);
            }
            c => out.push(c),
        }
    }
}

// --- Zero-Dependency Iterative & Bounded JSON-RPC Value Reader (TVEK-12) ---

#[derive(Debug, Clone)]
enum RpcValue {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<RpcValue>),
    Object(Vec<(String, RpcValue)>),
}

impl RpcValue {
    fn get_field(&self, key: &str) -> Option<&RpcValue> {
        match self {
            RpcValue::Object(entries) => entries
                .iter()
                .rev()
                .find_map(|(k, v)| if k == key { Some(v) } else { None }),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            RpcValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            RpcValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    fn as_usize(&self) -> Option<usize> {
        match self {
            RpcValue::Number(n) => n.parse::<usize>().ok(),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[RpcValue]> {
        match self {
            RpcValue::Array(arr) => Some(arr.as_slice()),
            _ => None,
        }
    }
}

fn serialize_rpc_value(val: &RpcValue) -> String {
    match val {
        RpcValue::Null => "null".to_string(),
        RpcValue::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        RpcValue::Number(n) => n.clone(),
        RpcValue::Str(s) => {
            let mut out = String::with_capacity(s.len() + 2);
            out.push('"');
            escape_json_string(s, &mut out);
            out.push('"');
            out
        }
        RpcValue::Array(_) | RpcValue::Object(_) => "null".to_string(),
    }
}

enum RpcBuildFrame {
    Object {
        entries: Vec<(String, RpcValue)>,
        pending_key: String,
    },
    Array {
        items: Vec<RpcValue>,
    },
}

fn parse_rpc_value(input: &[u8]) -> Option<RpcValue> {
    let mut parser = RpcParser {
        input,
        pos: 0,
        nodes_parsed: 0,
    };
    let val = parser.parse_root()?;
    parser.skip_ws();
    if parser.pos != input.len() {
        return None;
    }
    Some(val)
}

struct RpcParser<'a> {
    input: &'a [u8],
    pos: usize,
    nodes_parsed: usize,
}

impl<'a> RpcParser<'a> {
    #[inline]
    fn charge_node(&mut self) -> Option<()> {
        self.nodes_parsed = self.nodes_parsed.saturating_add(1);
        if self.nodes_parsed > MAX_RPC_NODES {
            None
        } else {
            Some(())
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.input.len() {
            match self.input[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    /// Iterative JSON-RPC envelope parser bounded by `MAX_RPC_DEPTH` and `MAX_RPC_NODES` (TVEK-12).
    fn parse_root(&mut self) -> Option<RpcValue> {
        let mut stack: Vec<RpcBuildFrame> = Vec::with_capacity(16);

        'expect_val: loop {
            self.skip_ws();
            let mut current_val = loop {
                self.skip_ws();
                let b = *self.input.get(self.pos)?;
                match b {
                    b'{' => {
                        if stack.len() + 1 > MAX_RPC_DEPTH {
                            return None;
                        }
                        self.charge_node()?;
                        self.pos += 1;
                        self.skip_ws();
                        if *self.input.get(self.pos)? == b'}' {
                            self.pos += 1;
                            break RpcValue::Object(Vec::new());
                        }
                        let key = self.parse_string()?;
                        self.skip_ws();
                        if *self.input.get(self.pos)? != b':' {
                            return None;
                        }
                        self.pos += 1;
                        stack.push(RpcBuildFrame::Object {
                            entries: Vec::new(),
                            pending_key: key,
                        });
                    }
                    b'[' => {
                        if stack.len() + 1 > MAX_RPC_DEPTH {
                            return None;
                        }
                        self.charge_node()?;
                        self.pos += 1;
                        self.skip_ws();
                        if *self.input.get(self.pos)? == b']' {
                            self.pos += 1;
                            break RpcValue::Array(Vec::new());
                        }
                        stack.push(RpcBuildFrame::Array { items: Vec::new() });
                    }
                    b'"' => {
                        self.charge_node()?;
                        break RpcValue::Str(self.parse_string()?);
                    }
                    b't' => {
                        self.charge_node()?;
                        self.pos += 4;
                        break RpcValue::Bool(true);
                    }
                    b'f' => {
                        self.charge_node()?;
                        self.pos += 5;
                        break RpcValue::Bool(false);
                    }
                    b'n' => {
                        self.charge_node()?;
                        self.pos += 4;
                        break RpcValue::Null;
                    }
                    b'-' | b'0'..=b'9' => {
                        self.charge_node()?;
                        break RpcValue::Number(self.parse_number()?);
                    }
                    _ => return None,
                }
            };

            while let Some(frame) = stack.last_mut() {
                self.skip_ws();
                match frame {
                    RpcBuildFrame::Object {
                        entries,
                        pending_key,
                    } => {
                        let key = std::mem::take(pending_key);
                        entries.push((key, current_val));
                        match *self.input.get(self.pos)? {
                            b',' => {
                                self.pos += 1;
                                self.skip_ws();
                                let next_key = self.parse_string()?;
                                self.skip_ws();
                                if *self.input.get(self.pos)? != b':' {
                                    return None;
                                }
                                self.pos += 1;
                                if let Some(RpcBuildFrame::Object { pending_key, .. }) =
                                    stack.last_mut()
                                {
                                    *pending_key = next_key;
                                }
                                continue 'expect_val;
                            }
                            b'}' => {
                                self.pos += 1;
                                if let Some(RpcBuildFrame::Object { entries, .. }) = stack.pop() {
                                    current_val = RpcValue::Object(entries);
                                } else {
                                    unreachable!();
                                }
                            }
                            _ => return None,
                        }
                    }
                    RpcBuildFrame::Array { items } => {
                        items.push(current_val);
                        match *self.input.get(self.pos)? {
                            b',' => {
                                self.pos += 1;
                                continue 'expect_val;
                            }
                            b']' => {
                                self.pos += 1;
                                if let Some(RpcBuildFrame::Array { items }) = stack.pop() {
                                    current_val = RpcValue::Array(items);
                                } else {
                                    unreachable!();
                                }
                            }
                            _ => return None,
                        }
                    }
                }
            }

            return Some(current_val);
        }
    }

    fn parse_number(&mut self) -> Option<String> {
        let start = self.pos;
        while self.pos < self.input.len() {
            match self.input[self.pos] {
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E' => self.pos += 1,
                _ => break,
            }
        }
        std::str::from_utf8(&self.input[start..self.pos])
            .ok()
            .map(ToString::to_string)
    }

    fn parse_string(&mut self) -> Option<String> {
        if *self.input.get(self.pos)? != b'"' {
            return None;
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.input.len() {
            let b = self.input[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Some(out);
            } else if b == b'\\' {
                self.pos += 1;
                let esc = *self.input.get(self.pos)?;
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let code = self.read_hex4()?;
                        if (0xD800..=0xDBFF).contains(&code) {
                            self.pos += 2; // skip `\u`
                            let low = self.read_hex4()?;
                            let combined = 0x10000
                                + (((code as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                            out.push(char::from_u32(combined)?);
                        } else {
                            out.push(char::from_u32(code as u32)?);
                        }
                    }
                    _ => return None,
                }
            } else {
                let start = self.pos;
                self.pos += 1;
                while self.pos < self.input.len() && (self.input[self.pos] & 0xC0) == 0x80 {
                    self.pos += 1;
                }
                let s = std::str::from_utf8(&self.input[start..self.pos]).ok()?;
                out.push_str(s);
            }
        }
        None
    }

    fn read_hex4(&mut self) -> Option<u16> {
        if self.pos + 4 > self.input.len() {
            return None;
        }
        let mut val = 0u16;
        for i in 0..4 {
            let b = self.input[self.pos + i];
            let d = match b {
                b'0'..=b'9' => (b - b'0') as u16,
                b'a'..=b'f' => (b - b'a' + 10) as u16,
                b'A'..=b'F' => (b - b'A' + 10) as u16,
                _ => return None,
            };
            val = (val << 4) | d;
        }
        self.pos += 4;
        Some(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame_msg(json: &str) -> String {
        format!("Content-Length: {}\r\n\r\n{}", json.len(), json)
    }

    fn read_all_frames(raw_output: &[u8]) -> Vec<RpcValue> {
        let mut cursor = Cursor::new(raw_output);
        let mut frames = Vec::new();
        while let Some(body) = read_lsp_frame(&mut cursor, DEFAULT_MAX_INPUT_BYTES).unwrap() {
            frames.push(parse_rpc_value(&body).unwrap());
        }
        frames
    }

    #[test]
    fn test_lsp_initialize_and_shutdown_lifecycle() {
        let mut input_stream = String::new();
        input_stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"initializationOptions":{"sortKeys":true}}}"#,
        ));
        input_stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","method":"initialized","params":{}}"#,
        ));
        input_stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","id":2,"method":"shutdown","params":null}"#,
        ));
        input_stream.push_str(&frame_msg(r#"{"jsonrpc":"2.0","method":"exit"}"#));

        let mut reader = Cursor::new(input_stream.into_bytes());
        let mut writer = Vec::new();
        let exit_code =
            run_server_loop(&mut reader, &mut writer, LspConfig::default()).unwrap();
        assert_eq!(exit_code, 0);

        let responses = read_all_frames(&writer);
        assert_eq!(responses.len(), 2);

        assert_eq!(
            responses[0]
                .get_field("result")
                .and_then(|r| r.get_field("capabilities"))
                .and_then(|c| c.get_field("documentFormattingProvider"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(matches!(
            responses[1].get_field("result"),
            Some(RpcValue::Null)
        ));

        let uninit_exit = frame_msg(r#"{"jsonrpc":"2.0","method":"exit"}"#);
        let mut reader2 = Cursor::new(uninit_exit.into_bytes());
        let mut writer2 = Vec::new();
        let code2 = run_server_loop(&mut reader2, &mut writer2, LspConfig::default()).unwrap();
        assert_eq!(code2, 1);
    }

    #[test]
    fn test_lsp_did_open_change_close_diagnostics() {
        let mut input_stream = String::new();
        input_stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        ));
        // 1. Open document with UTF-16 astral emoji ("😀" = 2 UTF-16 code units) + trailing comma
        input_stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///test.json","languageId":"json","version":1,"text":"{\"😀\": 1,}"}}}"#,
        ));
        // 2. Fix syntax error via didChange
        input_stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","method":"textDocument/didChange","params":{"textDocument":{"uri":"file:///test.json","version":2},"contentChanges":[{"text":"{\"😀\": 1}"}]}}"#,
        ));
        // 3. Close document
        input_stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","method":"textDocument/didClose","params":{"textDocument":{"uri":"file:///test.json"}}}"#,
        ));

        let mut reader = Cursor::new(input_stream.into_bytes());
        let mut writer = Vec::new();
        let _ = run_server_loop(&mut reader, &mut writer, LspConfig::default()).unwrap();

        let frames = read_all_frames(&writer);
        // Frame 0 is initialize response; Frames 1..=3 are publishDiagnostics notifications
        assert_eq!(frames.len(), 4);

        let diags_1 = frames[1]
            .get_field("params")
            .and_then(|p| p.get_field("diagnostics"))
            .and_then(|d| d.as_array())
            .unwrap();
        assert_eq!(diags_1.len(), 1);
        let start_char = diags_1[0]
            .get_field("range")
            .and_then(|r| r.get_field("start"))
            .and_then(|s| s.get_field("character"))
            .and_then(|c| c.as_usize())
            .unwrap();
        assert_eq!(start_char, 8);

        let diags_2 = frames[2]
            .get_field("params")
            .and_then(|p| p.get_field("diagnostics"))
            .and_then(|d| d.as_array())
            .unwrap();
        assert!(diags_2.is_empty());

        let diags_3 = frames[3]
            .get_field("params")
            .and_then(|p| p.get_field("diagnostics"))
            .and_then(|d| d.as_array())
            .unwrap();
        assert!(diags_3.is_empty());
    }

    #[test]
    fn test_lsp_formatting_spaces_tabs_and_sort_keys() {
        let mut input_stream = String::new();
        input_stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"initializationOptions":{"sortKeys":true}}}"#,
        ));
        input_stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///fmt.json","languageId":"json","version":1,"text":"{\"b\":2,\"a\":1}"}}}"#,
        ));
        input_stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","id":2,"method":"textDocument/formatting","params":{"textDocument":{"uri":"file:///fmt.json"},"options":{"tabSize":4,"insertSpaces":true}}}"#,
        ));
        input_stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","id":3,"method":"textDocument/formatting","params":{"textDocument":{"uri":"file:///fmt.json"},"options":{"tabSize":4,"insertSpaces":false}}}"#,
        ));

        let mut reader = Cursor::new(input_stream.into_bytes());
        let mut writer = Vec::new();
        let _ = run_server_loop(&mut reader, &mut writer, LspConfig::default()).unwrap();

        let frames = read_all_frames(&writer);
        assert_eq!(frames.len(), 4);

        let edits_4 = frames[2]
            .get_field("result")
            .and_then(|r| r.as_array())
            .unwrap();
        assert_eq!(
            edits_4[0].get_field("newText").and_then(|v| v.as_str()),
            Some("{\n    \"a\": 1,\n    \"b\": 2\n}\n")
        );

        let edits_tab = frames[3]
            .get_field("result")
            .and_then(|r| r.as_array())
            .unwrap();
        assert_eq!(
            edits_tab[0].get_field("newText").and_then(|v| v.as_str()),
            Some("{\n\t\"a\": 1,\n\t\"b\": 2\n}\n")
        );
    }

    #[test]
    fn test_lsp_bounded_content_length_and_invalid_headers() {
        let oversized_frame = "Content-Length: 999999999\r\n\r\n{}";
        let mut reader = Cursor::new(oversized_frame.as_bytes());
        let err = read_lsp_frame(&mut reader, 1024).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum allowed size"));
    }

    #[test]
    fn test_tvek_10_clamp_init_max_size_and_incremental_frame_read() {
        // Host starts server with max_input_bytes = 1024. Client tries to escalate maxSize to 999_999_999.
        let mut cfg = LspConfig {
            sort_keys: false,
            minify: false,
            max_input_bytes: 1024,
        };
        let opts = parse_rpc_value(br#"{"maxSize": 999999999}"#).unwrap();
        apply_initialization_options(&mut cfg, &opts, 1024);
        assert_eq!(cfg.max_input_bytes, 1024);

        // Client can still lower maxSize below the host ceiling
        let opts_lower = parse_rpc_value(br#"{"maxSize": 512}"#).unwrap();
        apply_initialization_options(&mut cfg, &opts_lower, 1024);
        assert_eq!(cfg.max_input_bytes, 512);

        // Truncated frame claiming a large Content-Length must fail with UnexpectedEof without OOM
        let truncated_frame = "Content-Length: 50000000\r\n\r\n{}";
        let mut reader = Cursor::new(truncated_frame.as_bytes());
        let err = read_lsp_frame(&mut reader, 60_000_000).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_tvek_11_evict_stale_doc_on_rejected_did_change_and_reject_dup_content_length() {
        // 1. Duplicate Content-Length header must be rejected
        let dup_cl = "Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
        let mut dup_reader = Cursor::new(dup_cl.as_bytes());
        let dup_err = read_lsp_frame(&mut dup_reader, 1024).unwrap_err();
        assert_eq!(dup_err.kind(), io::ErrorKind::InvalidData);
        assert!(dup_err.to_string().contains("Duplicate Content-Length"));

        // 2. When didChange exceeds max_input_bytes, stale cached document must be evicted
        let small_cfg = LspConfig {
            sort_keys: false,
            minify: false,
            max_input_bytes: 32,
        };
        let mut stream = String::new();
        stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        ));
        stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///a.json","languageId":"json","version":1,"text":"{\"a\":1}"}}}"#,
        ));
        // Send oversized didChange (> 32 bytes)
        stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","method":"textDocument/didChange","params":{"textDocument":{"uri":"file:///a.json","version":2},"contentChanges":[{"text":"{\"very_long_key_exceeding_32_byte_limit\": 1234567890}"}]}}"#,
        ));
        // Request formatting — must return empty edits `[]` rather than formatting stale `{"a":1}`
        stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","id":2,"method":"textDocument/formatting","params":{"textDocument":{"uri":"file:///a.json"},"options":{"tabSize":2,"insertSpaces":true}}}"#,
        ));

        let mut reader = Cursor::new(stream.into_bytes());
        let mut writer = Vec::new();
        let _ = run_server_loop(&mut reader, &mut writer, small_cfg).unwrap();

        let frames = read_all_frames(&writer);
        // Frame 0: initialize, Frame 1: didOpen diag ([]), Frame 2: didChange size-error diag, Frame 3: formatting result ([])
        assert_eq!(frames.len(), 4);
        let fmt_edits = frames[3]
            .get_field("result")
            .and_then(|r| r.as_array())
            .unwrap();
        assert!(
            fmt_edits.is_empty(),
            "Formatting must not use stale document after rejected didChange"
        );
    }

    #[test]
    fn test_tvek_12_rpc_parser_depth_and_node_caps() {
        // Nesting > MAX_RPC_DEPTH (32) in JSON-RPC envelope is rejected
        let deep = "[".repeat(40) + &"]".repeat(40);
        assert!(parse_rpc_value(deep.as_bytes()).is_none());

        // Array with > MAX_RPC_NODES (10,000) elements in JSON-RPC envelope is rejected
        let mut many_nodes = String::from("[0");
        for _ in 0..10_005 {
            many_nodes.push_str(",0");
        }
        many_nodes.push(']');
        assert!(parse_rpc_value(many_nodes.as_bytes()).is_none());
    }

    #[test]
    fn test_tvek_13_utf8_char_boundary_safety_and_pre_initialize_check() {
        // Calling offset_to_utf16_position with byte_offset inside a 4-byte UTF-8 sequence ("😀" = bytes 0..4)
        // must never panic and must snap cleanly to the start of the character
        let text = "😀hello";
        for mid_offset in 1..4 {
            assert_eq!(offset_to_utf16_position(text, mid_offset), (0, 0));
        }
        assert_eq!(offset_to_utf16_position(text, 4), (0, 2));

        // Sending a request before `initialize` must return JSON-RPC error -32002 (ServerNotInitialized)
        let mut stream = String::new();
        stream.push_str(&frame_msg(
            r#"{"jsonrpc":"2.0","id":99,"method":"textDocument/formatting","params":{}}"#,
        ));
        stream.push_str(&frame_msg(r#"{"jsonrpc":"2.0","method":"exit"}"#));

        let mut reader = Cursor::new(stream.into_bytes());
        let mut writer = Vec::new();
        let code = run_server_loop(&mut reader, &mut writer, LspConfig::default()).unwrap();
        assert_eq!(code, 1);

        let frames = read_all_frames(&writer);
        assert_eq!(frames.len(), 1);
        let err_str = frames[0]
            .get_field("error")
            .and_then(|e| e.get_field("code"))
            .map(serialize_rpc_value);
        assert_eq!(err_str.as_deref(), Some("-32002"));
    }
}
