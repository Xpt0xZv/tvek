# tvek

**tvek** is a zero-dependency, ultra-fast RFC 8259 JSON linter and formatter written in pure Rust (`std` only).

## Features

- **Zero External Dependencies**: Built exclusively with the Rust standard library (`std`)—no third-party crates.
- **Single-Pass Streaming Byte Engine**: Validates RFC 8259 compliance and emits formatted output in a single byte-level pass (`&[u8]`) with 8-byte SWAR string scanning and pre-allocated indentation tables, without constructing an intermediate DOM/AST (unless `--sort-keys` is explicitly requested).
- **Multi-Threaded Batch Processing**: Automatically scales across available CPU cores via `std::thread::scope` when linting, checking, or formatting multiple files in-place, with canonical path deduplication.
- **Strict RFC 8259 Compliance**:
  - Rejects UTF-8 byte order marks (`0xEF 0xBB 0xBF` BOM) at offset `0` with an explicit diagnostic per RFC 8259 §8.1.
  - Rejects trailing commas in objects and arrays.
  - Validates the full JSON number grammar (`[-]? (0 | [1-9][0-9]*) (\.[0-9]+)? ([eE][+-]?[0-9]+)?`), rejecting leading zeros (`01`), leading/trailing decimal points (`.5`, `1.`), `+1`, `NaN`, and `Infinity`.
  - Rejects single-quoted strings, unquoted keys, and unescaped control characters (`0x00..=0x1F`).
  - Validates all escape sequences (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\uXXXX`), including strict UTF-16 surrogate pair verification (`0xD800..=0xDBFF` paired with `0xDC00..=0xDFFF`).
  - Rejects duplicate object keys (including Unicode escape-equivalent keys) to prevent parser differential/smuggling issues.
  - Enforces a maximum nesting depth of 512 and bounded input, DOM, key-set, and output buffers.
- **Ruff-Style Diagnostics**: Reports exact 1-indexed line, column, and byte offsets with a visual caret (`^`) snippet, windowing long minified lines to 120 characters and sanitizing terminal control, format (`Cf`), line/paragraph separator (`Zl`/`Zp`), and BiDi override characters.

## Installation

### Via Cargo

```bash
cargo install --path .
```

### Via uv / pipx (Maturin Binary Wheel)

```bash
uv tool install .
# or run directly:
uvx tvek --help
```

## Usage

```text
tvek [OPTIONS] [FILES_OR_DIRS...]
tvek server [OPTIONS]
```

### Options

| Flag | Description |
| :--- | :--- |
| `-c, --check` | Lint and verify formatting without modifying files (exits `1` if unformatted or invalid) |
| `-l, --lint` | Lint syntax only, ignoring whitespace/indentation differences |
| `-w, --write` | Format files in-place atomically (only writes if formatted output differs) |
| `-m, --minify` | Output compact single-line JSON with all insignificant whitespace stripped |
| `-i, --indent <N>` | Number of spaces per indentation level (default: `2`; `0` uses `\t`) |
| `-s, --sort-keys` | Lexicographically sort object keys at every nesting level |
| `--max-size <BYTES>` | Maximum input size in bytes (default: `104857600` / 100 MiB) |
| `--lsp` | Start the Language Server Protocol (LSP) server over stdio (alias for `tvek server`) |
| `-q, --quiet` | Suppress non-error output |
| `-v, --version` | Print `tvek 0.1.0` and exit `0` |
| `-h, --help` | Print CLI help documentation and exit `0` |

## Language Server (`tvek server`)

`tvek` includes a built-in, zero-dependency Language Server Protocol (LSP) engine over `stdio` supporting real-time RFC 8259 diagnostics (`textDocument/publishDiagnostics`) and document formatting (`textDocument/formatting`).

```bash
tvek server
# Or with default server-level options:
tvek server --sort-keys --max-size 104857600
```

You can also pass `initializationOptions` (`{ "sortKeys": true, "minify": false, "maxSize": 104857600 }`) from your editor client.

### CLI Validation & Directory Discovery Rules

- **Mutually Exclusive Modes**: `--lint`, `--check`, and `--write` are mutually exclusive; `--minify` and `--indent <N>` cannot be combined; and `--write` cannot be used with `stdin` (`-`). Invalid flag combinations exit with code `2`.
- **Directory Filtering**: When recursively traversing directories, `tvek` automatically skips hidden child directories (`.*`, such as `.git`, `.venv`, `.vscode`) as well as `node_modules`, `target`, `dist`, `build`, `vendor`, and `__pycache__` (up to 64 directory levels and 100,000 files). Hidden files or directories passed explicitly as CLI arguments (e.g., `tvek -w .vscode/settings.json`) are processed normally.

### Exit Codes

- `0`: Success (all inputs valid and properly formatted).
- `1`: Lint error or formatting check failed.
- `2`: CLI usage error or file I/O error.

### Diagnostic Example

```text
error: Trailing comma is not allowed in JSON object
  --> config.json:14:22
   |
14 |   "port": 8080,
   |               ^
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

