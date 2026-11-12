use std::borrow::Cow;
use std::collections::HashSet;
use std::hash::{BuildHasher, Hasher};
use std::mem::size_of;

use crate::error::SyntaxError;

pub const MAX_DEPTH: usize = 512;
pub const MAX_LINT_DIAGNOSTICS: usize = 50;
pub const DEFAULT_LINE_WIDTH: usize = 80;
pub const MAX_LINE_WIDTH: usize = 4096;
pub const DEFAULT_MAX_INPUT_BYTES: usize = 100 * 1024 * 1024; // 100 MiB
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024; // 256 MiB
const MAX_INITIAL_CAPACITY: usize = 16 * 1024 * 1024; // 16 MiB cap on initial Vec reservation
const SMALL_KEY_SET_LIMIT: usize = 8;
const MAX_POOLED_HASHSET_CAPACITY: usize = 64;
const MAX_FREE_KEY_SETS: usize = 32;
const FX_SEED_CONST: u64 = 0x517c_c1b7_2722_0a95;

static STATIC_SPACES: [u8; MAX_DEPTH * 8] = [b' '; MAX_DEPTH * 8];
static STATIC_TABS: [u8; MAX_DEPTH] = [b'\t'; MAX_DEPTH];

/// Fast, zero-dependency 64-bit multiply-rotate hasher seeded with stack/code address entropy (PERF-05).
#[derive(Clone, Copy)]
struct FxBuildHasher {
    seed: u64,
}

impl FxBuildHasher {
    #[inline]
    fn new() -> Self {
        let code_addr = (Self::new as *const () as usize) as u64;
        let stack_addr = (&code_addr as *const u64 as usize) as u64;
        let seed = (code_addr ^ stack_addr.rotate_left(29)).wrapping_mul(FX_SEED_CONST);
        Self { seed }
    }
}

impl BuildHasher for FxBuildHasher {
    type Hasher = FxHasher;

    #[inline(always)]
    fn build_hasher(&self) -> Self::Hasher {
        FxHasher { hash: self.seed }
    }
}

struct FxHasher {
    hash: u64,
}

impl FxHasher {
    #[inline(always)]
    fn add_to_hash(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(FX_SEED_CONST);
    }
}

impl Hasher for FxHasher {
    #[inline(always)]
    fn write(&mut self, mut bytes: &[u8]) {
        while bytes.len() >= 8 {
            let word = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
            self.add_to_hash(word);
            bytes = &bytes[8..];
        }
        if bytes.len() >= 4 {
            let word = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as u64;
            self.add_to_hash(word);
            bytes = &bytes[4..];
        }
        if bytes.len() >= 2 {
            let word = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as u64;
            self.add_to_hash(word);
            bytes = &bytes[2..];
        }
        if let Some(&b) = bytes.first() {
            self.add_to_hash(b as u64);
        }
    }

    #[inline(always)]
    fn write_u8(&mut self, i: u8) {
        self.add_to_hash(i as u64);
    }

    #[inline(always)]
    fn write_usize(&mut self, i: usize) {
        self.add_to_hash(i as u64);
    }

    #[inline(always)]
    fn finish(&self) -> u64 {
        self.hash
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatOptions {
    pub minify: bool,
    pub indent: usize,
    pub sort_keys: bool,
    pub allow_comments: bool,
    pub line_width: usize,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            minify: false,
            indent: 2,
            sort_keys: false,
            allow_comments: true,
            line_width: DEFAULT_LINE_WIDTH,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommentPiece<'a> {
    raw: &'a [u8],
    pos: usize,
    inline_with_prev: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerKind {
    Object,
    Array,
}

/// Three-tier key set that uses a flat `Vec` for small objects (`<= 8` keys), upgrades to a
/// pooled `FxHasher`-backed `HashSet` for medium objects (`9..=64` keys), and upgrades to a
/// `RandomState` (SipHash-1-3) `HashSet` for large objects (`> 64` keys) to prevent HashDoS
/// while tracking heap memory and shrinking oversized tables (IMP-05 / TVEK-08 / PERF-05 / TVEK-20).
enum KeySetStorage<'a> {
    Small(Vec<Cow<'a, str>>),
    Medium(HashSet<Cow<'a, str>, FxBuildHasher>),
    Large(HashSet<Cow<'a, str>>),
}

struct KeySet<'a> {
    storage: KeySetStorage<'a>,
    allocated_bytes: usize,
}

impl<'a> KeySet<'a> {
    #[inline]
    fn new() -> Self {
        Self {
            storage: KeySetStorage::Small(Vec::with_capacity(SMALL_KEY_SET_LIMIT)),
            allocated_bytes: 0,
        }
    }

    #[inline]
    fn insert(&mut self, key: Cow<'a, str>) -> (bool, usize) {
        let key_cost = size_of::<Cow<'a, str>>().saturating_add(match &key {
            Cow::Borrowed(_) => 0,
            Cow::Owned(s) => s.len(),
        });

        let inserted = match &mut self.storage {
            KeySetStorage::Small(vec) => {
                for existing in vec.iter() {
                    if existing == &key {
                        return (false, 0);
                    }
                }
                if vec.len() < SMALL_KEY_SET_LIMIT {
                    vec.push(key);
                    true
                } else {
                    let mut set = HashSet::with_capacity_and_hasher(
                        SMALL_KEY_SET_LIMIT * 2,
                        FxBuildHasher::new(),
                    );
                    for item in vec.drain(..) {
                        set.insert(item);
                    }
                    let ok = set.insert(key);
                    self.storage = KeySetStorage::Medium(set);
                    ok
                }
            }
            KeySetStorage::Medium(set) => {
                if set.len() < MAX_POOLED_HASHSET_CAPACITY {
                    set.insert(key)
                } else if set.contains(&key) {
                    return (false, 0);
                } else {
                    let mut large = HashSet::with_capacity(MAX_POOLED_HASHSET_CAPACITY * 2);
                    for item in set.drain() {
                        large.insert(item);
                    }
                    let ok = large.insert(key);
                    self.storage = KeySetStorage::Large(large);
                    ok
                }
            }
            KeySetStorage::Large(set) => set.insert(key),
        };

        if inserted {
            self.allocated_bytes = self.allocated_bytes.saturating_add(key_cost);
            (true, key_cost)
        } else {
            (false, 0)
        }
    }

    /// Clears the key set and returns the freed byte count. If the underlying `HashSet` grew
    /// into `Large` (`> MAX_POOLED_HASHSET_CAPACITY` keys), downgrades back to `Small` so
    /// multi-megabyte tables are deallocated immediately on `}` (TVEK-08 / TVEK-20).
    #[inline]
    fn clear(&mut self) -> usize {
        let freed = self.allocated_bytes;
        self.allocated_bytes = 0;
        match &mut self.storage {
            KeySetStorage::Small(vec) => vec.clear(),
            KeySetStorage::Medium(set) => set.clear(),
            KeySetStorage::Large(_) => {
                self.storage = KeySetStorage::Small(Vec::with_capacity(SMALL_KEY_SET_LIMIT));
            }
        }
        freed
    }
}

enum IndentBacking {
    Static(&'static [u8]),
    Owned(Vec<u8>),
}

/// Pre-allocated single-slice indentation table for O(1) slice emission up to `MAX_DEPTH`,
/// backed by static `.rodata` slices for standard indentations (`<= 8` spaces and tabs) (IMP-05 / PERF-08).
struct IndentTable {
    backing: IndentBacking,
    unit_len: usize,
}

impl IndentTable {
    #[inline]
    fn new(indent: usize, minify: bool) -> Self {
        if minify {
            return Self {
                backing: IndentBacking::Static(&[]),
                unit_len: 0,
            };
        }
        if indent == 0 {
            Self {
                backing: IndentBacking::Static(&STATIC_TABS),
                unit_len: 1,
            }
        } else if indent <= 8 {
            Self {
                backing: IndentBacking::Static(&STATIC_SPACES[..indent * MAX_DEPTH]),
                unit_len: indent,
            }
        } else {
            Self {
                backing: IndentBacking::Owned(vec![b' '; indent.saturating_mul(MAX_DEPTH)]),
                unit_len: indent,
            }
        }
    }

    #[inline(always)]
    fn as_slice(&self) -> &[u8] {
        match &self.backing {
            IndentBacking::Static(s) => s,
            IndentBacking::Owned(v) => v.as_slice(),
        }
    }

    #[inline(always)]
    fn slice_for_depth(&self, depth: usize) -> &[u8] {
        let slice = self.as_slice();
        let len = self.unit_len.saturating_mul(depth).min(slice.len());
        &slice[..len]
    }
}

/// Validate JSON/JSONC syntax in a single streaming byte pass without allocating formatted output.
pub fn lint_json(input: &[u8]) -> Result<(), SyntaxError> {
    lint_json_with_limit(input, DEFAULT_MAX_OUTPUT_BYTES)
}

/// Validate JSON/JSONC syntax in a single streaming byte pass with an explicit upper bound
/// on active object key-set memory (TVEK-08).
pub fn lint_json_with_limit(input: &[u8], max_key_bytes: usize) -> Result<(), SyntaxError> {
    lint_json_with_options(input, true, max_key_bytes)
}

/// Validate strict RFC 8259 syntax (rejecting `//` and `/* ... */` comments) with an explicit
/// upper bound on active object key-set memory.
pub fn lint_json_strict(input: &[u8], max_key_bytes: usize) -> Result<(), SyntaxError> {
    lint_json_with_options(input, false, max_key_bytes)
}

/// Validate syntax in a single streaming byte pass with configurable comment support and
/// an explicit upper bound on active object key-set memory.
pub fn lint_json_with_options(
    input: &[u8],
    allow_comments: bool,
    max_key_bytes: usize,
) -> Result<(), SyntaxError> {
    let opts = FormatOptions {
        minify: true,
        indent: 0,
        sort_keys: false,
        allow_comments,
        line_width: 0,
    };
    let indent_table = IndentTable::new(0, true);
    let mut sink = NullSink;
    let mut emitter = StreamEmitter::new(&mut sink, &opts, &indent_table, max_key_bytes);
    let mut scanner = Scanner::new(input, allow_comments, max_key_bytes);
    scanner.run_unified_parser(&mut emitter)
}

/// Validate syntax and collect up to `max_errors` local diagnostics in a single pass (PERF-10).
/// Uses the zero-overhead fast path when the document is valid and enters cold-path recovery
/// only when a syntax error is present.
pub fn lint_json_multi_with_options(
    input: &[u8],
    allow_comments: bool,
    max_key_bytes: usize,
    max_errors: usize,
) -> Vec<SyntaxError> {
    if max_errors == 0 {
        return Vec::new();
    }
    match lint_json_with_options(input, allow_comments, max_key_bytes) {
        Ok(()) => Vec::new(),
        Err(first_err) => {
            if max_errors == 1 {
                return vec![first_err];
            }
            let mut diags =
                collect_multi_diagnostics(input, allow_comments, max_key_bytes, max_errors);
            if diags.is_empty() {
                diags.push(first_err);
            }
            diags
        }
    }
}

/// Validate syntax and format JSON/JSONC according to `options` with the default output size cap.
pub fn format_json(input: &[u8], options: &FormatOptions) -> Result<Vec<u8>, SyntaxError> {
    format_json_with_limit(input, options, DEFAULT_MAX_OUTPUT_BYTES)
}

/// Validate syntax and format JSON/JSONC with an explicit upper bound on output and DOM memory
/// to prevent memory amplification DoS (TVEK-02 / IMP-04 / TVEK-08).
pub fn format_json_with_limit(
    input: &[u8],
    options: &FormatOptions,
    max_output_bytes: usize,
) -> Result<Vec<u8>, SyntaxError> {
    let mut out = Vec::new();
    format_json_into_buf(input, options, max_output_bytes, &mut out)?;
    Ok(out)
}

/// Validate syntax and format JSON/JSONC directly into a caller-provided reusable `Vec<u8>`
/// with an explicit upper bound on output and DOM memory (PERF-08 / TVEK-02).
pub fn format_json_into_buf(
    input: &[u8],
    options: &FormatOptions,
    max_output_bytes: usize,
    out: &mut Vec<u8>,
) -> Result<(), SyntaxError> {
    out.clear();
    let initial_cap = if options.minify {
        input.len().saturating_add(1)
    } else {
        input
            .len()
            .saturating_add(input.len() / 4)
            .saturating_add(16)
    }
    .min(max_output_bytes)
    .min(MAX_INITIAL_CAPACITY);

    if out.capacity() < initial_cap {
        out.reserve(initial_cap - out.capacity());
    }

    let indent_table = IndentTable::new(options.indent, options.minify);
    let mut sink = BoundedVecRefSink::new(out, max_output_bytes);
    let mut scanner = Scanner::new(input, options.allow_comments, max_output_bytes);

    if options.sort_keys {
        let mut builder = SortedDomBuilder::new(max_output_bytes);
        scanner.run_unified_parser(&mut builder)?;
        let root = builder
            .current_val
            .ok_or_else(|| SyntaxError::new("Unexpected end of JSON input", input.len(), input))?;
        if !options.minify {
            for comment in &builder.root_leading_comments {
                emit_comment_raw(&mut sink, comment.raw)
                    .map_err(|msg| SyntaxError::new(msg, comment.pos, input))?;
                sink.push_byte(b'\n')
                    .map_err(|msg| SyntaxError::new(msg, comment.pos, input))?;
            }
        }
        emit_sorted_value_iterative(&root, &mut sink, options, &indent_table)
            .map_err(|msg| SyntaxError::new(msg, input.len(), input))?;
        if !options.minify {
            for comment in &builder.root_trailing_comments {
                if comment.inline_with_prev {
                    sink.push_byte(b' ')
                        .map_err(|msg| SyntaxError::new(msg, comment.pos, input))?;
                } else {
                    sink.push_byte(b'\n')
                        .map_err(|msg| SyntaxError::new(msg, comment.pos, input))?;
                }
                emit_comment_raw(&mut sink, comment.raw)
                    .map_err(|msg| SyntaxError::new(msg, comment.pos, input))?;
            }
        }
        sink.push_byte(b'\n')
            .map_err(|msg| SyntaxError::new(msg, input.len(), input))?;
    } else {
        let mut emitter = StreamEmitter::new(&mut sink, options, &indent_table, max_output_bytes);
        scanner.run_unified_parser(&mut emitter)?;
    }

    Ok(())
}

trait OutputSink {
    fn push_byte(&mut self, b: u8) -> Result<(), &'static str>;
    fn extend_slice(&mut self, slice: &[u8]) -> Result<(), &'static str>;
    fn push_indent(&mut self, table: &IndentTable, depth: usize) -> Result<(), &'static str>;
}

struct NullSink;

impl OutputSink for NullSink {
    #[inline(always)]
    fn push_byte(&mut self, _b: u8) -> Result<(), &'static str> {
        Ok(())
    }
    #[inline(always)]
    fn extend_slice(&mut self, _slice: &[u8]) -> Result<(), &'static str> {
        Ok(())
    }
    #[inline(always)]
    fn push_indent(&mut self, _table: &IndentTable, _depth: usize) -> Result<(), &'static str> {
        Ok(())
    }
}

struct BoundedVecRefSink<'b> {
    buf: &'b mut Vec<u8>,
    max_bytes: usize,
}

impl<'b> BoundedVecRefSink<'b> {
    #[inline]
    fn new(buf: &'b mut Vec<u8>, max_bytes: usize) -> Self {
        Self { buf, max_bytes }
    }

    #[inline]
    fn check_additional(&self, additional: usize) -> Result<(), &'static str> {
        if self.buf.len().saturating_add(additional) > self.max_bytes {
            Err("Formatted output exceeds maximum allowed buffer size")
        } else {
            Ok(())
        }
    }
}

impl<'b> OutputSink for BoundedVecRefSink<'b> {
    #[inline(always)]
    fn push_byte(&mut self, b: u8) -> Result<(), &'static str> {
        self.check_additional(1)?;
        self.buf.push(b);
        Ok(())
    }

    #[inline(always)]
    fn extend_slice(&mut self, slice: &[u8]) -> Result<(), &'static str> {
        self.check_additional(slice.len())?;
        self.buf.extend_from_slice(slice);
        Ok(())
    }

    #[inline(always)]
    fn push_indent(&mut self, table: &IndentTable, depth: usize) -> Result<(), &'static str> {
        let indent_slice = table.slice_for_depth(depth);
        self.extend_slice(indent_slice)
    }
}

#[derive(Debug, Clone, Copy)]
struct KeyToken<'a> {
    slice: &'a [u8],
    key_pos: usize,
    colon_pos: usize,
    has_escapes: bool,
}

#[inline]
fn emit_comment_raw<S: OutputSink>(out: &mut S, raw: &[u8]) -> Result<(), &'static str> {
    if !raw.contains(&b'\r') {
        return out.extend_slice(raw);
    }
    let mut start = 0;
    for (i, &b) in raw.iter().enumerate() {
        if b == b'\r' {
            if i > start {
                out.extend_slice(&raw[start..i])?;
            }
            start = i + 1;
        }
    }
    if start < raw.len() {
        out.extend_slice(&raw[start..])?;
    }
    Ok(())
}

#[inline]
fn split_inline_comments<'b, 'a>(
    comments: &'b [CommentPiece<'a>],
) -> (&'b [CommentPiece<'a>], &'b [CommentPiece<'a>]) {
    let split = comments
        .iter()
        .position(|c| !c.inline_with_prev)
        .unwrap_or(comments.len());
    (&comments[..split], &comments[split..])
}

/// Zero-cost generic event interface unifying single-pass streaming and `--sort-keys` DOM construction (IMP-06).
trait ParseEvents<'a> {
    fn depth(&self) -> usize;
    fn top_container(&self) -> Option<ContainerKind>;

    fn on_root_leading_comments(
        &mut self,
        comments: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_empty_object(
        &mut self,
        open_pos: usize,
        close_pos: usize,
        comments: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_open_object(
        &mut self,
        open_pos: usize,
        open_comments: &[CommentPiece<'a>],
        first_leading: &[CommentPiece<'a>],
        first_key: KeyToken<'a>,
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_object_next_key(
        &mut self,
        comma_pos: usize,
        prev_trailing: &[CommentPiece<'a>],
        next_leading: &[CommentPiece<'a>],
        next_key: KeyToken<'a>,
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_close_object(
        &mut self,
        close_pos: usize,
        last_trailing: &[CommentPiece<'a>],
        inner_trailing: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_empty_array(
        &mut self,
        open_pos: usize,
        close_pos: usize,
        comments: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_open_array(
        &mut self,
        open_pos: usize,
        open_comments: &[CommentPiece<'a>],
        first_leading: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_array_comma(
        &mut self,
        comma_pos: usize,
        prev_trailing: &[CommentPiece<'a>],
        next_leading: &[CommentPiece<'a>],
        next_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_close_array(
        &mut self,
        close_pos: usize,
        last_trailing: &[CommentPiece<'a>],
        inner_trailing: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    #[inline(always)]
    fn inline_array_budget(&self) -> Option<usize> {
        None
    }

    #[inline(always)]
    fn on_inline_scalar_array(
        &mut self,
        _open_pos: usize,
        _items: &[&'a [u8]],
        _close_pos: usize,
        _input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        Ok(())
    }

    fn on_primitive(
        &mut self,
        slice: &'a [u8],
        pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_finish(
        &mut self,
        trailing_comments: &[CommentPiece<'a>],
        end_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;
}

enum StreamFrame<'a> {
    Object(KeySet<'a>),
    Array,
}

struct StreamEmitter<'a, 'b, S: OutputSink> {
    out: &'b mut S,
    minify: bool,
    line_width: usize,
    last_key_len: usize,
    indent_table: &'b IndentTable,
    stack: Vec<StreamFrame<'a>>,
    free_sets: Vec<KeySet<'a>>,
    allocated_key_bytes: usize,
    max_key_bytes: usize,
}

impl<'a, 'b, S: OutputSink> StreamEmitter<'a, 'b, S> {
    fn new(
        out: &'b mut S,
        options: &FormatOptions,
        indent_table: &'b IndentTable,
        max_key_bytes: usize,
    ) -> Self {
        Self {
            out,
            minify: options.minify,
            line_width: options.line_width.min(MAX_LINE_WIDTH),
            last_key_len: 0,
            indent_table,
            stack: Vec::with_capacity(32),
            free_sets: Vec::with_capacity(MAX_FREE_KEY_SETS),
            allocated_key_bytes: 0,
            max_key_bytes,
        }
    }

    #[inline(always)]
    fn charge_key_bytes(
        &mut self,
        added: usize,
        pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.allocated_key_bytes = self.allocated_key_bytes.saturating_add(added);
        if self.allocated_key_bytes > self.max_key_bytes {
            Err(SyntaxError::new(
                "Formatted output exceeds maximum allowed buffer size",
                pos,
                input,
            ))
        } else {
            Ok(())
        }
    }

    #[inline(always)]
    fn emit_key(&mut self, key: KeyToken<'a>, input: &'a [u8]) -> Result<(), SyntaxError> {
        self.out
            .extend_slice(key.slice)
            .map_err(|msg| SyntaxError::new(msg, key.key_pos, input))?;
        self.out
            .push_byte(b':')
            .map_err(|msg| SyntaxError::new(msg, key.colon_pos, input))?;
        if !self.minify {
            self.out
                .push_byte(b' ')
                .map_err(|msg| SyntaxError::new(msg, key.colon_pos, input))?;
        }
        self.last_key_len = key.slice.len().saturating_add(2);
        Ok(())
    }

    #[inline(always)]
    fn emit_inline_comments(
        &mut self,
        comments: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        if !self.minify && !comments.is_empty() {
            for c in comments {
                self.out
                    .push_byte(b' ')
                    .map_err(|msg| SyntaxError::new(msg, c.pos, input))?;
                emit_comment_raw(self.out, c.raw)
                    .map_err(|msg| SyntaxError::new(msg, c.pos, input))?;
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn emit_standalone_comments(
        &mut self,
        comments: &[CommentPiece<'a>],
        depth: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        if !self.minify && !comments.is_empty() {
            for c in comments {
                self.out
                    .push_byte(b'\n')
                    .map_err(|msg| SyntaxError::new(msg, c.pos, input))?;
                self.out
                    .push_indent(self.indent_table, depth)
                    .map_err(|msg| SyntaxError::new(msg, c.pos, input))?;
                emit_comment_raw(self.out, c.raw)
                    .map_err(|msg| SyntaxError::new(msg, c.pos, input))?;
            }
        }
        Ok(())
    }
}

impl<'a, 'b, S: OutputSink> ParseEvents<'a> for StreamEmitter<'a, 'b, S> {
    #[inline(always)]
    fn depth(&self) -> usize {
        self.stack.len()
    }

    #[inline(always)]
    fn top_container(&self) -> Option<ContainerKind> {
        match self.stack.last() {
            Some(StreamFrame::Object(_)) => Some(ContainerKind::Object),
            Some(StreamFrame::Array) => Some(ContainerKind::Array),
            None => None,
        }
    }

    #[inline(always)]
    fn on_root_leading_comments(
        &mut self,
        comments: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        if !self.minify {
            for c in comments {
                emit_comment_raw(self.out, c.raw)
                    .map_err(|msg| SyntaxError::new(msg, c.pos, input))?;
                self.out
                    .push_byte(b'\n')
                    .map_err(|msg| SyntaxError::new(msg, c.pos, input))?;
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn on_empty_object(
        &mut self,
        open_pos: usize,
        close_pos: usize,
        comments: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.last_key_len = 0;
        let depth = self.stack.len();
        self.out
            .push_byte(b'{')
            .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
        if !self.minify && !comments.is_empty() {
            self.emit_standalone_comments(comments, depth + 1, input)?;
            self.out
                .push_byte(b'\n')
                .map_err(|msg| SyntaxError::new(msg, close_pos, input))?;
            self.out
                .push_indent(self.indent_table, depth)
                .map_err(|msg| SyntaxError::new(msg, close_pos, input))?;
        }
        self.out
            .push_byte(b'}')
            .map_err(|msg| SyntaxError::new(msg, close_pos, input))
    }

    #[inline(always)]
    fn on_open_object(
        &mut self,
        open_pos: usize,
        open_comments: &[CommentPiece<'a>],
        first_leading: &[CommentPiece<'a>],
        first_key: KeyToken<'a>,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        let new_depth = self.stack.len() + 1;
        self.out
            .push_byte(b'{')
            .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
        self.emit_inline_comments(open_comments, input)?;
        self.emit_standalone_comments(first_leading, new_depth, input)?;
        if !self.minify {
            self.out
                .push_byte(b'\n')
                .map_err(|msg| SyntaxError::new(msg, first_key.key_pos, input))?;
            self.out
                .push_indent(self.indent_table, new_depth)
                .map_err(|msg| SyntaxError::new(msg, first_key.key_pos, input))?;
        }

        let mut key_set = self.free_sets.pop().unwrap_or_else(KeySet::new);
        let (_, added) = key_set.insert(decode_json_key_token(first_key));
        self.charge_key_bytes(added, first_key.key_pos, input)?;
        self.emit_key(first_key, input)?;
        self.stack.push(StreamFrame::Object(key_set));
        Ok(())
    }

    #[inline(always)]
    fn on_object_next_key(
        &mut self,
        comma_pos: usize,
        prev_trailing: &[CommentPiece<'a>],
        next_leading: &[CommentPiece<'a>],
        next_key: KeyToken<'a>,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        let depth = self.stack.len();
        let mut added_bytes = 0usize;
        if let Some(StreamFrame::Object(key_set)) = self.stack.last_mut() {
            let decoded = decode_json_key_token(next_key);
            let (inserted, added) = key_set.insert(decoded);
            if !inserted {
                return Err(SyntaxError::new(
                    "Duplicate object key is not allowed in JSON object",
                    next_key.key_pos,
                    input,
                ));
            }
            added_bytes = added;
        }
        self.charge_key_bytes(added_bytes, next_key.key_pos, input)?;
        self.out
            .push_byte(b',')
            .map_err(|msg| SyntaxError::new(msg, comma_pos, input))?;
        self.emit_inline_comments(prev_trailing, input)?;
        self.emit_standalone_comments(next_leading, depth, input)?;
        if !self.minify {
            self.out
                .push_byte(b'\n')
                .map_err(|msg| SyntaxError::new(msg, next_key.key_pos, input))?;
            self.out
                .push_indent(self.indent_table, depth)
                .map_err(|msg| SyntaxError::new(msg, next_key.key_pos, input))?;
        }
        self.emit_key(next_key, input)
    }

    #[inline(always)]
    fn on_close_object(
        &mut self,
        close_pos: usize,
        last_trailing: &[CommentPiece<'a>],
        inner_trailing: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.last_key_len = 0;
        let inner_depth = self.stack.len();
        self.emit_inline_comments(last_trailing, input)?;
        self.emit_standalone_comments(inner_trailing, inner_depth, input)?;
        if let Some(StreamFrame::Object(mut key_set)) = self.stack.pop() {
            let freed = key_set.clear();
            self.allocated_key_bytes = self.allocated_key_bytes.saturating_sub(freed);
            if self.free_sets.len() < MAX_FREE_KEY_SETS {
                self.free_sets.push(key_set);
            }
        }
        if !self.minify {
            self.out
                .push_byte(b'\n')
                .map_err(|msg| SyntaxError::new(msg, close_pos, input))?;
            self.out
                .push_indent(self.indent_table, self.stack.len())
                .map_err(|msg| SyntaxError::new(msg, close_pos, input))?;
        }
        self.out
            .push_byte(b'}')
            .map_err(|msg| SyntaxError::new(msg, close_pos, input))
    }

    #[inline(always)]
    fn on_empty_array(
        &mut self,
        open_pos: usize,
        close_pos: usize,
        comments: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.last_key_len = 0;
        let depth = self.stack.len();
        self.out
            .push_byte(b'[')
            .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
        if !self.minify && !comments.is_empty() {
            self.emit_standalone_comments(comments, depth + 1, input)?;
            self.out
                .push_byte(b'\n')
                .map_err(|msg| SyntaxError::new(msg, close_pos, input))?;
            self.out
                .push_indent(self.indent_table, depth)
                .map_err(|msg| SyntaxError::new(msg, close_pos, input))?;
        }
        self.out
            .push_byte(b']')
            .map_err(|msg| SyntaxError::new(msg, close_pos, input))
    }

    #[inline(always)]
    fn on_open_array(
        &mut self,
        open_pos: usize,
        open_comments: &[CommentPiece<'a>],
        first_leading: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.last_key_len = 0;
        let new_depth = self.stack.len() + 1;
        self.out
            .push_byte(b'[')
            .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
        self.emit_inline_comments(open_comments, input)?;
        self.emit_standalone_comments(first_leading, new_depth, input)?;
        if !self.minify {
            self.out
                .push_byte(b'\n')
                .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
            self.out
                .push_indent(self.indent_table, new_depth)
                .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
        }
        self.stack.push(StreamFrame::Array);
        Ok(())
    }

    #[inline(always)]
    fn on_array_comma(
        &mut self,
        comma_pos: usize,
        prev_trailing: &[CommentPiece<'a>],
        next_leading: &[CommentPiece<'a>],
        next_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.last_key_len = 0;
        let depth = self.stack.len();
        self.out
            .push_byte(b',')
            .map_err(|msg| SyntaxError::new(msg, comma_pos, input))?;
        self.emit_inline_comments(prev_trailing, input)?;
        self.emit_standalone_comments(next_leading, depth, input)?;
        if !self.minify {
            self.out
                .push_byte(b'\n')
                .map_err(|msg| SyntaxError::new(msg, next_pos, input))?;
            self.out
                .push_indent(self.indent_table, depth)
                .map_err(|msg| SyntaxError::new(msg, next_pos, input))?;
        }
        Ok(())
    }

    #[inline(always)]
    fn on_close_array(
        &mut self,
        close_pos: usize,
        last_trailing: &[CommentPiece<'a>],
        inner_trailing: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.last_key_len = 0;
        let inner_depth = self.stack.len();
        self.emit_inline_comments(last_trailing, input)?;
        self.emit_standalone_comments(inner_trailing, inner_depth, input)?;
        self.stack.pop();
        if !self.minify {
            self.out
                .push_byte(b'\n')
                .map_err(|msg| SyntaxError::new(msg, close_pos, input))?;
            self.out
                .push_indent(self.indent_table, self.stack.len())
                .map_err(|msg| SyntaxError::new(msg, close_pos, input))?;
        }
        self.out
            .push_byte(b']')
            .map_err(|msg| SyntaxError::new(msg, close_pos, input))
    }

    #[inline(always)]
    fn inline_array_budget(&self) -> Option<usize> {
        if self.minify || self.line_width == 0 {
            return None;
        }
        let prefix_cols = self
            .stack
            .len()
            .saturating_mul(self.indent_table.unit_len)
            .saturating_add(self.last_key_len);
        let budget = self
            .line_width
            .saturating_sub(prefix_cols.saturating_add(1));
        if budget >= 3 {
            Some(budget)
        } else {
            None
        }
    }

    #[inline(always)]
    fn on_inline_scalar_array(
        &mut self,
        open_pos: usize,
        items: &[&'a [u8]],
        close_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.last_key_len = 0;
        self.out
            .push_byte(b'[')
            .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
        for (idx, item) in items.iter().enumerate() {
            if idx > 0 {
                self.out
                    .extend_slice(b", ")
                    .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
            }
            self.out
                .extend_slice(item)
                .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
        }
        self.out
            .push_byte(b']')
            .map_err(|msg| SyntaxError::new(msg, close_pos, input))
    }

    #[inline(always)]
    fn on_primitive(
        &mut self,
        slice: &'a [u8],
        pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.last_key_len = 0;
        self.out
            .extend_slice(slice)
            .map_err(|msg| SyntaxError::new(msg, pos, input))
    }

    #[inline(always)]
    fn on_finish(
        &mut self,
        trailing_comments: &[CommentPiece<'a>],
        end_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        if !self.minify {
            for c in trailing_comments {
                if c.inline_with_prev {
                    self.out
                        .push_byte(b' ')
                        .map_err(|msg| SyntaxError::new(msg, c.pos, input))?;
                } else {
                    self.out
                        .push_byte(b'\n')
                        .map_err(|msg| SyntaxError::new(msg, c.pos, input))?;
                }
                emit_comment_raw(self.out, c.raw)
                    .map_err(|msg| SyntaxError::new(msg, c.pos, input))?;
            }
        }
        self.out
            .push_byte(b'\n')
            .map_err(|msg| SyntaxError::new(msg, end_pos, input))
    }
}

struct SortedArrayItem<'a> {
    leading_comments: Vec<CommentPiece<'a>>,
    trailing_comments: Vec<CommentPiece<'a>>,
    value: SortedValue<'a>,
}

struct SortedEntry<'a> {
    leading_comments: Vec<CommentPiece<'a>>,
    trailing_comments: Vec<CommentPiece<'a>>,
    sort_key: Cow<'a, str>,
    raw_key: &'a [u8],
    key_pos: usize,
    value: SortedValue<'a>,
}

enum SortedValue<'a> {
    Raw(&'a [u8]),
    Array {
        open_comments: Vec<CommentPiece<'a>>,
        items: Vec<SortedArrayItem<'a>>,
        inner_trailing_comments: Vec<CommentPiece<'a>>,
    },
    Object {
        open_comments: Vec<CommentPiece<'a>>,
        entries: Vec<SortedEntry<'a>>,
        inner_trailing_comments: Vec<CommentPiece<'a>>,
    },
}

enum SortBuildFrame<'a> {
    Object {
        open_comments: Vec<CommentPiece<'a>>,
        entries: Vec<SortedEntry<'a>>,
        pending_leading: Vec<CommentPiece<'a>>,
        pending_key: (Cow<'a, str>, &'a [u8], usize),
    },
    Array {
        open_comments: Vec<CommentPiece<'a>>,
        items: Vec<SortedArrayItem<'a>>,
        pending_leading: Vec<CommentPiece<'a>>,
    },
}

/// Bounded DOM builder for `--sort-keys` that tracks in-memory node and comment allocations and checks
/// duplicate keys via adjacent sorted pairs without cloning keys or allocating `HashSet`s (IMP-04).
struct SortedDomBuilder<'a> {
    stack: Vec<SortBuildFrame<'a>>,
    current_val: Option<SortedValue<'a>>,
    root_leading_comments: Vec<CommentPiece<'a>>,
    root_trailing_comments: Vec<CommentPiece<'a>>,
    allocated_dom_bytes: usize,
    max_dom_bytes: usize,
}

impl<'a> SortedDomBuilder<'a> {
    fn new(max_dom_bytes: usize) -> Self {
        Self {
            stack: Vec::with_capacity(32),
            current_val: None,
            root_leading_comments: Vec::new(),
            root_trailing_comments: Vec::new(),
            allocated_dom_bytes: 0,
            max_dom_bytes,
        }
    }

    #[inline(always)]
    fn charge_dom_bytes(
        &mut self,
        bytes: usize,
        pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.allocated_dom_bytes = self.allocated_dom_bytes.saturating_add(bytes);
        if self.allocated_dom_bytes > self.max_dom_bytes {
            Err(SyntaxError::new(
                "Formatted output exceeds maximum allowed buffer size",
                pos,
                input,
            ))
        } else {
            Ok(())
        }
    }

    #[inline(always)]
    fn charge_comments(
        &mut self,
        comments: &[CommentPiece<'a>],
        fallback_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        if !comments.is_empty() {
            let pos = comments[0].pos;
            let bytes = comments.len().saturating_mul(size_of::<CommentPiece<'a>>());
            self.charge_dom_bytes(bytes, pos, input)?;
        } else {
            let _ = fallback_pos;
        }
        Ok(())
    }

    #[inline(always)]
    fn commit_object_entry(&mut self, trailing_comments: &[CommentPiece<'a>]) {
        let val = self.current_val.take().expect("Expected completed value");
        if let Some(SortBuildFrame::Object {
            entries,
            pending_leading,
            pending_key,
            ..
        }) = self.stack.last_mut()
        {
            let (sort_key, raw_key, key_pos) =
                std::mem::replace(pending_key, (Cow::Borrowed(""), &[], 0));
            let leading_comments = std::mem::take(pending_leading);
            entries.push(SortedEntry {
                leading_comments,
                trailing_comments: trailing_comments.to_vec(),
                sort_key,
                raw_key,
                key_pos,
                value: val,
            });
        }
    }

    #[inline(always)]
    fn commit_array_item(&mut self, trailing_comments: &[CommentPiece<'a>]) {
        let val = self.current_val.take().expect("Expected completed value");
        if let Some(SortBuildFrame::Array {
            items,
            pending_leading,
            ..
        }) = self.stack.last_mut()
        {
            let leading_comments = std::mem::take(pending_leading);
            items.push(SortedArrayItem {
                leading_comments,
                trailing_comments: trailing_comments.to_vec(),
                value: val,
            });
        }
    }
}

impl<'a> ParseEvents<'a> for SortedDomBuilder<'a> {
    #[inline(always)]
    fn depth(&self) -> usize {
        self.stack.len()
    }

    #[inline(always)]
    fn top_container(&self) -> Option<ContainerKind> {
        match self.stack.last() {
            Some(SortBuildFrame::Object { .. }) => Some(ContainerKind::Object),
            Some(SortBuildFrame::Array { .. }) => Some(ContainerKind::Array),
            None => None,
        }
    }

    #[inline(always)]
    fn on_root_leading_comments(
        &mut self,
        comments: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.charge_comments(comments, 0, input)?;
        self.root_leading_comments.extend_from_slice(comments);
        Ok(())
    }

    #[inline(always)]
    fn on_empty_object(
        &mut self,
        open_pos: usize,
        _close_pos: usize,
        comments: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.charge_dom_bytes(size_of::<SortedValue<'a>>(), open_pos, input)?;
        self.charge_comments(comments, open_pos, input)?;
        self.current_val = Some(SortedValue::Object {
            open_comments: Vec::new(),
            entries: Vec::new(),
            inner_trailing_comments: comments.to_vec(),
        });
        Ok(())
    }

    #[inline(always)]
    fn on_open_object(
        &mut self,
        open_pos: usize,
        open_comments: &[CommentPiece<'a>],
        first_leading: &[CommentPiece<'a>],
        first_key: KeyToken<'a>,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.charge_comments(open_comments, open_pos, input)?;
        self.charge_comments(first_leading, first_key.key_pos, input)?;
        let sort_key = decode_json_key_token(first_key);
        let owned_len = match &sort_key {
            Cow::Borrowed(_) => 0,
            Cow::Owned(s) => s.len(),
        };
        self.charge_dom_bytes(
            size_of::<SortedEntry<'a>>().saturating_add(owned_len),
            first_key.key_pos,
            input,
        )?;
        self.stack.push(SortBuildFrame::Object {
            open_comments: open_comments.to_vec(),
            entries: Vec::new(),
            pending_leading: first_leading.to_vec(),
            pending_key: (sort_key, first_key.slice, first_key.key_pos),
        });
        Ok(())
    }

    #[inline(always)]
    fn on_object_next_key(
        &mut self,
        comma_pos: usize,
        prev_trailing: &[CommentPiece<'a>],
        next_leading: &[CommentPiece<'a>],
        next_key: KeyToken<'a>,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.charge_comments(prev_trailing, comma_pos, input)?;
        self.charge_comments(next_leading, next_key.key_pos, input)?;
        self.commit_object_entry(prev_trailing);
        let sort_key = decode_json_key_token(next_key);
        let owned_len = match &sort_key {
            Cow::Borrowed(_) => 0,
            Cow::Owned(s) => s.len(),
        };
        let entry_key_overhead = size_of::<SortedEntry<'a>>() - size_of::<SortedValue<'a>>();
        self.charge_dom_bytes(
            entry_key_overhead.saturating_add(owned_len),
            next_key.key_pos,
            input,
        )?;
        if let Some(SortBuildFrame::Object {
            pending_leading,
            pending_key,
            ..
        }) = self.stack.last_mut()
        {
            *pending_leading = next_leading.to_vec();
            *pending_key = (sort_key, next_key.slice, next_key.key_pos);
        }
        Ok(())
    }

    #[inline(always)]
    fn on_close_object(
        &mut self,
        close_pos: usize,
        last_trailing: &[CommentPiece<'a>],
        inner_trailing: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.charge_comments(last_trailing, close_pos, input)?;
        self.charge_comments(inner_trailing, close_pos, input)?;
        self.commit_object_entry(last_trailing);
        if let Some(SortBuildFrame::Object {
            open_comments,
            mut entries,
            ..
        }) = self.stack.pop()
        {
            entries.sort_by(|a, b| {
                a.sort_key
                    .as_ref()
                    .cmp(b.sort_key.as_ref())
                    .then_with(|| a.key_pos.cmp(&b.key_pos))
            });
            // Detect duplicate keys in adjacent sorted order and report the earliest duplicate key_pos (IMP-04)
            let mut earliest_dup_pos: Option<usize> = None;
            for pair in entries.windows(2) {
                if pair[0].sort_key == pair[1].sort_key {
                    let dup_pos = pair[1].key_pos;
                    earliest_dup_pos = Some(match earliest_dup_pos {
                        Some(prev) => prev.min(dup_pos),
                        None => dup_pos,
                    });
                }
            }
            if let Some(dup_pos) = earliest_dup_pos {
                return Err(SyntaxError::new(
                    "Duplicate object key is not allowed in JSON object",
                    dup_pos,
                    input,
                ));
            }
            self.current_val = Some(SortedValue::Object {
                open_comments,
                entries,
                inner_trailing_comments: inner_trailing.to_vec(),
            });
        }
        Ok(())
    }

    #[inline(always)]
    fn on_empty_array(
        &mut self,
        open_pos: usize,
        _close_pos: usize,
        comments: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.charge_dom_bytes(size_of::<SortedValue<'a>>(), open_pos, input)?;
        self.charge_comments(comments, open_pos, input)?;
        self.current_val = Some(SortedValue::Array {
            open_comments: Vec::new(),
            items: Vec::new(),
            inner_trailing_comments: comments.to_vec(),
        });
        Ok(())
    }

    #[inline(always)]
    fn on_open_array(
        &mut self,
        open_pos: usize,
        open_comments: &[CommentPiece<'a>],
        first_leading: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        let item_overhead = size_of::<SortedArrayItem<'a>>() - size_of::<SortedValue<'a>>();
        self.charge_dom_bytes(
            size_of::<SortedValue<'a>>().saturating_add(item_overhead),
            open_pos,
            input,
        )?;
        self.charge_comments(open_comments, open_pos, input)?;
        self.charge_comments(first_leading, open_pos, input)?;
        self.stack.push(SortBuildFrame::Array {
            open_comments: open_comments.to_vec(),
            items: Vec::new(),
            pending_leading: first_leading.to_vec(),
        });
        Ok(())
    }

    #[inline(always)]
    fn on_array_comma(
        &mut self,
        comma_pos: usize,
        prev_trailing: &[CommentPiece<'a>],
        next_leading: &[CommentPiece<'a>],
        next_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        let item_overhead = size_of::<SortedArrayItem<'a>>() - size_of::<SortedValue<'a>>();
        self.charge_dom_bytes(item_overhead, next_pos, input)?;
        self.charge_comments(prev_trailing, comma_pos, input)?;
        self.charge_comments(next_leading, next_pos, input)?;
        self.commit_array_item(prev_trailing);
        if let Some(SortBuildFrame::Array {
            pending_leading, ..
        }) = self.stack.last_mut()
        {
            *pending_leading = next_leading.to_vec();
        }
        Ok(())
    }

    #[inline(always)]
    fn on_close_array(
        &mut self,
        close_pos: usize,
        last_trailing: &[CommentPiece<'a>],
        inner_trailing: &[CommentPiece<'a>],
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.charge_comments(last_trailing, close_pos, input)?;
        self.charge_comments(inner_trailing, close_pos, input)?;
        self.commit_array_item(last_trailing);
        if let Some(SortBuildFrame::Array {
            open_comments,
            items,
            ..
        }) = self.stack.pop()
        {
            self.current_val = Some(SortedValue::Array {
                open_comments,
                items,
                inner_trailing_comments: inner_trailing.to_vec(),
            });
        }
        Ok(())
    }

    #[inline(always)]
    fn on_primitive(
        &mut self,
        slice: &'a [u8],
        pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.charge_dom_bytes(size_of::<SortedValue<'a>>(), pos, input)?;
        self.current_val = Some(SortedValue::Raw(slice));
        Ok(())
    }

    #[inline(always)]
    fn on_finish(
        &mut self,
        trailing_comments: &[CommentPiece<'a>],
        end_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.charge_comments(trailing_comments, end_pos, input)?;
        self.root_trailing_comments
            .extend_from_slice(trailing_comments);
        Ok(())
    }
}

struct Scanner<'a> {
    input: &'a [u8],
    pos: usize,
    allow_comments: bool,
    max_scratch_bytes: usize,
    last_string_has_escapes: bool,
    defer_line_col: bool,
}

impl<'a> Scanner<'a> {
    #[inline]
    fn new(input: &'a [u8], allow_comments: bool, max_scratch_bytes: usize) -> Self {
        Self {
            input,
            pos: 0,
            allow_comments,
            max_scratch_bytes,
            last_string_has_escapes: false,
            defer_line_col: false,
        }
    }

    #[inline]
    fn err(&self, message: &'static str, offset: usize) -> SyntaxError {
        if self.defer_line_col {
            SyntaxError {
                message: message.into(),
                offset: offset.min(self.input.len()),
                line: 0,
                col: 0,
            }
        } else {
            SyntaxError::new(message, offset, self.input)
        }
    }

    /// Scans RFC 8259 insignificant whitespace (`0x20`, `0x09`, `0x0A`, `0x0D`) with an 8-byte
    /// SWAR fast-path and, when `self.allow_comments` is enabled, `//` single-line and `/* ... */`
    /// block comments (PERF-04).
    #[inline]
    fn scan_trivia(
        &mut self,
        has_prev_token: bool,
        out: &mut Vec<CommentPiece<'a>>,
    ) -> Result<(), SyntaxError> {
        let mut saw_newline = !has_prev_token;

        while self.pos < self.input.len() {
            // Hardware SIMD (AVX2 / NEON) + 8-byte SWAR fast-path for contiguous space runs (PERF-04 / PERF-09)
            self.pos += skip_ascii_spaces(&self.input[self.pos..]);

            if self.pos >= self.input.len() {
                break;
            }

            match self.input[self.pos] {
                b' ' | b'\t' | b'\r' => {
                    self.pos += 1;
                }
                b'\n' => {
                    self.pos += 1;
                    saw_newline = true;
                }
                b'/' => {
                    if !self.allow_comments {
                        return Err(
                            self.err("Comments are not allowed in strict RFC 8259 mode", self.pos)
                        );
                    }
                    let comment_pos = self.pos;
                    let inline_with_prev = !saw_newline;
                    let next = self.input.get(self.pos + 1).copied();
                    let raw = match next {
                        Some(b'/') => {
                            let slice = self.scan_line_comment()?;
                            saw_newline = true;
                            slice
                        }
                        Some(b'*') => {
                            let slice = self.scan_block_comment()?;
                            if slice.contains(&b'\n') {
                                saw_newline = true;
                            }
                            slice
                        }
                        _ => {
                            return Err(self.err(
                                "Unexpected '/' in JSON input, expected '//' or '/*'",
                                self.pos,
                            ));
                        }
                    };
                    let next_bytes = out
                        .len()
                        .saturating_add(1)
                        .saturating_mul(size_of::<CommentPiece<'a>>());
                    if next_bytes > self.max_scratch_bytes {
                        return Err(self.err(
                            "Formatted output exceeds maximum allowed buffer size",
                            comment_pos,
                        ));
                    }
                    out.push(CommentPiece {
                        raw,
                        pos: comment_pos,
                        inline_with_prev,
                    });
                }
                _ => break,
            }
        }

        Ok(())
    }

    fn scan_line_comment(&mut self) -> Result<&'a [u8], SyntaxError> {
        let start = self.pos;
        self.pos += 2; // Skip `//`

        while self.pos < self.input.len() {
            while self.pos + 8 <= self.input.len() {
                let chunk =
                    u64::from_ne_bytes(self.input[self.pos..self.pos + 8].try_into().unwrap());
                if is_plain_ascii_line_comment_chunk(chunk) {
                    self.pos += 8;
                } else {
                    break;
                }
            }
            if self.pos >= self.input.len() {
                break;
            }
            let b = self.input[self.pos];
            if b == b'\n' {
                break;
            }
            if b == b'\r' {
                if self.input.get(self.pos + 1) == Some(&b'\n') {
                    break;
                }
                return Err(self.err("Control character is not allowed in JSON comment", self.pos));
            }
            if b < 0x20 && b != b'\t' {
                return Err(self.err("Control character is not allowed in JSON comment", self.pos));
            }
            if b < 0x80 {
                self.pos += 1;
            } else {
                let char_len = validate_utf8_char(&self.input[self.pos..])
                    .ok_or_else(|| self.err("Invalid UTF-8 byte sequence in comment", self.pos))?;
                self.pos += char_len;
            }
        }

        Ok(&self.input[start..self.pos])
    }

    fn scan_block_comment(&mut self) -> Result<&'a [u8], SyntaxError> {
        let start = self.pos;
        self.pos += 2; // Skip `/*`

        while self.pos < self.input.len() {
            while self.pos + 8 <= self.input.len() {
                let chunk =
                    u64::from_ne_bytes(self.input[self.pos..self.pos + 8].try_into().unwrap());
                if is_plain_ascii_block_comment_chunk(chunk) {
                    self.pos += 8;
                } else {
                    break;
                }
            }
            if self.pos >= self.input.len() {
                break;
            }
            let b = self.input[self.pos];
            if b == b'*' && self.input.get(self.pos + 1) == Some(&b'/') {
                self.pos += 2;
                return Ok(&self.input[start..self.pos]);
            }
            if b == b'\r' {
                if self.input.get(self.pos + 1) != Some(&b'\n') {
                    return Err(
                        self.err("Control character is not allowed in JSON comment", self.pos)
                    );
                }
                self.pos += 1;
                continue;
            }
            if b < 0x20 && b != b'\t' && b != b'\n' {
                return Err(self.err("Control character is not allowed in JSON comment", self.pos));
            }
            if b < 0x80 {
                self.pos += 1;
            } else {
                let char_len = validate_utf8_char(&self.input[self.pos..])
                    .ok_or_else(|| self.err("Invalid UTF-8 byte sequence in comment", self.pos))?;
                self.pos += char_len;
            }
        }

        Err(self.err("Unterminated block comment", start))
    }

    /// Unified single-pass iterative RFC 8259 / JSONC parser driving `ParseEvents` (IMP-06 / PERF-04).
    fn run_unified_parser<E: ParseEvents<'a>>(
        &mut self,
        events: &mut E,
    ) -> Result<(), SyntaxError> {
        // ADR-02 / IMP-08: Explicitly reject UTF-8 BOM at offset 0
        if self.input.starts_with(b"\xEF\xBB\xBF") {
            return Err(self.err(
                "UTF-8 BOM (byte order mark) is not allowed in RFC 8259 JSON",
                0,
            ));
        }

        let mut trivia_a: Vec<CommentPiece<'a>> = Vec::new();
        let mut trivia_b: Vec<CommentPiece<'a>> = Vec::new();
        let mut combined_inline: Vec<CommentPiece<'a>> = Vec::new();
        let mut combined_leading: Vec<CommentPiece<'a>> = Vec::new();
        let mut inline_items: Vec<&'a [u8]> = Vec::new();

        self.scan_trivia(false, &mut trivia_a)?;
        if self.pos >= self.input.len() {
            return Err(self.err("Unexpected end of JSON input", self.pos));
        }
        if !trivia_a.is_empty() {
            events.on_root_leading_comments(&trivia_a, self.input)?;
            trivia_a.clear();
        }

        'expect_value: loop {
            if self.pos >= self.input.len() {
                return Err(self.err("Expected JSON value, found end of input", self.pos));
            }

            // Descend into any nested non-empty objects or arrays iteratively
            loop {
                let b = self.input[self.pos];
                if b == b'{' {
                    let open_pos = self.pos;
                    let new_depth = events.depth() + 1;
                    if new_depth > MAX_DEPTH {
                        return Err(self.err("Maximum nesting depth of 512 exceeded", open_pos));
                    }
                    self.pos += 1;
                    self.scan_trivia(true, &mut trivia_a)?;

                    if self.pos >= self.input.len() {
                        return Err(self.err("Unterminated JSON object", open_pos));
                    }
                    if self.input[self.pos] == b'}' {
                        let close_pos = self.pos;
                        self.pos += 1;
                        events.on_empty_object(open_pos, close_pos, &trivia_a, self.input)?;
                        if !trivia_a.is_empty() {
                            trivia_a.clear();
                        }
                        break; // Completed empty `{}` value
                    }

                    if trivia_a.is_empty() {
                        let first_key = self.scan_key_and_colon(&mut combined_leading)?;
                        events.on_open_object(
                            open_pos,
                            &[],
                            &combined_leading,
                            first_key,
                            self.input,
                        )?;
                        if !combined_leading.is_empty() {
                            combined_leading.clear();
                        }
                    } else {
                        let (open_comments, standalone_before_key) =
                            split_inline_comments(&trivia_a);
                        combined_leading.extend_from_slice(standalone_before_key);
                        let first_key = self.scan_key_and_colon(&mut combined_leading)?;
                        events.on_open_object(
                            open_pos,
                            open_comments,
                            &combined_leading,
                            first_key,
                            self.input,
                        )?;
                        trivia_a.clear();
                        combined_leading.clear();
                    }
                    if self.pos >= self.input.len() {
                        return Err(self.err("Expected JSON value after ':'", self.pos));
                    }
                } else if b == b'[' {
                    let open_pos = self.pos;
                    let new_depth = events.depth() + 1;
                    if new_depth > MAX_DEPTH {
                        return Err(self.err("Maximum nesting depth of 512 exceeded", open_pos));
                    }
                    self.pos += 1;
                    self.scan_trivia(true, &mut trivia_a)?;

                    if self.pos >= self.input.len() {
                        return Err(self.err("Unterminated JSON array", open_pos));
                    }
                    if self.input[self.pos] == b']' {
                        let close_pos = self.pos;
                        self.pos += 1;
                        events.on_empty_array(open_pos, close_pos, &trivia_a, self.input)?;
                        if !trivia_a.is_empty() {
                            trivia_a.clear();
                        }
                        break; // Completed empty `[]` value
                    }

                    if trivia_a.is_empty() {
                        if let Some(budget) = events.inline_array_budget() {
                            if self.try_emit_inline_scalar_array(
                                open_pos,
                                budget,
                                &mut inline_items,
                                events,
                            )? {
                                break; // Completed inline scalar `[a, b, c]` value
                            }
                        }
                        events.on_open_array(open_pos, &[], &[], self.input)?;
                    } else {
                        let (open_comments, first_leading) = split_inline_comments(&trivia_a);
                        events.on_open_array(open_pos, open_comments, first_leading, self.input)?;
                        trivia_a.clear();
                    }
                } else {
                    let prim_pos = self.pos;
                    let slice = self.scan_primitive()?;
                    events.on_primitive(slice, prim_pos, self.input)?;
                    break;
                }
            }

            // Completed a value; now handle continuation or closing of enclosing containers
            while let Some(container) = events.top_container() {
                self.scan_trivia(true, &mut trivia_a)?;
                match container {
                    ContainerKind::Object => {
                        if self.pos >= self.input.len() {
                            return Err(self.err("Unterminated JSON object", self.pos));
                        }
                        match self.input[self.pos] {
                            b',' => {
                                let comma_pos = self.pos;
                                self.pos += 1;
                                if trivia_a.is_empty() {
                                    self.scan_trivia(true, &mut trivia_b)?;
                                    if self.pos >= self.input.len() {
                                        return Err(self.err("Unterminated JSON object", self.pos));
                                    }
                                    if self.input[self.pos] == b'}' {
                                        return Err(self.err(
                                            "Trailing comma is not allowed in JSON object",
                                            comma_pos,
                                        ));
                                    }
                                    if trivia_b.is_empty() {
                                        let next_key =
                                            self.scan_key_and_colon(&mut combined_leading)?;
                                        events.on_object_next_key(
                                            comma_pos,
                                            &[],
                                            &combined_leading,
                                            next_key,
                                            self.input,
                                        )?;
                                        if !combined_leading.is_empty() {
                                            combined_leading.clear();
                                        }
                                        if self.pos >= self.input.len() {
                                            return Err(
                                                self.err("Expected JSON value after ':'", self.pos)
                                            );
                                        }
                                        continue 'expect_value;
                                    }
                                }

                                let (inline_before, standalone_before) =
                                    split_inline_comments(&trivia_a);
                                let has_newline_in_inline_before = inline_before
                                    .iter()
                                    .any(|c| c.raw.starts_with(b"//") || c.raw.contains(&b'\n'));
                                if !trivia_a.is_empty() {
                                    self.scan_trivia(!has_newline_in_inline_before, &mut trivia_b)?;
                                    if self.pos >= self.input.len() {
                                        return Err(self.err("Unterminated JSON object", self.pos));
                                    }
                                    if self.input[self.pos] == b'}' {
                                        return Err(self.err(
                                            "Trailing comma is not allowed in JSON object",
                                            comma_pos,
                                        ));
                                    }
                                }
                                let (inline_after, standalone_after) =
                                    split_inline_comments(&trivia_b);

                                combined_inline.extend_from_slice(inline_before);
                                combined_inline.extend_from_slice(inline_after);

                                combined_leading.extend_from_slice(standalone_before);
                                combined_leading.extend_from_slice(standalone_after);

                                let next_key = self.scan_key_and_colon(&mut combined_leading)?;
                                events.on_object_next_key(
                                    comma_pos,
                                    &combined_inline,
                                    &combined_leading,
                                    next_key,
                                    self.input,
                                )?;
                                trivia_a.clear();
                                trivia_b.clear();
                                combined_inline.clear();
                                combined_leading.clear();
                                if self.pos >= self.input.len() {
                                    return Err(self.err("Expected JSON value after ':'", self.pos));
                                }
                                continue 'expect_value;
                            }
                            b'}' => {
                                let close_pos = self.pos;
                                self.pos += 1;
                                if trivia_a.is_empty() {
                                    events.on_close_object(close_pos, &[], &[], self.input)?;
                                } else {
                                    let (last_trailing, inner_trailing) =
                                        split_inline_comments(&trivia_a);
                                    events.on_close_object(
                                        close_pos,
                                        last_trailing,
                                        inner_trailing,
                                        self.input,
                                    )?;
                                    trivia_a.clear();
                                }
                            }
                            _ => {
                                return Err(
                                    self.err("Expected ',' or '}' in JSON object", self.pos)
                                );
                            }
                        }
                    }
                    ContainerKind::Array => {
                        if self.pos >= self.input.len() {
                            return Err(self.err("Unterminated JSON array", self.pos));
                        }
                        match self.input[self.pos] {
                            b',' => {
                                let comma_pos = self.pos;
                                self.pos += 1;
                                if trivia_a.is_empty() {
                                    self.scan_trivia(true, &mut trivia_b)?;
                                    if self.pos >= self.input.len() {
                                        return Err(self.err("Unterminated JSON array", self.pos));
                                    }
                                    if self.input[self.pos] == b']' {
                                        return Err(self.err(
                                            "Trailing comma is not allowed in JSON array",
                                            comma_pos,
                                        ));
                                    }
                                    if trivia_b.is_empty() {
                                        events.on_array_comma(
                                            comma_pos,
                                            &[],
                                            &[],
                                            self.pos,
                                            self.input,
                                        )?;
                                        continue 'expect_value;
                                    }
                                }

                                let (inline_before, standalone_before) =
                                    split_inline_comments(&trivia_a);
                                let has_newline_in_inline_before = inline_before
                                    .iter()
                                    .any(|c| c.raw.starts_with(b"//") || c.raw.contains(&b'\n'));
                                if !trivia_a.is_empty() {
                                    self.scan_trivia(!has_newline_in_inline_before, &mut trivia_b)?;
                                    if self.pos >= self.input.len() {
                                        return Err(self.err("Unterminated JSON array", self.pos));
                                    }
                                    if self.input[self.pos] == b']' {
                                        return Err(self.err(
                                            "Trailing comma is not allowed in JSON array",
                                            comma_pos,
                                        ));
                                    }
                                }
                                let (inline_after, standalone_after) =
                                    split_inline_comments(&trivia_b);

                                combined_inline.extend_from_slice(inline_before);
                                combined_inline.extend_from_slice(inline_after);

                                combined_leading.extend_from_slice(standalone_before);
                                combined_leading.extend_from_slice(standalone_after);

                                events.on_array_comma(
                                    comma_pos,
                                    &combined_inline,
                                    &combined_leading,
                                    self.pos,
                                    self.input,
                                )?;
                                trivia_a.clear();
                                trivia_b.clear();
                                combined_inline.clear();
                                combined_leading.clear();
                                continue 'expect_value;
                            }
                            b']' => {
                                let close_pos = self.pos;
                                self.pos += 1;
                                if trivia_a.is_empty() {
                                    events.on_close_array(close_pos, &[], &[], self.input)?;
                                } else {
                                    let (last_trailing, inner_trailing) =
                                        split_inline_comments(&trivia_a);
                                    events.on_close_array(
                                        close_pos,
                                        last_trailing,
                                        inner_trailing,
                                        self.input,
                                    )?;
                                    trivia_a.clear();
                                }
                            }
                            _ => {
                                return Err(self.err("Expected ',' or ']' in JSON array", self.pos));
                            }
                        }
                    }
                }
            }

            break 'expect_value;
        }

        self.scan_trivia(true, &mut trivia_a)?;
        if self.pos < self.input.len() {
            return Err(self.err("Trailing data after root JSON value", self.pos));
        }

        events.on_finish(&trivia_a, self.pos, self.input)
    }

    #[inline(always)]
    fn skip_ws_no_comments(&mut self) -> bool {
        while self.pos < self.input.len() {
            self.pos += skip_ascii_spaces(&self.input[self.pos..]);
            if self.pos >= self.input.len() {
                break;
            }
            match self.input[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => {
                    self.pos += 1;
                }
                b'/' => return false,
                _ => break,
            }
        }
        true
    }

    /// Bounded $O(1)$ scalar-only lookahead probe for width-aware inline array formatting.
    /// Immediately bails out and restores `self.pos` on any nested `{`/`[`, `/` comment,
    /// syntax error, or element that pushes the inline length past `budget`.
    fn try_emit_inline_scalar_array<E: ParseEvents<'a>>(
        &mut self,
        open_pos: usize,
        budget: usize,
        inline_items: &mut Vec<&'a [u8]>,
        events: &mut E,
    ) -> Result<bool, SyntaxError> {
        let budget = budget.min(MAX_LINE_WIDTH);
        if budget < 3 {
            return Ok(false);
        }

        let saved_pos = self.pos;
        inline_items.clear();
        let mut inline_len = 2usize; // '[' and ']'

        loop {
            if self.pos >= self.input.len() {
                self.pos = saved_pos;
                return Ok(false);
            }

            let b = self.input[self.pos];
            if b == b'{' || b == b'[' || b == b']' || b == b'/' {
                self.pos = saved_pos;
                return Ok(false);
            }

            let sep_len = if inline_items.is_empty() { 0 } else { 2 }; // ", "
            if inline_len.saturating_add(sep_len) >= budget {
                self.pos = saved_pos;
                return Ok(false);
            }
            inline_len += sep_len;
            let rem_budget = budget - inline_len;

            let item_start = self.pos;
            let window_end = item_start
                .saturating_add(rem_budget)
                .saturating_add(1)
                .min(self.input.len());
            let mut sub = Scanner {
                input: &self.input[..window_end],
                pos: item_start,
                allow_comments: self.allow_comments,
                max_scratch_bytes: self.max_scratch_bytes,
                last_string_has_escapes: false,
                defer_line_col: true,
            };
            let Ok(slice) = sub.scan_primitive() else {
                self.pos = saved_pos;
                return Ok(false);
            };
            if slice.len() > rem_budget {
                self.pos = saved_pos;
                return Ok(false);
            }
            self.pos = sub.pos;
            inline_len += slice.len();
            inline_items.push(slice);

            if !self.skip_ws_no_comments() || self.pos >= self.input.len() {
                self.pos = saved_pos;
                return Ok(false);
            }

            match self.input[self.pos] {
                b',' => {
                    self.pos += 1;
                    if !self.skip_ws_no_comments() || self.pos >= self.input.len() {
                        self.pos = saved_pos;
                        return Ok(false);
                    }
                }
                b']' => {
                    let close_pos = self.pos;
                    self.pos += 1;
                    events.on_inline_scalar_array(open_pos, inline_items, close_pos, self.input)?;
                    return Ok(true);
                }
                _ => {
                    self.pos = saved_pos;
                    return Ok(false);
                }
            }
        }
    }

    #[inline(always)]
    fn scan_key_and_colon(
        &mut self,
        leading_comments: &mut Vec<CommentPiece<'a>>,
    ) -> Result<KeyToken<'a>, SyntaxError> {
        let key_pos = self.pos;
        let slice = self.scan_object_key()?;
        let has_escapes = self.last_string_has_escapes;
        self.scan_trivia(false, leading_comments)?;
        if self.pos >= self.input.len() || self.input[self.pos] != b':' {
            return Err(self.err("Expected ':' after object key", self.pos));
        }
        let colon_pos = self.pos;
        self.pos += 1;
        self.scan_trivia(false, leading_comments)?;
        Ok(KeyToken {
            slice,
            key_pos,
            colon_pos,
            has_escapes,
        })
    }

    fn scan_object_key(&mut self) -> Result<&'a [u8], SyntaxError> {
        if self.pos >= self.input.len() {
            return Err(self.err("Expected object key, found end of input", self.pos));
        }
        match self.input[self.pos] {
            b'"' => self.scan_string(),
            b'\'' => Err(self.err("Single-quoted strings are not allowed in JSON", self.pos)),
            b',' => Err(self.err("Unexpected comma in JSON object", self.pos)),
            _ => Err(self.err("Object keys must be double-quoted strings", self.pos)),
        }
    }

    fn scan_primitive(&mut self) -> Result<&'a [u8], SyntaxError> {
        let b = self.input[self.pos];
        match b {
            b'"' => self.scan_string(),
            b'-' | b'0'..=b'9' => self.scan_number(),
            b't' => self.scan_literal(b"true", "Invalid literal, expected 'true'"),
            b'f' => self.scan_literal(b"false", "Invalid literal, expected 'false'"),
            b'n' => self.scan_literal(b"null", "Invalid literal, expected 'null'"),
            b'\'' => Err(self.err("Single-quoted strings are not allowed in JSON", self.pos)),
            b'+' => Err(self.err("Leading '+' sign is not allowed in JSON numbers", self.pos)),
            b'.' => Err(self.err(
                "Leading decimal point is not allowed in JSON numbers",
                self.pos,
            )),
            b',' => Err(self.err("Unexpected comma, expected a JSON value", self.pos)),
            b'}' => Err(self.err("Unexpected '}' without matching '{'", self.pos)),
            b']' => Err(self.err("Unexpected ']' without matching '['", self.pos)),
            _ => Err(self.err("Unexpected token in JSON input", self.pos)),
        }
    }

    fn scan_literal(
        &mut self,
        expected: &'static [u8],
        err_msg: &'static str,
    ) -> Result<&'a [u8], SyntaxError> {
        let start = self.pos;
        if self.input[start..].starts_with(expected) {
            let end = start + expected.len();
            if end < self.input.len() && is_ident_continue(self.input[end]) {
                return Err(self.err(err_msg, start));
            }
            self.pos = end;
            Ok(&self.input[start..end])
        } else {
            Err(self.err(err_msg, start))
        }
    }

    /// Strict RFC 8259 number state machine:
    /// `[-]? (0 | [1-9][0-9]*) (\.[0-9]+)? ([eE][+-]?[0-9]+)?`
    fn scan_number(&mut self) -> Result<&'a [u8], SyntaxError> {
        let start = self.pos;

        if self.input[self.pos] == b'-' {
            self.pos += 1;
            if self.pos >= self.input.len() {
                return Err(self.err("Unexpected end of input after '-' in number", start));
            }
            if self.input[self.pos] == b'.' {
                return Err(self.err(
                    "Leading decimal point is not allowed in JSON numbers",
                    self.pos,
                ));
            }
        }

        match self.input[self.pos] {
            b'0' => {
                self.pos += 1;
                if self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
                    return Err(self.err("Leading zeros are not allowed in JSON numbers", start));
                }
            }
            b'1'..=b'9' => {
                self.pos += 1;
                while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
                    self.pos += 1;
                }
            }
            _ => {
                return Err(self.err("Invalid JSON number", start));
            }
        }

        if self.pos < self.input.len() && self.input[self.pos] == b'.' {
            let dot_pos = self.pos;
            self.pos += 1;
            if self.pos >= self.input.len() || !self.input[self.pos].is_ascii_digit() {
                return Err(self.err(
                    "Trailing decimal point is not allowed in JSON numbers",
                    dot_pos,
                ));
            }
            while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }

        if self.pos < self.input.len()
            && (self.input[self.pos] == b'e' || self.input[self.pos] == b'E')
        {
            let exp_pos = self.pos;
            self.pos += 1;
            if self.pos < self.input.len()
                && (self.input[self.pos] == b'+' || self.input[self.pos] == b'-')
            {
                self.pos += 1;
            }
            if self.pos >= self.input.len() || !self.input[self.pos].is_ascii_digit() {
                return Err(self.err(
                    "Exponent in JSON number must contain at least one digit",
                    exp_pos,
                ));
            }
            while self.pos < self.input.len() && self.input[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }

        if self.pos < self.input.len()
            && (self.input[self.pos] == b'.' || is_ident_continue(self.input[self.pos]))
        {
            return Err(self.err("Invalid character in JSON number", self.pos));
        }

        Ok(&self.input[start..self.pos])
    }

    /// Strict RFC 8259 string scanner with 8-byte SWAR fast-path (IMP-05 / PERF-04),
    /// escape validation, and UTF-16 surrogate pair verification.
    fn scan_string(&mut self) -> Result<&'a [u8], SyntaxError> {
        let start = self.pos;
        self.pos += 1; // Skip opening `"`
        let mut has_escapes = false;

        while self.pos < self.input.len() {
            // Hardware SIMD (AVX2 / NEON) + 8-byte SWAR fast-path: skip plain ASCII bytes in 0x20..=0x7F
            // that are neither `"` (0x22) nor `\` (0x5C) (IMP-05 / PERF-04 / PERF-09).
            self.pos += skip_plain_ascii_string_bytes(&self.input[self.pos..]);

            if self.pos >= self.input.len() {
                break;
            }

            let b = self.input[self.pos];
            if b == b'"' {
                self.pos += 1;
                self.last_string_has_escapes = has_escapes;
                return Ok(&self.input[start..self.pos]);
            } else if b < 0x20 {
                return Err(self.err(
                    "Unescaped control character is not allowed in JSON string",
                    self.pos,
                ));
            } else if b == b'\\' {
                has_escapes = true;
                let esc_pos = self.pos;
                self.pos += 1;
                if self.pos >= self.input.len() {
                    return Err(self.err("Unterminated escape sequence in string", esc_pos));
                }
                match self.input[self.pos] {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                        self.pos += 1;
                    }
                    b'u' => {
                        self.pos += 1;
                        let code = self.parse_hex4(esc_pos)?;
                        if (0xDC00..=0xDFFF).contains(&code) {
                            return Err(self.err(
                                "Lone UTF-16 low surrogate is not allowed in JSON string",
                                esc_pos,
                            ));
                        }
                        if (0xD800..=0xDBFF).contains(&code) {
                            if self.pos + 6 > self.input.len()
                                || self.input[self.pos] != b'\\'
                                || self.input[self.pos + 1] != b'u'
                            {
                                return Err(self.err(
                                    "Unpaired UTF-16 high surrogate is not allowed in JSON string",
                                    esc_pos,
                                ));
                            }
                            let low_esc_pos = self.pos;
                            self.pos += 2;
                            let low = self.parse_hex4(low_esc_pos)?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(self.err(
                                    "Invalid UTF-16 surrogate pair: expected low surrogate (0xDC00..=0xDFFF)",
                                    low_esc_pos,
                                ));
                            }
                        }
                    }
                    _ => {
                        return Err(self.err("Invalid escape sequence in JSON string", esc_pos));
                    }
                }
            } else if b < 0x80 {
                self.pos += 1;
            } else {
                let char_len = validate_utf8_char(&self.input[self.pos..])
                    .ok_or_else(|| self.err("Invalid UTF-8 byte sequence in string", self.pos))?;
                self.pos += char_len;
            }
        }

        Err(self.err("Unterminated string literal", start))
    }

    fn parse_hex4(&mut self, esc_pos: usize) -> Result<u16, SyntaxError> {
        if self.pos + 4 > self.input.len() {
            return Err(self.err(
                "Invalid \\uXXXX escape: expected 4 hexadecimal digits",
                esc_pos,
            ));
        }
        let mut val: u16 = 0;
        for i in 0..4 {
            let b = self.input[self.pos + i];
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u16,
                b'a'..=b'f' => (b - b'a' + 10) as u16,
                b'A'..=b'F' => (b - b'A' + 10) as u16,
                _ => {
                    return Err(self.err(
                        "Invalid \\uXXXX escape: expected 4 hexadecimal digits",
                        esc_pos,
                    ));
                }
            };
            val = (val << 4) | digit;
        }
        self.pos += 4;
        Ok(val)
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn has_avx2() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static AVX2_STATE: AtomicU8 = AtomicU8::new(0);
    match AVX2_STATE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let detected = std::is_x86_feature_detected!("avx2");
            AVX2_STATE.store(if detected { 1 } else { 2 }, Ordering::Relaxed);
            detected
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn skip_plain_ascii_string_bytes_avx2(bytes: &[u8]) -> usize {
    use std::arch::x86_64::*;
    let mut i = 0usize;
    let v_quote = _mm256_set1_epi8(b'"' as i8);
    let v_bslash = _mm256_set1_epi8(b'\\' as i8);
    let v_space = _mm256_set1_epi8(0x20);

    while i + 32 <= bytes.len() {
        // SAFETY: `i + 32 <= bytes.len()` is checked by the loop condition, and
        // `_mm256_loadu_si256` supports unaligned loads at any byte alignment.
        let chunk = unsafe { _mm256_loadu_si256(bytes.as_ptr().add(i) as *const __m256i) };
        let eq_quote = _mm256_cmpeq_epi8(chunk, v_quote);
        let eq_bslash = _mm256_cmpeq_epi8(chunk, v_bslash);
        // Signed comparison `0x20 > chunk_i8` is true iff byte is in `0x00..=0x1F` (0..=31)
        // or `0x80..=0xFF` (-128..=-1), simultaneously stopping on control chars and UTF-8 bytes!
        let bad_range = _mm256_cmpgt_epi8(v_space, chunk);
        let special = _mm256_or_si256(_mm256_or_si256(eq_quote, eq_bslash), bad_range);
        let mask = _mm256_movemask_epi8(special) as u32;
        if mask != 0 {
            return i + (mask.trailing_zeros() as usize);
        }
        i += 32;
    }

    while i + 8 <= bytes.len() {
        let chunk = u64::from_ne_bytes(bytes[i..i + 8].try_into().unwrap());
        if is_plain_ascii_string_chunk(chunk) {
            i += 8;
        } else {
            break;
        }
    }
    i
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn skip_plain_ascii_string_bytes_neon(bytes: &[u8]) -> usize {
    use std::arch::aarch64::*;
    let mut i = 0usize;
    let v_quote = vdupq_n_u8(b'"');
    let v_bslash = vdupq_n_u8(b'\\');
    let v_space = vdupq_n_s8(0x20);
    while i + 16 <= bytes.len() {
        // SAFETY: `i + 16 <= bytes.len()` is checked by the loop condition, and
        // `vld1q_u8` supports unaligned 16-byte loads on AArch64.
        let chunk = unsafe { vld1q_u8(bytes.as_ptr().add(i)) };
        let eq_quote = vceqq_u8(chunk, v_quote);
        let eq_bslash = vceqq_u8(chunk, v_bslash);
        let bad_range = vcltq_s8(vreinterpretq_s8_u8(chunk), v_space);
        let special = vorrq_u8(vorrq_u8(eq_quote, eq_bslash), bad_range);
        if vmaxvq_u8(special) != 0 {
            break;
        }
        i += 16;
    }

    while i + 8 <= bytes.len() {
        let chunk = u64::from_ne_bytes(bytes[i..i + 8].try_into().unwrap());
        if is_plain_ascii_string_chunk(chunk) {
            i += 8;
        } else {
            break;
        }
    }
    i
}

/// Skips contiguous plain ASCII string bytes (`0x20..=0x7F` excluding `"` and `\`) using
/// 32-byte AVX2 on `x86_64`, 16-byte NEON on `aarch64`, and an 8-byte SWAR tail (PERF-09).
#[inline(always)]
pub(crate) fn skip_plain_ascii_string_bytes(bytes: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if bytes.len() >= 32 && has_avx2() {
            // SAFETY: `has_avx2()` verified AVX2 support on the current CPU.
            return unsafe { skip_plain_ascii_string_bytes_avx2(bytes) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if bytes.len() >= 16 {
            // SAFETY: NEON is baseline mandatory on AArch64.
            return unsafe { skip_plain_ascii_string_bytes_neon(bytes) };
        }
    }
    let mut i = 0usize;
    while i + 8 <= bytes.len() {
        let chunk = u64::from_ne_bytes(bytes[i..i + 8].try_into().unwrap());
        if is_plain_ascii_string_chunk(chunk) {
            i += 8;
        } else {
            break;
        }
    }
    i
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn skip_ascii_spaces_avx2(bytes: &[u8]) -> usize {
    use std::arch::x86_64::*;
    let mut i = 0usize;
    let v_space = _mm256_set1_epi8(b' ' as i8);

    while i + 32 <= bytes.len() {
        // SAFETY: `i + 32 <= bytes.len()` is checked by the loop condition.
        let chunk = unsafe { _mm256_loadu_si256(bytes.as_ptr().add(i) as *const __m256i) };
        let eq_space = _mm256_cmpeq_epi8(chunk, v_space);
        let non_space_mask = (_mm256_movemask_epi8(eq_space) as u32) ^ 0xFFFF_FFFF;
        if non_space_mask != 0 {
            return i + (non_space_mask.trailing_zeros() as usize);
        }
        i += 32;
    }

    while i + 8 <= bytes.len() {
        let chunk = u64::from_ne_bytes(bytes[i..i + 8].try_into().unwrap());
        if chunk == 0x2020_2020_2020_2020 {
            i += 8;
        } else {
            break;
        }
    }
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    i
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn skip_ascii_spaces_neon(bytes: &[u8]) -> usize {
    use std::arch::aarch64::*;
    let mut i = 0usize;
    let v_space = vdupq_n_u8(b' ');
    while i + 16 <= bytes.len() {
        // SAFETY: `i + 16 <= bytes.len()` is checked by the loop condition.
        let chunk = unsafe { vld1q_u8(bytes.as_ptr().add(i)) };
        let eq_space = vceqq_u8(chunk, v_space);
        if vminvq_u8(eq_space) != 0xFF {
            break;
        }
        i += 16;
    }

    while i + 8 <= bytes.len() {
        let chunk = u64::from_ne_bytes(bytes[i..i + 8].try_into().unwrap());
        if chunk == 0x2020_2020_2020_2020 {
            i += 8;
        } else {
            break;
        }
    }
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    i
}

/// Skips contiguous ASCII space (`0x20`) runs using 32-byte AVX2 on `x86_64`,
/// 16-byte NEON on `aarch64`, and an 8-byte SWAR tail (PERF-09).
#[inline(always)]
pub(crate) fn skip_ascii_spaces(bytes: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if bytes.len() >= 32 && has_avx2() {
            // SAFETY: `has_avx2()` verified AVX2 support on the current CPU.
            return unsafe { skip_ascii_spaces_avx2(bytes) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if bytes.len() >= 16 {
            // SAFETY: NEON is baseline mandatory on AArch64.
            return unsafe { skip_ascii_spaces_neon(bytes) };
        }
    }
    let mut i = 0usize;
    while i + 8 <= bytes.len() {
        let chunk = u64::from_ne_bytes(bytes[i..i + 8].try_into().unwrap());
        if chunk == 0x2020_2020_2020_2020 {
            i += 8;
        } else {
            break;
        }
    }
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    i
}

/// Returns true if all 8 bytes in `chunk` are in `0x20..=0x7F` and none equal `"` (`0x22`) or `\` (`0x5C`).
#[inline(always)]
pub(crate) fn is_plain_ascii_string_chunk(chunk: u64) -> bool {
    const HIGH_BITS: u64 = 0x8080_8080_8080_8080;
    const LOW_ONES: u64 = 0x0101_0101_0101_0101;
    const SPACES: u64 = 0x2020_2020_2020_2020;
    const QUOTES: u64 = 0x2222_2222_2222_2222;
    const BACKSLASHES: u64 = 0x5C5C_5C5C_5C5C_5C5C;

    if (chunk & HIGH_BITS) != 0 {
        return false;
    }
    // Since all bytes have bit 7 == 0, subtracting 0x20 sets bit 7 iff byte < 0x20
    if (chunk.wrapping_sub(SPACES) & HIGH_BITS) != 0 {
        return false;
    }
    let xor_quote = chunk ^ QUOTES;
    if (xor_quote.wrapping_sub(LOW_ONES) & HIGH_BITS) != 0 {
        return false;
    }
    let xor_bs = chunk ^ BACKSLASHES;
    if (xor_bs.wrapping_sub(LOW_ONES) & HIGH_BITS) != 0 {
        return false;
    }
    true
}

/// Returns true if all 8 bytes in `chunk` are plain printable ASCII (`0x20..=0x7F`),
/// containing no `\n`, `\r`, control characters, or non-ASCII bytes.
#[inline(always)]
fn is_plain_ascii_line_comment_chunk(chunk: u64) -> bool {
    const HIGH_BITS: u64 = 0x8080_8080_8080_8080;
    const SPACES: u64 = 0x2020_2020_2020_2020;

    (chunk & HIGH_BITS) == 0 && (chunk.wrapping_sub(SPACES) & HIGH_BITS) == 0
}

/// Returns true if all 8 bytes in `chunk` are plain printable ASCII (`0x20..=0x7F`)
/// and none equal `*` (`0x2A`).
#[inline(always)]
fn is_plain_ascii_block_comment_chunk(chunk: u64) -> bool {
    const HIGH_BITS: u64 = 0x8080_8080_8080_8080;
    const LOW_ONES: u64 = 0x0101_0101_0101_0101;
    const SPACES: u64 = 0x2020_2020_2020_2020;
    const STARS: u64 = 0x2A2A_2A2A_2A2A_2A2A;

    if (chunk & HIGH_BITS) != 0 {
        return false;
    }
    if (chunk.wrapping_sub(SPACES) & HIGH_BITS) != 0 {
        return false;
    }
    let xor_star = chunk ^ STARS;
    (xor_star.wrapping_sub(LOW_ONES) & HIGH_BITS) == 0
}

enum EmitFrame<'b, 'a> {
    Array {
        items: &'b [SortedArrayItem<'a>],
        inner_trailing: &'b [CommentPiece<'a>],
        index: usize,
    },
    Object {
        entries: &'b [SortedEntry<'a>],
        inner_trailing: &'b [CommentPiece<'a>],
        index: usize,
    },
}

#[inline]
fn emit_sorted_inline_comments<S: OutputSink>(
    out: &mut S,
    comments: &[CommentPiece<'_>],
    minify: bool,
) -> Result<(), &'static str> {
    if !minify {
        for c in comments {
            out.push_byte(b' ')?;
            emit_comment_raw(out, c.raw)?;
        }
    }
    Ok(())
}

#[inline]
fn emit_sorted_standalone_comments<S: OutputSink>(
    out: &mut S,
    comments: &[CommentPiece<'_>],
    indent_table: &IndentTable,
    depth: usize,
    minify: bool,
) -> Result<(), &'static str> {
    if !minify {
        for c in comments {
            out.push_byte(b'\n')?;
            out.push_indent(indent_table, depth)?;
            emit_comment_raw(out, c.raw)?;
        }
    }
    Ok(())
}

/// Iterative emitter for `SortedValue` backed by a heap `Vec<EmitFrame>`
/// to avoid call-stack recursion up to depth 512 (TVEK-04 / CWE-674).
fn emit_sorted_value_iterative<'b, 'a, S: OutputSink>(
    root: &'b SortedValue<'a>,
    out: &mut S,
    options: &FormatOptions,
    indent_table: &IndentTable,
) -> Result<(), &'static str> {
    let minify = options.minify;
    let mut stack: Vec<EmitFrame<'b, 'a>> = Vec::with_capacity(32);
    let mut current: &'b SortedValue<'a> = root;

    'descend: loop {
        match current {
            SortedValue::Raw(slice) => {
                out.extend_slice(slice)?;
            }
            SortedValue::Array {
                open_comments,
                items,
                inner_trailing_comments,
            } => {
                if items.is_empty() {
                    out.push_byte(b'[')?;
                    if !minify && !inner_trailing_comments.is_empty() {
                        let parent_depth = stack.len();
                        emit_sorted_standalone_comments(
                            out,
                            inner_trailing_comments,
                            indent_table,
                            parent_depth + 1,
                            minify,
                        )?;
                        out.push_byte(b'\n')?;
                        out.push_indent(indent_table, parent_depth)?;
                    }
                    out.push_byte(b']')?;
                } else {
                    let line_width = options.line_width.min(MAX_LINE_WIDTH);
                    let can_inline = if !minify
                        && line_width > 0
                        && open_comments.is_empty()
                        && inner_trailing_comments.is_empty()
                    {
                        let key_cols = match stack.last() {
                            Some(EmitFrame::Object { entries, index, .. }) => {
                                entries[*index].raw_key.len().saturating_add(2)
                            }
                            _ => 0,
                        };
                        let prefix_cols = stack
                            .len()
                            .saturating_mul(indent_table.unit_len)
                            .saturating_add(key_cols);
                        let budget = line_width.saturating_sub(prefix_cols.saturating_add(1));
                        if budget >= 3 {
                            let mut inline_len = 2usize; // '[' and ']'
                            let mut ok = true;
                            for (idx, item) in items.iter().enumerate() {
                                if !item.leading_comments.is_empty()
                                    || !item.trailing_comments.is_empty()
                                {
                                    ok = false;
                                    break;
                                }
                                match item.value {
                                    SortedValue::Raw(slice) => {
                                        let sep = if idx == 0 { 0 } else { 2 };
                                        inline_len = inline_len
                                            .saturating_add(sep)
                                            .saturating_add(slice.len());
                                        if inline_len > budget {
                                            ok = false;
                                            break;
                                        }
                                    }
                                    _ => {
                                        ok = false;
                                        break;
                                    }
                                }
                            }
                            ok
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if can_inline {
                        out.push_byte(b'[')?;
                        for (idx, item) in items.iter().enumerate() {
                            if idx > 0 {
                                out.extend_slice(b", ")?;
                            }
                            if let SortedValue::Raw(slice) = item.value {
                                out.extend_slice(slice)?;
                            }
                        }
                        out.push_byte(b']')?;
                    } else {
                        out.push_byte(b'[')?;
                        let child_depth = stack.len() + 1;
                        emit_sorted_inline_comments(out, open_comments, minify)?;
                        let first = &items[0];
                        emit_sorted_standalone_comments(
                            out,
                            &first.leading_comments,
                            indent_table,
                            child_depth,
                            minify,
                        )?;
                        if !minify {
                            out.push_byte(b'\n')?;
                            out.push_indent(indent_table, child_depth)?;
                        }
                        stack.push(EmitFrame::Array {
                            items,
                            inner_trailing: inner_trailing_comments,
                            index: 0,
                        });
                        current = &first.value;
                        continue 'descend;
                    }
                }
            }
            SortedValue::Object {
                open_comments,
                entries,
                inner_trailing_comments,
            } => {
                if entries.is_empty() {
                    out.push_byte(b'{')?;
                    if !minify && !inner_trailing_comments.is_empty() {
                        let parent_depth = stack.len();
                        emit_sorted_standalone_comments(
                            out,
                            inner_trailing_comments,
                            indent_table,
                            parent_depth + 1,
                            minify,
                        )?;
                        out.push_byte(b'\n')?;
                        out.push_indent(indent_table, parent_depth)?;
                    }
                    out.push_byte(b'}')?;
                } else {
                    out.push_byte(b'{')?;
                    let child_depth = stack.len() + 1;
                    emit_sorted_inline_comments(out, open_comments, minify)?;
                    let first = &entries[0];
                    emit_sorted_standalone_comments(
                        out,
                        &first.leading_comments,
                        indent_table,
                        child_depth,
                        minify,
                    )?;
                    if !minify {
                        out.push_byte(b'\n')?;
                        out.push_indent(indent_table, child_depth)?;
                    }
                    out.extend_slice(first.raw_key)?;
                    out.push_byte(b':')?;
                    if !minify {
                        out.push_byte(b' ')?;
                    }
                    stack.push(EmitFrame::Object {
                        entries,
                        inner_trailing: inner_trailing_comments,
                        index: 0,
                    });
                    current = &first.value;
                    continue 'descend;
                }
            }
        }

        loop {
            let depth = stack.len();
            let Some(frame) = stack.last_mut() else {
                break;
            };
            match frame {
                EmitFrame::Array {
                    items,
                    inner_trailing,
                    index,
                } => {
                    let prev_item = &items[*index];
                    *index += 1;
                    if *index < items.len() {
                        let next_item = &items[*index];
                        out.push_byte(b',')?;
                        emit_sorted_inline_comments(out, &prev_item.trailing_comments, minify)?;
                        emit_sorted_standalone_comments(
                            out,
                            &next_item.leading_comments,
                            indent_table,
                            depth,
                            minify,
                        )?;
                        if !minify {
                            out.push_byte(b'\n')?;
                            out.push_indent(indent_table, depth)?;
                        }
                        current = &next_item.value;
                        continue 'descend;
                    } else {
                        let trailing_in_arr = *inner_trailing;
                        emit_sorted_inline_comments(out, &prev_item.trailing_comments, minify)?;
                        emit_sorted_standalone_comments(
                            out,
                            trailing_in_arr,
                            indent_table,
                            depth,
                            minify,
                        )?;
                        stack.pop();
                        if !minify {
                            out.push_byte(b'\n')?;
                            out.push_indent(indent_table, stack.len())?;
                        }
                        out.push_byte(b']')?;
                    }
                }
                EmitFrame::Object {
                    entries,
                    inner_trailing,
                    index,
                } => {
                    let prev_entry = &entries[*index];
                    *index += 1;
                    if *index < entries.len() {
                        let next_entry = &entries[*index];
                        out.push_byte(b',')?;
                        emit_sorted_inline_comments(out, &prev_entry.trailing_comments, minify)?;
                        emit_sorted_standalone_comments(
                            out,
                            &next_entry.leading_comments,
                            indent_table,
                            depth,
                            minify,
                        )?;
                        if !minify {
                            out.push_byte(b'\n')?;
                            out.push_indent(indent_table, depth)?;
                        }
                        out.extend_slice(next_entry.raw_key)?;
                        out.push_byte(b':')?;
                        if !minify {
                            out.push_byte(b' ')?;
                        }
                        current = &next_entry.value;
                        continue 'descend;
                    } else {
                        let trailing_in_obj = *inner_trailing;
                        emit_sorted_inline_comments(out, &prev_entry.trailing_comments, minify)?;
                        emit_sorted_standalone_comments(
                            out,
                            trailing_in_obj,
                            indent_table,
                            depth,
                            minify,
                        )?;
                        stack.pop();
                        if !minify {
                            out.push_byte(b'\n')?;
                            out.push_indent(indent_table, stack.len())?;
                        }
                        out.push_byte(b'}')?;
                    }
                }
            }
        }

        break 'descend;
    }

    Ok(())
}

/// Decodes a validated `KeyToken` into a `Cow<str>` for lexicographical sorting and duplicate key
/// detection without rescanning for backslashes when `!key.has_escapes` (PERF-04).
#[inline(always)]
fn decode_json_key_token(key: KeyToken<'_>) -> Cow<'_, str> {
    let inner = &key.slice[1..key.slice.len() - 1];
    if !key.has_escapes {
        if let Ok(s) = std::str::from_utf8(inner) {
            return Cow::Borrowed(s);
        }
    }
    decode_escaped_json_key(inner)
}

#[cold]
fn decode_escaped_json_key(inner: &[u8]) -> Cow<'_, str> {
    let mut out = String::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        let run_start = i;
        while i < inner.len() && inner[i] != b'\\' {
            i += 1;
        }
        if i > run_start {
            if let Ok(s) = std::str::from_utf8(&inner[run_start..i]) {
                out.push_str(s);
            }
        }
        if i >= inner.len() {
            break;
        }
        // inner[i] == b'\\'
        i += 1;
        match inner[i] {
            b'"' => {
                out.push('"');
                i += 1;
            }
            b'\\' => {
                out.push('\\');
                i += 1;
            }
            b'/' => {
                out.push('/');
                i += 1;
            }
            b'b' => {
                out.push('\u{0008}');
                i += 1;
            }
            b'f' => {
                out.push('\u{000C}');
                i += 1;
            }
            b'n' => {
                out.push('\n');
                i += 1;
            }
            b'r' => {
                out.push('\r');
                i += 1;
            }
            b't' => {
                out.push('\t');
                i += 1;
            }
            b'u' => {
                i += 1;
                let code = parse_hex4_unchecked(&inner[i..i + 4]);
                i += 4;
                if (0xD800..=0xDBFF).contains(&code) {
                    i += 2; // skip `\u`
                    let low = parse_hex4_unchecked(&inner[i..i + 4]);
                    i += 4;
                    let combined =
                        0x10000 + (((code as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                    if let Some(ch) = char::from_u32(combined) {
                        out.push(ch);
                    }
                } else if let Some(ch) = char::from_u32(code as u32) {
                    out.push(ch);
                }
            }
            _ => i += 1,
        }
    }
    Cow::Owned(out)
}

#[inline]
fn parse_hex4_unchecked(bytes: &[u8]) -> u16 {
    let mut val = 0u16;
    for &b in &bytes[..4] {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0,
        };
        val = (val << 4) | (d as u16);
    }
    val
}

#[inline]
pub(crate) fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'+' || b == b'-'
}

/// Validates the next UTF-8 character at the start of `bytes` per RFC 3629.
/// Returns the byte length (1..=4) if valid, or `None` if invalid.
#[inline]
fn validate_utf8_char(bytes: &[u8]) -> Option<usize> {
    let b0 = *bytes.first()?;
    if b0 < 0x80 {
        return Some(1);
    }
    if (0xC2..=0xDF).contains(&b0) {
        let b1 = *bytes.get(1)?;
        if (0x80..=0xBF).contains(&b1) {
            return Some(2);
        }
        return None;
    }
    if (0xE0..=0xEF).contains(&b0) {
        let b1 = *bytes.get(1)?;
        let b2 = *bytes.get(2)?;
        if !(0x80..=0xBF).contains(&b2) {
            return None;
        }
        let valid_b1 = match b0 {
            0xE0 => (0xA0..=0xBF).contains(&b1),
            0xED => (0x80..=0x9F).contains(&b1),
            _ => (0x80..=0xBF).contains(&b1),
        };
        if valid_b1 {
            return Some(3);
        }
        return None;
    }
    if (0xF0..=0xF4).contains(&b0) {
        let b1 = *bytes.get(1)?;
        let b2 = *bytes.get(2)?;
        let b3 = *bytes.get(3)?;
        if !(0x80..=0xBF).contains(&b2) || !(0x80..=0xBF).contains(&b3) {
            return None;
        }
        let valid_b1 = match b0 {
            0xF0 => (0x90..=0xBF).contains(&b1),
            0xF4 => (0x80..=0x8F).contains(&b1),
            _ => (0x80..=0xBF).contains(&b1),
        };
        if valid_b1 {
            return Some(4);
        }
        return None;
    }
    None
}

/// Cold-path scoped multi-diagnostic collector (PERF-10 / TVEK-21).
/// Recovers on local, structure-preserving errors (comments in `--strict` mode, duplicate object keys,
/// trailing commas in objects/arrays, recoverable string interior errors, and invalid scalar literals)
/// while deferring `(line, col)` resolution to a single $O(N)$ pass via `SyntaxError::resolve_in_place`.
#[cold]
fn collect_multi_diagnostics(
    input: &[u8],
    allow_comments: bool,
    max_key_bytes: usize,
    max_errors: usize,
) -> Vec<SyntaxError> {
    let mut diags: Vec<SyntaxError> = Vec::new();
    let mut scanner = Scanner::new(input, allow_comments, max_key_bytes);
    scanner.defer_line_col = true;
    collect_multi_diagnostics_inner(&mut scanner, &mut diags, max_key_bytes, max_errors);
    SyntaxError::resolve_in_place(&mut diags, input);
    diags
}

#[cold]
fn collect_multi_diagnostics_inner(
    scanner: &mut Scanner<'_>,
    diags: &mut Vec<SyntaxError>,
    max_key_bytes: usize,
    max_errors: usize,
) {
    let input = scanner.input;
    if input.starts_with(b"\xEF\xBB\xBF") {
        diags.push(scanner.err(
            "UTF-8 BOM (byte order mark) is not allowed in RFC 8259 JSON",
            0,
        ));
        return;
    }

    let mut stack: Vec<StreamFrame<'_>> = Vec::with_capacity(32);
    let mut free_sets: Vec<KeySet<'_>> = Vec::with_capacity(MAX_FREE_KEY_SETS);
    let mut allocated_key_bytes = 0usize;

    if scanner.scan_trivia_recovering(diags, max_errors).is_err() {
        return;
    }
    if scanner.pos >= input.len() {
        if diags.len() < max_errors {
            diags.push(scanner.err("Unexpected end of JSON input", scanner.pos));
        }
        return;
    }

    'expect_value: loop {
        if scanner.pos >= input.len() {
            if diags.len() < max_errors {
                diags.push(scanner.err("Expected JSON value, found end of input", scanner.pos));
            }
            return;
        }

        loop {
            let b = input[scanner.pos];
            if b == b'{' {
                let open_pos = scanner.pos;
                if stack.len() + 1 > MAX_DEPTH {
                    if diags.len() < max_errors {
                        diags.push(scanner.err("Maximum nesting depth of 512 exceeded", open_pos));
                    }
                    return;
                }
                scanner.pos += 1;
                if scanner.scan_trivia_recovering(diags, max_errors).is_err() {
                    return;
                }
                if scanner.pos >= input.len() {
                    if diags.len() < max_errors {
                        diags.push(scanner.err("Unterminated JSON object", open_pos));
                    }
                    return;
                }
                if input[scanner.pos] == b'}' {
                    scanner.pos += 1;
                    break;
                }

                let Ok(first_key) = scanner.scan_key_and_colon_recovering(diags, max_errors) else {
                    return;
                };
                let mut key_set = free_sets.pop().unwrap_or_else(KeySet::new);
                let (_, added) = key_set.insert(decode_key_token_safe(first_key));
                allocated_key_bytes = allocated_key_bytes.saturating_add(added);
                if allocated_key_bytes > max_key_bytes {
                    if diags.len() < max_errors {
                        diags.push(scanner.err(
                            "Formatted output exceeds maximum allowed buffer size",
                            first_key.key_pos,
                        ));
                    }
                    return;
                }
                stack.push(StreamFrame::Object(key_set));
                if scanner.pos >= input.len() {
                    if diags.len() < max_errors {
                        diags.push(scanner.err("Expected JSON value after ':'", scanner.pos));
                    }
                    return;
                }
            } else if b == b'[' {
                let open_pos = scanner.pos;
                if stack.len() + 1 > MAX_DEPTH {
                    if diags.len() < max_errors {
                        diags.push(scanner.err("Maximum nesting depth of 512 exceeded", open_pos));
                    }
                    return;
                }
                scanner.pos += 1;
                if scanner.scan_trivia_recovering(diags, max_errors).is_err() {
                    return;
                }
                if scanner.pos >= input.len() {
                    if diags.len() < max_errors {
                        diags.push(scanner.err("Unterminated JSON array", open_pos));
                    }
                    return;
                }
                if input[scanner.pos] == b']' {
                    scanner.pos += 1;
                    break;
                }
                stack.push(StreamFrame::Array);
            } else {
                if scanner
                    .scan_primitive_recovering(diags, max_errors)
                    .is_err()
                {
                    return;
                }
                break;
            }
        }

        while let Some(top) = stack.last() {
            let is_object = matches!(top, StreamFrame::Object(_));
            if scanner.scan_trivia_recovering(diags, max_errors).is_err() {
                return;
            }
            if is_object {
                if scanner.pos >= input.len() {
                    if diags.len() < max_errors {
                        diags.push(scanner.err("Unterminated JSON object", scanner.pos));
                    }
                    return;
                }
                match input[scanner.pos] {
                    b',' => {
                        let comma_pos = scanner.pos;
                        scanner.pos += 1;
                        if scanner.scan_trivia_recovering(diags, max_errors).is_err() {
                            return;
                        }
                        if scanner.pos >= input.len() {
                            if diags.len() < max_errors {
                                diags.push(scanner.err("Unterminated JSON object", scanner.pos));
                            }
                            return;
                        }
                        if input[scanner.pos] == b'}' {
                            diags.push(
                                scanner
                                    .err("Trailing comma is not allowed in JSON object", comma_pos),
                            );
                            if diags.len() >= max_errors {
                                return;
                            }
                            scanner.pos += 1;
                            if let Some(StreamFrame::Object(mut key_set)) = stack.pop() {
                                let freed = key_set.clear();
                                allocated_key_bytes = allocated_key_bytes.saturating_sub(freed);
                                if free_sets.len() < MAX_FREE_KEY_SETS {
                                    free_sets.push(key_set);
                                }
                            }
                            continue;
                        }

                        let Ok(next_key) = scanner.scan_key_and_colon_recovering(diags, max_errors)
                        else {
                            return;
                        };
                        if let Some(StreamFrame::Object(key_set)) = stack.last_mut() {
                            let (inserted, added) = key_set.insert(decode_key_token_safe(next_key));
                            if !inserted {
                                diags.push(scanner.err(
                                    "Duplicate object key is not allowed in JSON object",
                                    next_key.key_pos,
                                ));
                                if diags.len() >= max_errors {
                                    return;
                                }
                            }
                            allocated_key_bytes = allocated_key_bytes.saturating_add(added);
                            if allocated_key_bytes > max_key_bytes {
                                if diags.len() < max_errors {
                                    diags.push(scanner.err(
                                        "Formatted output exceeds maximum allowed buffer size",
                                        next_key.key_pos,
                                    ));
                                }
                                return;
                            }
                        }
                        if scanner.pos >= input.len() {
                            if diags.len() < max_errors {
                                diags.push(
                                    scanner.err("Expected JSON value after ':'", scanner.pos),
                                );
                            }
                            return;
                        }
                        continue 'expect_value;
                    }
                    b'}' => {
                        scanner.pos += 1;
                        if let Some(StreamFrame::Object(mut key_set)) = stack.pop() {
                            let freed = key_set.clear();
                            allocated_key_bytes = allocated_key_bytes.saturating_sub(freed);
                            if free_sets.len() < MAX_FREE_KEY_SETS {
                                free_sets.push(key_set);
                            }
                        }
                    }
                    _ => {
                        if diags.len() < max_errors {
                            diags.push(
                                scanner.err("Expected ',' or '}' in JSON object", scanner.pos),
                            );
                        }
                        return;
                    }
                }
            } else {
                if scanner.pos >= input.len() {
                    if diags.len() < max_errors {
                        diags.push(scanner.err("Unterminated JSON array", scanner.pos));
                    }
                    return;
                }
                match input[scanner.pos] {
                    b',' => {
                        let comma_pos = scanner.pos;
                        scanner.pos += 1;
                        if scanner.scan_trivia_recovering(diags, max_errors).is_err() {
                            return;
                        }
                        if scanner.pos >= input.len() {
                            if diags.len() < max_errors {
                                diags.push(scanner.err("Unterminated JSON array", scanner.pos));
                            }
                            return;
                        }
                        if input[scanner.pos] == b']' {
                            diags.push(
                                scanner
                                    .err("Trailing comma is not allowed in JSON array", comma_pos),
                            );
                            if diags.len() >= max_errors {
                                return;
                            }
                            scanner.pos += 1;
                            stack.pop();
                            continue;
                        }
                        continue 'expect_value;
                    }
                    b']' => {
                        scanner.pos += 1;
                        stack.pop();
                    }
                    _ => {
                        if diags.len() < max_errors {
                            diags.push(
                                scanner.err("Expected ',' or ']' in JSON array", scanner.pos),
                            );
                        }
                        return;
                    }
                }
            }
        }

        break 'expect_value;
    }

    if scanner.scan_trivia_recovering(diags, max_errors).is_err() {
        return;
    }
    if scanner.pos < input.len() && diags.len() < max_errors {
        diags.push(scanner.err("Trailing data after root JSON value", scanner.pos));
    }
}

#[inline]
fn decode_key_token_safe(key: KeyToken<'_>) -> Cow<'_, str> {
    if !key.has_escapes {
        let inner = &key.slice[1..key.slice.len() - 1];
        if let Ok(s) = std::str::from_utf8(inner) {
            return Cow::Borrowed(s);
        }
        return Cow::Owned(String::from_utf8_lossy(inner).into_owned());
    }
    decode_json_key_token(key)
}

impl<'a> Scanner<'a> {
    fn scan_trivia_recovering(
        &mut self,
        diags: &mut Vec<SyntaxError>,
        max_errors: usize,
    ) -> Result<(), ()> {
        while self.pos < self.input.len() {
            self.pos += skip_ascii_spaces(&self.input[self.pos..]);
            if self.pos >= self.input.len() {
                break;
            }
            match self.input[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => {
                    self.pos += 1;
                }
                b'/' => {
                    let comment_pos = self.pos;
                    let next = self.input.get(self.pos + 1).copied();
                    match next {
                        Some(b'/') => {
                            if !self.allow_comments {
                                diags.push(self.err(
                                    "Comments are not allowed in strict RFC 8259 mode",
                                    comment_pos,
                                ));
                                if diags.len() >= max_errors {
                                    return Err(());
                                }
                            }
                            if let Err(e) = self.scan_line_comment() {
                                diags.push(e);
                                if diags.len() >= max_errors {
                                    return Err(());
                                }
                                while self.pos < self.input.len() && self.input[self.pos] != b'\n' {
                                    self.pos += 1;
                                }
                            }
                        }
                        Some(b'*') => {
                            if !self.allow_comments {
                                diags.push(self.err(
                                    "Comments are not allowed in strict RFC 8259 mode",
                                    comment_pos,
                                ));
                                if diags.len() >= max_errors {
                                    return Err(());
                                }
                            }
                            if let Err(e) = self.scan_block_comment() {
                                diags.push(e);
                                return Err(());
                            }
                        }
                        _ => {
                            if diags.len() < max_errors {
                                diags.push(self.err(
                                    "Unexpected '/' in JSON input, expected '//' or '/*'",
                                    comment_pos,
                                ));
                            }
                            return Err(());
                        }
                    }
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn scan_key_and_colon_recovering(
        &mut self,
        diags: &mut Vec<SyntaxError>,
        max_errors: usize,
    ) -> Result<KeyToken<'a>, ()> {
        let key_pos = self.pos;
        if self.pos >= self.input.len() {
            if diags.len() < max_errors {
                diags.push(self.err("Expected object key, found end of input", self.pos));
            }
            return Err(());
        }
        let slice = match self.input[self.pos] {
            b'"' => self.scan_string_recovering(diags, max_errors)?,
            b'\'' => {
                if diags.len() < max_errors {
                    diags.push(self.err("Single-quoted strings are not allowed in JSON", self.pos));
                }
                return Err(());
            }
            b',' => {
                if diags.len() < max_errors {
                    diags.push(self.err("Unexpected comma in JSON object", self.pos));
                }
                return Err(());
            }
            _ => {
                if diags.len() < max_errors {
                    diags.push(self.err("Object keys must be double-quoted strings", self.pos));
                }
                return Err(());
            }
        };
        let has_escapes = self.last_string_has_escapes;
        self.scan_trivia_recovering(diags, max_errors)?;
        if self.pos >= self.input.len() || self.input[self.pos] != b':' {
            if diags.len() < max_errors {
                diags.push(self.err("Expected ':' after object key", self.pos));
            }
            return Err(());
        }
        let colon_pos = self.pos;
        self.pos += 1;
        self.scan_trivia_recovering(diags, max_errors)?;
        Ok(KeyToken {
            slice,
            key_pos,
            colon_pos,
            has_escapes,
        })
    }

    fn scan_string_recovering(
        &mut self,
        diags: &mut Vec<SyntaxError>,
        max_errors: usize,
    ) -> Result<&'a [u8], ()> {
        let start = self.pos;
        self.pos += 1; // Skip opening `"`
        let mut has_escapes = false;
        let mut had_interior_error = false;

        while self.pos < self.input.len() {
            self.pos += skip_plain_ascii_string_bytes(&self.input[self.pos..]);
            if self.pos >= self.input.len() {
                break;
            }
            let b = self.input[self.pos];
            if b == b'"' {
                self.pos += 1;
                self.last_string_has_escapes = has_escapes && !had_interior_error;
                return Ok(&self.input[start..self.pos]);
            } else if b == b'\n' || b == b'\r' {
                if diags.len() < max_errors {
                    diags.push(self.err(
                        "Unescaped control character is not allowed in JSON string",
                        self.pos,
                    ));
                }
                return Err(());
            } else if b < 0x20 {
                had_interior_error = true;
                diags.push(self.err(
                    "Unescaped control character is not allowed in JSON string",
                    self.pos,
                ));
                if diags.len() >= max_errors {
                    return Err(());
                }
                self.pos += 1;
            } else if b == b'\\' {
                has_escapes = true;
                let esc_pos = self.pos;
                self.pos += 1;
                if self.pos >= self.input.len() {
                    if diags.len() < max_errors {
                        diags.push(self.err("Unterminated escape sequence in string", esc_pos));
                    }
                    return Err(());
                }
                match self.input[self.pos] {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                        self.pos += 1;
                    }
                    b'u' => {
                        self.pos += 1;
                        match self.parse_hex4(esc_pos) {
                            Ok(code) => {
                                if (0xDC00..=0xDFFF).contains(&code) {
                                    had_interior_error = true;
                                    diags.push(self.err(
                                        "Lone UTF-16 low surrogate is not allowed in JSON string",
                                        esc_pos,
                                    ));
                                    if diags.len() >= max_errors {
                                        return Err(());
                                    }
                                } else if (0xD800..=0xDBFF).contains(&code) {
                                    if self.pos + 6 > self.input.len()
                                        || self.input[self.pos] != b'\\'
                                        || self.input[self.pos + 1] != b'u'
                                    {
                                        had_interior_error = true;
                                        diags.push(self.err(
                                            "Unpaired UTF-16 high surrogate is not allowed in JSON string",
                                            esc_pos,
                                        ));
                                        if diags.len() >= max_errors {
                                            return Err(());
                                        }
                                    } else {
                                        let low_esc_pos = self.pos;
                                        self.pos += 2;
                                        match self.parse_hex4(low_esc_pos) {
                                            Ok(low) => {
                                                if !(0xDC00..=0xDFFF).contains(&low) {
                                                    had_interior_error = true;
                                                    diags.push(self.err(
                                                        "Invalid UTF-16 surrogate pair: expected low surrogate (0xDC00..=0xDFFF)",
                                                        low_esc_pos,
                                                    ));
                                                    if diags.len() >= max_errors {
                                                        return Err(());
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                had_interior_error = true;
                                                diags.push(e);
                                                if diags.len() >= max_errors {
                                                    return Err(());
                                                }
                                                self.skip_bad_hex4();
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                had_interior_error = true;
                                diags.push(e);
                                if diags.len() >= max_errors {
                                    return Err(());
                                }
                                self.skip_bad_hex4();
                            }
                        }
                    }
                    _ => {
                        had_interior_error = true;
                        diags.push(self.err("Invalid escape sequence in JSON string", esc_pos));
                        if diags.len() >= max_errors {
                            return Err(());
                        }
                        self.pos += 1;
                    }
                }
            } else if b < 0x80 {
                self.pos += 1;
            } else if let Some(char_len) = validate_utf8_char(&self.input[self.pos..]) {
                self.pos += char_len;
            } else {
                had_interior_error = true;
                diags.push(self.err("Invalid UTF-8 byte sequence in string", self.pos));
                if diags.len() >= max_errors {
                    return Err(());
                }
                self.pos += 1;
                while self.pos < self.input.len() && (self.input[self.pos] & 0xC0) == 0x80 {
                    self.pos += 1;
                }
            }
        }

        if diags.len() < max_errors {
            diags.push(self.err("Unterminated string literal", start));
        }
        Err(())
    }

    fn skip_bad_hex4(&mut self) {
        let mut skipped = 0usize;
        while skipped < 4 && self.pos < self.input.len() {
            let b = self.input[self.pos];
            if b == b'"' || b == b'\\' || b == b'\n' || b == b'\r' {
                break;
            }
            self.pos += 1;
            skipped += 1;
        }
    }

    fn scan_primitive_recovering(
        &mut self,
        diags: &mut Vec<SyntaxError>,
        max_errors: usize,
    ) -> Result<(), ()> {
        let prim_pos = self.pos;
        let b = self.input[prim_pos];
        if b == b'"' {
            self.scan_string_recovering(diags, max_errors)?;
            return Ok(());
        }
        match self.scan_primitive() {
            Ok(_) => Ok(()),
            Err(err) => {
                diags.push(err);
                if diags.len() >= max_errors {
                    return Err(());
                }
                // Recover on scalar/literal/number errors by advancing to the next delimiter
                if b == b'-' || b == b'+' || b == b'.' || b.is_ascii_alphanumeric() {
                    while self.pos < self.input.len()
                        && !matches!(
                            self.input[self.pos],
                            b' ' | b'\t'
                                | b'\n'
                                | b'\r'
                                | b','
                                | b'}'
                                | b']'
                                | b':'
                                | b'{'
                                | b'['
                                | b'"'
                                | b'/'
                        )
                    {
                        self.pos += 1;
                    }
                    if self.pos > prim_pos {
                        return Ok(());
                    }
                }
                Err(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt_default(input: &str) -> Result<String, SyntaxError> {
        let bytes = format_json(input.as_bytes(), &FormatOptions::default())?;
        Ok(String::from_utf8(bytes).unwrap())
    }

    #[test]
    fn test_valid_complex_json_formatting() {
        let input = r#"{"name":"tvek","version":1,"active":true,"nothing":null,"items":[1,-2.5,3e10,4.5e-2],"nested":{"empty_obj":{},"empty_arr":[]}}"#;
        let expected_default = "\
{
  \"name\": \"tvek\",
  \"version\": 1,
  \"active\": true,
  \"nothing\": null,
  \"items\": [1, -2.5, 3e10, 4.5e-2],
  \"nested\": {
    \"empty_obj\": {},
    \"empty_arr\": []
  }
}
";
        assert_eq!(fmt_default(input).unwrap(), expected_default);

        let structural_opts = FormatOptions {
            line_width: 0,
            ..FormatOptions::default()
        };
        let expected_structural = "\
{
  \"name\": \"tvek\",
  \"version\": 1,
  \"active\": true,
  \"nothing\": null,
  \"items\": [
    1,
    -2.5,
    3e10,
    4.5e-2
  ],
  \"nested\": {
    \"empty_obj\": {},
    \"empty_arr\": []
  }
}
";
        let out_structural =
            String::from_utf8(format_json(input.as_bytes(), &structural_opts).unwrap()).unwrap();
        assert_eq!(out_structural, expected_structural);
    }

    #[test]
    fn test_empty_containers_collapse() {
        assert_eq!(fmt_default("{}").unwrap(), "{}\n");
        assert_eq!(fmt_default("  {  \n\t  }  ").unwrap(), "{}\n");
        assert_eq!(fmt_default("[]").unwrap(), "[]\n");
        assert_eq!(fmt_default("  [  \n\t  ]  ").unwrap(), "[]\n");
        assert_eq!(
            fmt_default(r#"{"a": {   }, "b": [   ]}"#).unwrap(),
            "{\n  \"a\": {},\n  \"b\": []\n}\n"
        );
    }

    #[test]
    fn test_minify_option() {
        let input = "{\n  \"a\": 1,\n  \"b\": [ true, false, null, { }, [ ] ],\n  \"c\": \"hello world\"\n}\n";
        let opts = FormatOptions {
            minify: true,
            ..FormatOptions::default()
        };
        let out = String::from_utf8(format_json(input.as_bytes(), &opts).unwrap()).unwrap();
        assert_eq!(
            out,
            "{\"a\":1,\"b\":[true,false,null,{},[]],\"c\":\"hello world\"}\n"
        );
    }

    #[test]
    fn test_indent_4_and_tab() {
        let input = r#"{"a":{"b":[1,2]}}"#;
        let opts_4 = FormatOptions {
            indent: 4,
            ..FormatOptions::default()
        };
        let out_4 = String::from_utf8(format_json(input.as_bytes(), &opts_4).unwrap()).unwrap();
        let expected_4 = "{\n    \"a\": {\n        \"b\": [1, 2]\n    }\n}\n";
        assert_eq!(out_4, expected_4);

        let opts_4_structural = FormatOptions {
            indent: 4,
            line_width: 0,
            ..FormatOptions::default()
        };
        let out_4_structural =
            String::from_utf8(format_json(input.as_bytes(), &opts_4_structural).unwrap()).unwrap();
        assert_eq!(
            out_4_structural,
            "{\n    \"a\": {\n        \"b\": [\n            1,\n            2\n        ]\n    }\n}\n"
        );

        let opts_tab = FormatOptions {
            indent: 0,
            ..FormatOptions::default()
        };
        let out_tab = String::from_utf8(format_json(input.as_bytes(), &opts_tab).unwrap()).unwrap();
        let expected_tab = "{\n\t\"a\": {\n\t\t\"b\": [1, 2]\n\t}\n}\n";
        assert_eq!(out_tab, expected_tab);

        let opts_tab_structural = FormatOptions {
            indent: 0,
            line_width: 0,
            ..FormatOptions::default()
        };
        let out_tab_structural =
            String::from_utf8(format_json(input.as_bytes(), &opts_tab_structural).unwrap())
                .unwrap();
        assert_eq!(
            out_tab_structural,
            "{\n\t\"a\": {\n\t\t\"b\": [\n\t\t\t1,\n\t\t\t2\n\t\t]\n\t}\n}\n"
        );
    }

    #[test]
    fn test_sort_keys_recursive() {
        let input = r#"{"z": 1, "a": {"d": 4, "c": 3}, "m": [{"y": 2, "x": 1}]}"#;
        let opts = FormatOptions {
            sort_keys: true,
            ..FormatOptions::default()
        };
        let out = String::from_utf8(format_json(input.as_bytes(), &opts).unwrap()).unwrap();
        let expected = "\
{
  \"a\": {
    \"c\": 3,
    \"d\": 4
  },
  \"m\": [
    {
      \"x\": 1,
      \"y\": 2
    }
  ],
  \"z\": 1
}
";
        assert_eq!(out, expected);
    }

    #[test]
    fn test_reject_trailing_commas() {
        let err_obj = fmt_default("{\n  \"port\": 8080,\n}").unwrap_err();
        assert!(err_obj.message.contains("Trailing comma"));
        assert_eq!(err_obj.line, 2);
        assert_eq!(err_obj.col, 15);

        let err_arr = fmt_default("[1, 2, ]").unwrap_err();
        assert!(err_arr.message.contains("Trailing comma"));
    }

    #[test]
    fn test_reject_invalid_numbers() {
        assert!(fmt_default("01").is_err());
        assert!(fmt_default("-01").is_err());
        assert!(fmt_default("[00]").is_err());

        assert!(fmt_default("1.").is_err());
        assert!(fmt_default(".5").is_err());
        assert!(fmt_default("-.5").is_err());

        assert!(fmt_default("+1").is_err());
        assert!(fmt_default("NaN").is_err());
        assert!(fmt_default("Infinity").is_err());
        assert!(fmt_default("-Infinity").is_err());

        assert!(fmt_default("1e").is_err());
        assert!(fmt_default("1e+").is_err());
        assert!(fmt_default("1e-").is_err());
    }

    #[test]
    fn test_reject_invalid_strings_and_escapes() {
        assert!(fmt_default(r#"{"a": "\x41"}"#).is_err());
        assert!(fmt_default("{\"a\": \"hello\nworld\"}").is_err());
        assert!(fmt_default("{\"a\": \"hello\tworld\"}").is_err());
        assert!(fmt_default("{\"a\": \"\x00\"}").is_err());
        assert!(fmt_default("{'a': 1}").is_err());
        assert!(fmt_default("{\"a\": 'b'}").is_err());
        assert!(fmt_default("{a: 1}").is_err());
    }

    #[test]
    fn test_utf16_surrogate_validation() {
        assert!(fmt_default(r#"{"emoji": "\uD83D\uDE00"}"#).is_ok());
        assert!(fmt_default(r#"{"bad": "\uD83D"}"#).is_err());
        assert!(fmt_default(r#"{"bad": "\uD83Dabc"}"#).is_err());
        assert!(fmt_default(r#"{"bad": "\uD83D\u0041"}"#).is_err());
        assert!(fmt_default(r#"{"bad": "\uDE00"}"#).is_err());
    }

    #[test]
    fn test_reject_unclosed_brackets_and_trailing_garbage() {
        assert!(fmt_default("{\"a\": 1").is_err());
        assert!(fmt_default("[1, 2").is_err());
        assert!(fmt_default("{\"a\": [1, 2}").is_err());
        assert!(fmt_default("{\"a\": 1} trailing").is_err());
        assert!(fmt_default("{\"a\": 1} 123").is_err());
    }

    #[test]
    fn test_max_nesting_depth_512() {
        let valid_512 = "[".repeat(512) + &"]".repeat(512);
        assert!(lint_json(valid_512.as_bytes()).is_ok());

        let invalid_513 = "[".repeat(513) + &"]".repeat(513);
        let err = lint_json(invalid_513.as_bytes()).unwrap_err();
        assert!(err.message.contains("512"));
    }

    #[test]
    fn test_tvek_02_output_amplification_bound() {
        let nested = "[".repeat(100) + "1" + &"]".repeat(100);
        let opts = FormatOptions {
            indent: 64,
            ..FormatOptions::default()
        };
        let err = format_json_with_limit(nested.as_bytes(), &opts, 4096).unwrap_err();
        assert!(err.message.contains("exceeds maximum allowed buffer size"));

        let opts_sorted = FormatOptions {
            indent: 64,
            sort_keys: true,
            ..FormatOptions::default()
        };
        let err_sorted = format_json_with_limit(nested.as_bytes(), &opts_sorted, 4096).unwrap_err();
        assert!(err_sorted
            .message
            .contains("exceeds maximum allowed buffer size"));
    }

    #[test]
    fn test_tvek_03_reject_duplicate_object_keys() {
        let dup_exact = r#"{"admin": false, "admin": true}"#;
        let err1 = fmt_default(dup_exact).unwrap_err();
        assert!(err1.message.contains("Duplicate object key"));
        assert_eq!(err1.offset, 17);
        assert!(lint_json(dup_exact.as_bytes()).is_err());

        let dup_escaped = r#"{"\u0061dmin": false, "admin": true}"#;
        let err2 = fmt_default(dup_escaped).unwrap_err();
        assert!(err2.message.contains("Duplicate object key"));
        assert_eq!(err2.offset, 22);

        let sort_opts = FormatOptions {
            sort_keys: true,
            ..FormatOptions::default()
        };
        let err3 = format_json(dup_escaped.as_bytes(), &sort_opts).unwrap_err();
        assert!(err3.message.contains("Duplicate object key"));
        assert_eq!(err3.offset, 22);

        let valid_distinct_scopes = r#"{"a": {"k": 1}, "b": {"k": 2}}"#;
        assert!(fmt_default(valid_distinct_scopes).is_ok());
        assert!(format_json(valid_distinct_scopes.as_bytes(), &sort_opts).is_ok());
    }

    #[test]
    fn test_tvek_04_iterative_sort_keys_deep_nesting_on_small_stack() {
        let mut payload = String::new();
        for _ in 0..256 {
            payload.push_str("{\"b\":1,\"a\":[");
        }
        payload.push_str("42");
        for _ in 0..256 {
            payload.push_str("]}");
        }

        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let opts = FormatOptions {
                    minify: true,
                    sort_keys: true,
                    ..FormatOptions::default()
                };
                let res = format_json(payload.as_bytes(), &opts).unwrap();
                assert!(res.starts_with(b"{\"a\":[{\"a\":["));
            })
            .unwrap();

        handle.join().unwrap();
    }

    #[test]
    fn test_imp_04_sorted_dom_memory_bound() {
        // A compact array `[0,0,0,...]` with 200 elements requires 200 * size_of::<SortedValue>() > 4096 bytes of DOM
        let mut arr = String::from("[0");
        for _ in 0..200 {
            arr.push_str(",0");
        }
        arr.push(']');
        let opts = FormatOptions {
            minify: true,
            sort_keys: true,
            ..FormatOptions::default()
        };
        let err = format_json_with_limit(arr.as_bytes(), &opts, 2048).unwrap_err();
        assert!(err.message.contains("exceeds maximum allowed buffer size"));
    }

    #[test]
    fn test_imp_05_hybrid_keyset_spill_and_swar_strings() {
        // Object with > 8 keys to exercise KeySet::Small -> KeySet::Large spill and duplicate detection
        let mut obj = String::from("{");
        for i in 0..12 {
            if i > 0 {
                obj.push(',');
            }
            obj.push_str(&format!(
                "\"long_ascii_key_for_swar_fast_path_{:02}\": \"value_with_more_than_8_bytes_for_swar\"",
                i
            ));
        }
        obj.push('}');
        assert!(fmt_default(&obj).is_ok());

        // Add a duplicate 13th key matching key 05
        let mut dup_obj = obj[..obj.len() - 1].to_string();
        dup_obj.push_str(",\"long_ascii_key_for_swar_fast_path_05\": 99}");
        let err = fmt_default(&dup_obj).unwrap_err();
        assert!(err.message.contains("Duplicate object key"));
    }

    #[test]
    fn test_imp_08_reject_utf8_bom_explicit_diagnostic() {
        let with_bom = b"\xEF\xBB\xBF{\"a\": 1}";
        let err = lint_json(with_bom).unwrap_err();
        assert!(err.message.contains("UTF-8 BOM"));
        assert_eq!(err.offset, 0);
        assert_eq!(err.line, 1);
        assert_eq!(err.col, 1);

        let err_fmt = format_json(with_bom, &FormatOptions::default()).unwrap_err();
        assert!(err_fmt.message.contains("UTF-8 BOM"));
    }

    #[test]
    fn test_tvek_08_stream_keyset_memory_bound_and_pool_shrink() {
        // Build an object with 100 escaped keys and verify lint_json_with_limit bounds KeySet memory
        let mut obj = String::from("{");
        for i in 0..100 {
            if i > 0 {
                obj.push(',');
            }
            obj.push_str(&format!("\"\\u0061_escaped_key_{:04}\":1", i));
        }
        obj.push('}');

        let err = lint_json_with_limit(obj.as_bytes(), 1024).unwrap_err();
        assert!(err.message.contains("exceeds maximum allowed buffer size"));

        // Verify KeySet::clear downgrades oversized HashSet (> 64 capacity) back to KeySetStorage::Small
        let mut ks = KeySet::new();
        for i in 0..100 {
            ks.insert(Cow::Owned(format!("key_{}", i)));
        }
        assert!(matches!(ks.storage, KeySetStorage::Large(_)));
        let freed = ks.clear();
        assert!(freed > 0);
        assert_eq!(ks.allocated_bytes, 0);
        assert!(matches!(ks.storage, KeySetStorage::Small(_)));
    }

    #[test]
    fn test_jsonc_line_and_block_comments_preserved_in_format() {
        let input = "\
// Leading file comment
/* Second header comment */
{ // open brace comment
  // comment before host
  \"host\": \"localhost\", // inline host comment
  \"ports\": [ /* open bracket comment */
    // first port
    8080, // http
    /* https */
    8443 // last port
    // end of ports array
  ]
  // end of root object
} // inline root comment
// EOF comment
";
        let formatted = fmt_default(input).unwrap();
        assert_eq!(formatted, input);

        // Verify idempotency when formatting a second time
        let formatted_twice = fmt_default(&formatted).unwrap();
        assert_eq!(formatted_twice, input);

        // Verify --minify strips all comments cleanly
        let minify_opts = FormatOptions {
            minify: true,
            ..FormatOptions::default()
        };
        let minified =
            String::from_utf8(format_json(input.as_bytes(), &minify_opts).unwrap()).unwrap();
        assert_eq!(minified, "{\"host\":\"localhost\",\"ports\":[8080,8443]}\n");
    }

    #[test]
    fn test_jsonc_empty_containers_with_comments() {
        let obj_input = "{ /* inside empty object */ }";
        let expected_obj = "{\n  /* inside empty object */\n}\n";
        assert_eq!(fmt_default(obj_input).unwrap(), expected_obj);

        let arr_input = "[\n  // inside empty array\n]";
        let expected_arr = "[\n  // inside empty array\n]\n";
        assert_eq!(fmt_default(arr_input).unwrap(), expected_arr);

        let sort_opts = FormatOptions {
            sort_keys: true,
            ..FormatOptions::default()
        };
        assert_eq!(
            String::from_utf8(format_json(obj_input.as_bytes(), &sort_opts).unwrap()).unwrap(),
            expected_obj
        );
        assert_eq!(
            String::from_utf8(format_json(arr_input.as_bytes(), &sort_opts).unwrap()).unwrap(),
            expected_arr
        );

        let minify_opts = FormatOptions {
            minify: true,
            ..FormatOptions::default()
        };
        assert_eq!(
            String::from_utf8(format_json(obj_input.as_bytes(), &minify_opts).unwrap()).unwrap(),
            "{}\n"
        );
        assert_eq!(
            String::from_utf8(format_json(arr_input.as_bytes(), &minify_opts).unwrap()).unwrap(),
            "[]\n"
        );
    }

    #[test]
    fn test_jsonc_sort_keys_moves_comments_with_keys() {
        let input = "\
// Header comment
{
  // Comment for b
  \"b\": 1, // inline on b
  // Comment for a
  \"a\": 2 // inline on a
  // Footer inside object
}
// EOF comment
";
        let expected = "\
// Header comment
{
  // Comment for a
  \"a\": 2, // inline on a
  // Comment for b
  \"b\": 1 // inline on b
  // Footer inside object
}
// EOF comment
";
        let sort_opts = FormatOptions {
            sort_keys: true,
            ..FormatOptions::default()
        };
        let out = String::from_utf8(format_json(input.as_bytes(), &sort_opts).unwrap()).unwrap();
        assert_eq!(out, expected);

        let minify_sort_opts = FormatOptions {
            minify: true,
            sort_keys: true,
            ..FormatOptions::default()
        };
        let out_min =
            String::from_utf8(format_json(input.as_bytes(), &minify_sort_opts).unwrap()).unwrap();
        assert_eq!(out_min, "{\"a\":2,\"b\":1}\n");
    }

    #[test]
    fn test_jsonc_strict_mode_rejects_comments() {
        let with_line_comment = b"{\n  // comment\n  \"a\": 1\n}";
        let with_block_comment = b"{\"a\": /* comment */ 1}";

        assert!(lint_json(with_line_comment).is_ok());
        assert!(lint_json(with_block_comment).is_ok());

        let err_line = lint_json_strict(with_line_comment, DEFAULT_MAX_OUTPUT_BYTES).unwrap_err();
        assert!(err_line.message.contains("strict RFC 8259"));

        let err_block = lint_json_strict(with_block_comment, DEFAULT_MAX_OUTPUT_BYTES).unwrap_err();
        assert!(err_block.message.contains("strict RFC 8259"));

        let strict_opts = FormatOptions {
            allow_comments: false,
            ..FormatOptions::default()
        };
        assert!(format_json(with_line_comment, &strict_opts).is_err());
        assert!(format_json(with_block_comment, &strict_opts).is_err());
    }

    #[test]
    fn test_jsonc_unterminated_block_comment_and_invalid_utf8() {
        let unterminated_1 = b"{\"a\": 1} /* unterminated";
        let err1 = lint_json(unterminated_1).unwrap_err();
        assert!(err1.message.contains("Unterminated block comment"));

        let unterminated_2 = b"/*/";
        let err2 = lint_json(unterminated_2).unwrap_err();
        assert!(err2.message.contains("Unterminated block comment"));

        let lone_slash = b"{ / \"a\": 1 }";
        let err3 = lint_json(lone_slash).unwrap_err();
        assert!(err3.message.contains("expected '//' or '/*'"));

        let bad_ctrl_line = b"// bad \x07 bell\n{\"a\": 1}";
        let err4 = lint_json(bad_ctrl_line).unwrap_err();
        assert!(err4.message.contains("Control character is not allowed"));

        let bad_ctrl_block = b"/* bad \x00 null */ {\"a\": 1}";
        let err5 = lint_json(bad_ctrl_block).unwrap_err();
        assert!(err5.message.contains("Control character is not allowed"));

        let bad_utf8_comment = b"// invalid \xFF utf8\n{\"a\": 1}";
        let err6 = lint_json(bad_utf8_comment).unwrap_err();
        assert!(err6.message.contains("Invalid UTF-8"));
    }

    #[test]
    fn test_tvek_16_reject_bare_cr_in_block_comment_breakout() {
        // Bare '\r' (0x0D) inside a block comment (`/* *\r/ "admin": true, /* */`) must be rejected
        // so stripping '\r' during formatting can never fuse `*` and `/` into `*/` (TVEK-16).
        let smuggling_payload = b"{\n  /* *\r/ \"admin\": true, /* */\n  \"admin\": false\n}";
        let lint_err = lint_json(smuggling_payload).unwrap_err();
        assert!(lint_err
            .message
            .contains("Control character is not allowed in JSON comment"));

        let fmt_err = format_json(smuggling_payload, &FormatOptions::default()).unwrap_err();
        assert!(fmt_err
            .message
            .contains("Control character is not allowed in JSON comment"));

        // Valid CRLF (`\r\n`) inside a block comment remains allowed and normalized to `\n`
        let valid_crlf_comment = b"{\r\n  /* line 1\r\n   * line 2 */\r\n  \"a\": 1\r\n}\r\n";
        assert!(lint_json(valid_crlf_comment).is_ok());
        let formatted =
            String::from_utf8(format_json(valid_crlf_comment, &FormatOptions::default()).unwrap())
                .unwrap();
        assert_eq!(formatted, "{\n  /* line 1\n   * line 2 */\n  \"a\": 1\n}\n");
    }

    #[test]
    fn test_tvek_17_sorted_array_item_overhead_and_multiline_comment_idempotency() {
        // 1. Multi-line block comment before `,` followed by another comment after `,` must format idempotently
        let obj_input = "{\n  \"a\": 1 /* line 1\n  line 2 */, // after\n  \"b\": 2\n}";
        let pass1 = fmt_default(obj_input).unwrap();
        let pass2 = fmt_default(&pass1).unwrap();
        assert_eq!(
            pass1, pass2,
            "Formatting multi-line block comment before comma must be idempotent"
        );

        let arr_input = "[\n  1 /* line 1\n  line 2 */, // after\n  2\n]";
        let arr_pass1 = fmt_default(arr_input).unwrap();
        let arr_pass2 = fmt_default(&arr_pass1).unwrap();
        assert_eq!(
            arr_pass1, arr_pass2,
            "Formatting array with multi-line block comment before comma must be idempotent"
        );

        // 2. Verify SortedArrayItem wrapper overhead is charged in SortedDomBuilder
        let mut arr = String::from("[0");
        for _ in 0..19 {
            arr.push_str(",0");
        }
        arr.push(']');
        // 20 elements * size_of::<SortedArrayItem>() (128 bytes) + root SortedValue (80 bytes) = 2640 bytes > 2048
        let sort_opts = FormatOptions {
            minify: true,
            sort_keys: true,
            ..FormatOptions::default()
        };
        let err = format_json_with_limit(arr.as_bytes(), &sort_opts, 2048).unwrap_err();
        assert!(err.message.contains("exceeds maximum allowed buffer size"));
    }

    #[test]
    fn test_perf_05_fxhasher_and_keyset_pool_reuse() {
        // Build an array of sibling objects, each with > 8 keys to exercise FxHasher and KeySet pool reuse
        let mut json = String::from("[");
        for obj_idx in 0..8 {
            if obj_idx > 0 {
                json.push(',');
            }
            json.push('{');
            for k in 0..16 {
                if k > 0 {
                    json.push(',');
                }
                json.push_str(&format!("\"sibling_key_{:02}\":{}", k, obj_idx));
            }
            json.push('}');
        }
        json.push(']');

        assert!(lint_json(json.as_bytes()).is_ok());
        let formatted = fmt_default(&json).unwrap();
        assert!(lint_json(formatted.as_bytes()).is_ok());
    }

    #[test]
    fn test_tvek_20_tiered_keyset_upgrades_to_siphash_above_64_keys() {
        let mut set = KeySet::new();
        for i in 0..64 {
            let (ok, _) = set.insert(Cow::Owned(format!("k_{}", i)));
            assert!(ok);
        }
        assert!(matches!(set.storage, KeySetStorage::Medium(_)));

        // Duplicate within Medium tier must be rejected without upgrading
        let (dup_ok, _) = set.insert(Cow::Borrowed("k_10"));
        assert!(!dup_ok);
        assert!(matches!(set.storage, KeySetStorage::Medium(_)));

        // 65th unique key must upgrade to Large (RandomState SipHash-1-3)
        let (ok_65, _) = set.insert(Cow::Borrowed("k_64"));
        assert!(ok_65);
        assert!(matches!(set.storage, KeySetStorage::Large(_)));

        // Clearing a Large KeySet downgrades back to Small to free memory immediately
        set.clear();
        assert!(matches!(set.storage, KeySetStorage::Small(_)));
    }

    #[test]
    fn test_simd_string_and_whitespace_utf8_bidi_safety() {
        // Test strings > 64 bytes (exercising 32-byte AVX2, 16-byte NEON, and 8-byte SWAR tail)
        // at every byte alignment offset 0..32 to prove PERF-09 stops on control chars, quotes,
        // backslashes, UTF-8 multi-byte chars, and invalid 0xFF bytes.
        for offset in 0..32 {
            let prefix = "a".repeat(offset);
            let suffix = "b".repeat(72);

            // 1. Valid multi-byte UTF-8 emoji and Trojan Source BiDi char (\u{202E}) inside >64B string
            let valid_utf8 = format!("{{\"k\":\"{}\u{202E}😀{}\"}}", prefix, suffix);
            assert!(lint_json(valid_utf8.as_bytes()).is_ok());

            // 2. Unescaped control byte (0x1F) at every offset must be rejected
            let mut bad_ctrl = Vec::from(b"{\"k\":\"".as_slice());
            bad_ctrl.extend_from_slice(prefix.as_bytes());
            bad_ctrl.push(0x1F);
            bad_ctrl.extend_from_slice(suffix.as_bytes());
            bad_ctrl.extend_from_slice(b"\"}");
            assert!(lint_json(&bad_ctrl).is_err());

            // 3. Invalid UTF-8 byte (0xFF) at every offset must never be skipped by SIMD
            let mut bad_utf8 = Vec::from(b"{\"k\":\"".as_slice());
            bad_utf8.extend_from_slice(prefix.as_bytes());
            bad_utf8.push(0xFF);
            bad_utf8.extend_from_slice(suffix.as_bytes());
            bad_utf8.extend_from_slice(b"\"}");
            assert!(lint_json(&bad_utf8).is_err());

            // 4. Verify skip_ascii_spaces stops accurately at every offset 0..64
            let spaces_and_brace = format!("{}{{}}", " ".repeat(offset + 40));
            assert_eq!(skip_ascii_spaces(spaces_and_brace.as_bytes()), offset + 40);
        }
    }

    #[test]
    fn test_width_aware_inline_array_and_structural_mode() {
        // 1. User sample: default width-aware (line_width = 80) keeps short scalar arrays inline
        let sample = "{\"first\": [\n  1,\n  2,\n  3\n], \"second\": [1, 2, 3]}";
        let expected_inline = "{\n  \"first\": [1, 2, 3],\n  \"second\": [1, 2, 3]\n}\n";
        assert_eq!(fmt_default(sample).unwrap(), expected_inline);

        // 2. --sort-keys produces the exact same width-aware inline array output
        let sort_opts = FormatOptions {
            sort_keys: true,
            ..FormatOptions::default()
        };
        assert_eq!(
            String::from_utf8(format_json(sample.as_bytes(), &sort_opts).unwrap()).unwrap(),
            expected_inline
        );

        // 3. --structural (line_width: 0) expands every element onto its own line
        let structural_opts = FormatOptions {
            line_width: 0,
            ..FormatOptions::default()
        };
        let expected_structural =
            "{\n  \"first\": [\n    1,\n    2,\n    3\n  ],\n  \"second\": [\n    1,\n    2,\n    3\n  ]\n}\n";
        assert_eq!(
            String::from_utf8(format_json(sample.as_bytes(), &structural_opts).unwrap()).unwrap(),
            expected_structural
        );

        // 4. Scalar arrays exceeding 80 columns expand automatically in both streaming and --sort-keys
        let long_arr = r#"{"numbers": [1000000001, 1000000002, 1000000003, 1000000004, 1000000005, 1000000006, 1000000007]}"#;
        let formatted_long = fmt_default(long_arr).unwrap();
        assert!(formatted_long.contains("\"numbers\": [\n    1000000001,"));
        let sorted_long =
            String::from_utf8(format_json(long_arr.as_bytes(), &sort_opts).unwrap()).unwrap();
        assert_eq!(formatted_long, sorted_long);

        // 5. Arrays containing comments or nested containers expand to multi-line while inner scalar arrays stay inline
        let nested_and_comment =
            "{\n  \"with_comment\": [1, /* c */ 2],\n  \"matrix\": [[1, 2], [3, 4]]\n}";
        let expected_nested = "{\n  \"with_comment\": [\n    1, /* c */\n    2\n  ],\n  \"matrix\": [\n    [1, 2],\n    [3, 4]\n  ]\n}\n";
        assert_eq!(fmt_default(nested_and_comment).unwrap(), expected_nested);
    }
}
