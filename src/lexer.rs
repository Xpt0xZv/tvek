use std::borrow::Cow;
use std::collections::HashSet;
use std::mem::size_of;

use crate::error::SyntaxError;

pub const MAX_DEPTH: usize = 512;
pub const DEFAULT_MAX_INPUT_BYTES: usize = 100 * 1024 * 1024; // 100 MiB
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024; // 256 MiB
const MAX_INITIAL_CAPACITY: usize = 16 * 1024 * 1024; // 16 MiB cap on initial Vec reservation
const SMALL_KEY_SET_LIMIT: usize = 8;
const MAX_POOLED_HASHSET_CAPACITY: usize = 64;
const MAX_FREE_KEY_SETS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatOptions {
    pub minify: bool,
    pub indent: usize,
    pub sort_keys: bool,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            minify: false,
            indent: 2,
            sort_keys: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerKind {
    Object,
    Array,
}

/// Hybrid key set that uses a flat `Vec` for small objects (`<= 8` keys) and upgrades
/// to a `HashSet` for larger objects, tracking heap memory and shrinking oversized tables (IMP-05 / TVEK-08).
enum KeySetStorage<'a> {
    Small(Vec<Cow<'a, str>>),
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
                    let mut set = HashSet::with_capacity(SMALL_KEY_SET_LIMIT * 2);
                    for item in vec.drain(..) {
                        set.insert(item);
                    }
                    let ok = set.insert(key);
                    self.storage = KeySetStorage::Large(set);
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
    /// beyond `MAX_POOLED_HASHSET_CAPACITY`, downgrades back to `Small` so multi-megabyte tables
    /// are deallocated immediately on `}` (TVEK-08).
    #[inline]
    fn clear(&mut self) -> usize {
        let freed = self.allocated_bytes;
        self.allocated_bytes = 0;
        match &mut self.storage {
            KeySetStorage::Small(vec) => vec.clear(),
            KeySetStorage::Large(set) => {
                if set.capacity() > MAX_POOLED_HASHSET_CAPACITY {
                    self.storage =
                        KeySetStorage::Small(Vec::with_capacity(SMALL_KEY_SET_LIMIT));
                } else {
                    set.clear();
                }
            }
        }
        freed
    }
}

/// Pre-allocated single-slice indentation table for O(1) slice emission up to `MAX_DEPTH` (IMP-05).
struct IndentTable {
    buf: Vec<u8>,
    unit_len: usize,
}

impl IndentTable {
    fn new(indent: usize, minify: bool) -> Self {
        if minify {
            return Self {
                buf: Vec::new(),
                unit_len: 0,
            };
        }
        if indent == 0 {
            Self {
                buf: vec![b'\t'; MAX_DEPTH],
                unit_len: 1,
            }
        } else {
            Self {
                buf: vec![b' '; indent.saturating_mul(MAX_DEPTH)],
                unit_len: indent,
            }
        }
    }

    #[inline(always)]
    fn slice_for_depth(&self, depth: usize) -> &[u8] {
        let len = self.unit_len.saturating_mul(depth).min(self.buf.len());
        &self.buf[..len]
    }
}

/// Validate RFC 8259 syntax in a single streaming byte pass without allocating formatted output.
pub fn lint_json(input: &[u8]) -> Result<(), SyntaxError> {
    lint_json_with_limit(input, DEFAULT_MAX_OUTPUT_BYTES)
}

/// Validate RFC 8259 syntax in a single streaming byte pass with an explicit upper bound
/// on active object key-set memory (TVEK-08).
pub fn lint_json_with_limit(input: &[u8], max_key_bytes: usize) -> Result<(), SyntaxError> {
    let opts = FormatOptions {
        minify: true,
        indent: 0,
        sort_keys: false,
    };
    let indent_table = IndentTable::new(0, true);
    let mut sink = NullSink;
    let mut emitter = StreamEmitter::new(&mut sink, &opts, &indent_table, max_key_bytes);
    let mut scanner = Scanner::new(input);
    scanner.run_unified_parser(&mut emitter)
}

/// Validate RFC 8259 syntax and format JSON according to `options` with the default output size cap.
pub fn format_json(input: &[u8], options: &FormatOptions) -> Result<Vec<u8>, SyntaxError> {
    format_json_with_limit(input, options, DEFAULT_MAX_OUTPUT_BYTES)
}

/// Validate RFC 8259 syntax and format JSON with an explicit upper bound on output and DOM memory
/// to prevent memory amplification DoS (TVEK-02 / IMP-04 / TVEK-08).
pub fn format_json_with_limit(
    input: &[u8],
    options: &FormatOptions,
    max_output_bytes: usize,
) -> Result<Vec<u8>, SyntaxError> {
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

    let indent_table = IndentTable::new(options.indent, options.minify);
    let mut sink = BoundedVecSink::new(initial_cap, max_output_bytes);
    let mut scanner = Scanner::new(input);

    if options.sort_keys {
        let mut builder = SortedDomBuilder::new(max_output_bytes);
        scanner.run_unified_parser(&mut builder)?;
        let root = builder
            .current_val
            .ok_or_else(|| SyntaxError::new("Unexpected end of JSON input", input.len(), input))?;
        emit_sorted_value_iterative(&root, &mut sink, options, &indent_table)
            .map_err(|msg| SyntaxError::new(msg, input.len(), input))?;
        sink.push_byte(b'\n')
            .map_err(|msg| SyntaxError::new(msg, input.len(), input))?;
    } else {
        let mut emitter = StreamEmitter::new(&mut sink, options, &indent_table, max_output_bytes);
        scanner.run_unified_parser(&mut emitter)?;
    }

    Ok(sink.into_inner())
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

struct BoundedVecSink {
    buf: Vec<u8>,
    max_bytes: usize,
}

impl BoundedVecSink {
    #[inline]
    fn new(capacity: usize, max_bytes: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            max_bytes,
        }
    }

    #[inline]
    fn into_inner(self) -> Vec<u8> {
        self.buf
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

impl OutputSink for BoundedVecSink {
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

/// Zero-cost generic event interface unifying single-pass streaming and `--sort-keys` DOM construction (IMP-06).
trait ParseEvents<'a> {
    fn depth(&self) -> usize;
    fn top_container(&self) -> Option<ContainerKind>;

    fn on_empty_object(
        &mut self,
        open_pos: usize,
        close_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_open_object(
        &mut self,
        open_pos: usize,
        first_key_slice: &'a [u8],
        first_key_pos: usize,
        colon_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_object_next_key(
        &mut self,
        comma_pos: usize,
        key_slice: &'a [u8],
        key_pos: usize,
        colon_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_close_object(&mut self, close_pos: usize, input: &'a [u8]) -> Result<(), SyntaxError>;

    fn on_empty_array(
        &mut self,
        open_pos: usize,
        close_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_open_array(&mut self, open_pos: usize, input: &'a [u8]) -> Result<(), SyntaxError>;

    fn on_array_comma(
        &mut self,
        comma_pos: usize,
        next_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_close_array(&mut self, close_pos: usize, input: &'a [u8]) -> Result<(), SyntaxError>;

    fn on_primitive(
        &mut self,
        slice: &'a [u8],
        pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError>;

    fn on_finish(&mut self, end_pos: usize, input: &'a [u8]) -> Result<(), SyntaxError>;
}

enum StreamFrame<'a> {
    Object(KeySet<'a>),
    Array,
}

struct StreamEmitter<'a, 'b, S: OutputSink> {
    out: &'b mut S,
    minify: bool,
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
    fn emit_key(
        &mut self,
        key_slice: &'a [u8],
        key_pos: usize,
        colon_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.out
            .extend_slice(key_slice)
            .map_err(|msg| SyntaxError::new(msg, key_pos, input))?;
        self.out
            .push_byte(b':')
            .map_err(|msg| SyntaxError::new(msg, colon_pos, input))?;
        if !self.minify {
            self.out
                .push_byte(b' ')
                .map_err(|msg| SyntaxError::new(msg, colon_pos, input))?;
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
    fn on_empty_object(
        &mut self,
        open_pos: usize,
        close_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.out
            .push_byte(b'{')
            .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
        self.out
            .push_byte(b'}')
            .map_err(|msg| SyntaxError::new(msg, close_pos, input))
    }

    #[inline(always)]
    fn on_open_object(
        &mut self,
        open_pos: usize,
        first_key_slice: &'a [u8],
        first_key_pos: usize,
        colon_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        let new_depth = self.stack.len() + 1;
        self.out
            .push_byte(b'{')
            .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
        if !self.minify {
            self.out
                .push_byte(b'\n')
                .map_err(|msg| SyntaxError::new(msg, first_key_pos, input))?;
            self.out
                .push_indent(self.indent_table, new_depth)
                .map_err(|msg| SyntaxError::new(msg, first_key_pos, input))?;
        }

        let mut key_set = self.free_sets.pop().unwrap_or_else(KeySet::new);
        let (_, added) = key_set.insert(decode_json_key_for_sort(first_key_slice));
        self.charge_key_bytes(added, first_key_pos, input)?;
        self.emit_key(first_key_slice, first_key_pos, colon_pos, input)?;
        self.stack.push(StreamFrame::Object(key_set));
        Ok(())
    }

    #[inline(always)]
    fn on_object_next_key(
        &mut self,
        comma_pos: usize,
        key_slice: &'a [u8],
        key_pos: usize,
        colon_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        let depth = self.stack.len();
        let mut added_bytes = 0usize;
        if let Some(StreamFrame::Object(key_set)) = self.stack.last_mut() {
            let decoded = decode_json_key_for_sort(key_slice);
            let (inserted, added) = key_set.insert(decoded);
            if !inserted {
                return Err(SyntaxError::new(
                    "Duplicate object key is not allowed in JSON object",
                    key_pos,
                    input,
                ));
            }
            added_bytes = added;
        }
        self.charge_key_bytes(added_bytes, key_pos, input)?;
        self.out
            .push_byte(b',')
            .map_err(|msg| SyntaxError::new(msg, comma_pos, input))?;
        if !self.minify {
            self.out
                .push_byte(b'\n')
                .map_err(|msg| SyntaxError::new(msg, key_pos, input))?;
            self.out
                .push_indent(self.indent_table, depth)
                .map_err(|msg| SyntaxError::new(msg, key_pos, input))?;
        }
        self.emit_key(key_slice, key_pos, colon_pos, input)
    }

    #[inline(always)]
    fn on_close_object(&mut self, close_pos: usize, input: &'a [u8]) -> Result<(), SyntaxError> {
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
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.out
            .push_byte(b'[')
            .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
        self.out
            .push_byte(b']')
            .map_err(|msg| SyntaxError::new(msg, close_pos, input))
    }

    #[inline(always)]
    fn on_open_array(&mut self, open_pos: usize, input: &'a [u8]) -> Result<(), SyntaxError> {
        let new_depth = self.stack.len() + 1;
        self.out
            .push_byte(b'[')
            .map_err(|msg| SyntaxError::new(msg, open_pos, input))?;
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
        next_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        let depth = self.stack.len();
        self.out
            .push_byte(b',')
            .map_err(|msg| SyntaxError::new(msg, comma_pos, input))?;
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
    fn on_close_array(&mut self, close_pos: usize, input: &'a [u8]) -> Result<(), SyntaxError> {
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
    fn on_primitive(
        &mut self,
        slice: &'a [u8],
        pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.out
            .extend_slice(slice)
            .map_err(|msg| SyntaxError::new(msg, pos, input))
    }

    #[inline(always)]
    fn on_finish(&mut self, end_pos: usize, input: &'a [u8]) -> Result<(), SyntaxError> {
        self.out
            .push_byte(b'\n')
            .map_err(|msg| SyntaxError::new(msg, end_pos, input))
    }
}

struct SortedEntry<'a> {
    sort_key: Cow<'a, str>,
    raw_key: &'a [u8],
    key_pos: usize,
    value: SortedValue<'a>,
}

enum SortedValue<'a> {
    Raw(&'a [u8]),
    Array(Vec<SortedValue<'a>>),
    Object(Vec<SortedEntry<'a>>),
}

enum SortBuildFrame<'a> {
    Object {
        entries: Vec<SortedEntry<'a>>,
        pending_key: (Cow<'a, str>, &'a [u8], usize),
    },
    Array {
        items: Vec<SortedValue<'a>>,
    },
}

/// Bounded DOM builder for `--sort-keys` that tracks in-memory node allocations and checks
/// duplicate keys via adjacent sorted pairs without cloning keys or allocating `HashSet`s (IMP-04).
struct SortedDomBuilder<'a> {
    stack: Vec<SortBuildFrame<'a>>,
    current_val: Option<SortedValue<'a>>,
    allocated_dom_bytes: usize,
    max_dom_bytes: usize,
}

impl<'a> SortedDomBuilder<'a> {
    fn new(max_dom_bytes: usize) -> Self {
        Self {
            stack: Vec::with_capacity(32),
            current_val: None,
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
    fn commit_object_entry(&mut self) {
        let val = self.current_val.take().expect("Expected completed value");
        if let Some(SortBuildFrame::Object {
            entries,
            pending_key,
        }) = self.stack.last_mut()
        {
            let (sort_key, raw_key, key_pos) =
                std::mem::replace(pending_key, (Cow::Borrowed(""), &[], 0));
            entries.push(SortedEntry {
                sort_key,
                raw_key,
                key_pos,
                value: val,
            });
        }
    }

    #[inline(always)]
    fn commit_array_item(&mut self) {
        let val = self.current_val.take().expect("Expected completed value");
        if let Some(SortBuildFrame::Array { items }) = self.stack.last_mut() {
            items.push(val);
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
    fn on_empty_object(
        &mut self,
        open_pos: usize,
        _close_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.charge_dom_bytes(size_of::<SortedValue<'a>>(), open_pos, input)?;
        self.current_val = Some(SortedValue::Object(Vec::new()));
        Ok(())
    }

    #[inline(always)]
    fn on_open_object(
        &mut self,
        _open_pos: usize,
        first_key_slice: &'a [u8],
        first_key_pos: usize,
        _colon_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        let sort_key = decode_json_key_for_sort(first_key_slice);
        let owned_len = match &sort_key {
            Cow::Borrowed(_) => 0,
            Cow::Owned(s) => s.len(),
        };
        self.charge_dom_bytes(
            size_of::<SortedEntry<'a>>().saturating_add(owned_len),
            first_key_pos,
            input,
        )?;
        self.stack.push(SortBuildFrame::Object {
            entries: Vec::new(),
            pending_key: (sort_key, first_key_slice, first_key_pos),
        });
        Ok(())
    }

    #[inline(always)]
    fn on_object_next_key(
        &mut self,
        _comma_pos: usize,
        key_slice: &'a [u8],
        key_pos: usize,
        _colon_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.commit_object_entry();
        let sort_key = decode_json_key_for_sort(key_slice);
        let owned_len = match &sort_key {
            Cow::Borrowed(_) => 0,
            Cow::Owned(s) => s.len(),
        };
        let entry_key_overhead = size_of::<SortedEntry<'a>>() - size_of::<SortedValue<'a>>();
        self.charge_dom_bytes(
            entry_key_overhead.saturating_add(owned_len),
            key_pos,
            input,
        )?;
        if let Some(SortBuildFrame::Object { pending_key, .. }) = self.stack.last_mut() {
            *pending_key = (sort_key, key_slice, key_pos);
        }
        Ok(())
    }

    #[inline(always)]
    fn on_close_object(&mut self, _close_pos: usize, input: &'a [u8]) -> Result<(), SyntaxError> {
        self.commit_object_entry();
        if let Some(SortBuildFrame::Object { mut entries, .. }) = self.stack.pop() {
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
            self.current_val = Some(SortedValue::Object(entries));
        }
        Ok(())
    }

    #[inline(always)]
    fn on_empty_array(
        &mut self,
        open_pos: usize,
        _close_pos: usize,
        input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.charge_dom_bytes(size_of::<SortedValue<'a>>(), open_pos, input)?;
        self.current_val = Some(SortedValue::Array(Vec::new()));
        Ok(())
    }

    #[inline(always)]
    fn on_open_array(&mut self, open_pos: usize, input: &'a [u8]) -> Result<(), SyntaxError> {
        self.charge_dom_bytes(size_of::<SortedValue<'a>>(), open_pos, input)?;
        self.stack.push(SortBuildFrame::Array { items: Vec::new() });
        Ok(())
    }

    #[inline(always)]
    fn on_array_comma(
        &mut self,
        _comma_pos: usize,
        _next_pos: usize,
        _input: &'a [u8],
    ) -> Result<(), SyntaxError> {
        self.commit_array_item();
        Ok(())
    }

    #[inline(always)]
    fn on_close_array(&mut self, _close_pos: usize, _input: &'a [u8]) -> Result<(), SyntaxError> {
        self.commit_array_item();
        if let Some(SortBuildFrame::Array { items }) = self.stack.pop() {
            self.current_val = Some(SortedValue::Array(items));
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
    fn on_finish(&mut self, _end_pos: usize, _input: &'a [u8]) -> Result<(), SyntaxError> {
        Ok(())
    }
}

struct Scanner<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    #[inline]
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    #[inline]
    fn err(&self, message: &'static str, offset: usize) -> SyntaxError {
        SyntaxError::new(message, offset, self.input)
    }

    /// Skip strictly RFC 8259 insignificant whitespace: 0x20, 0x09, 0x0A, 0x0D.
    #[inline]
    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() {
            match self.input[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    /// Unified single-pass iterative RFC 8259 parser driving `ParseEvents` (IMP-06).
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

        self.skip_whitespace();
        if self.pos >= self.input.len() {
            return Err(self.err("Unexpected end of JSON input", self.pos));
        }

        'expect_value: loop {
            self.skip_whitespace();
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
                        return Err(self.err(
                            "Maximum nesting depth of 512 exceeded",
                            open_pos,
                        ));
                    }
                    self.pos += 1;
                    self.skip_whitespace();

                    if self.pos >= self.input.len() {
                        return Err(self.err("Unterminated JSON object", open_pos));
                    }
                    if self.input[self.pos] == b'}' {
                        let close_pos = self.pos;
                        self.pos += 1;
                        events.on_empty_object(open_pos, close_pos, self.input)?;
                        break; // Completed empty `{}` value
                    }

                    let (key_slice, key_pos, colon_pos) = self.scan_key_and_colon()?;
                    events.on_open_object(
                        open_pos,
                        key_slice,
                        key_pos,
                        colon_pos,
                        self.input,
                    )?;
                    self.skip_whitespace();
                    if self.pos >= self.input.len() {
                        return Err(self.err("Expected JSON value after ':'", self.pos));
                    }
                } else if b == b'[' {
                    let open_pos = self.pos;
                    let new_depth = events.depth() + 1;
                    if new_depth > MAX_DEPTH {
                        return Err(self.err(
                            "Maximum nesting depth of 512 exceeded",
                            open_pos,
                        ));
                    }
                    self.pos += 1;
                    self.skip_whitespace();

                    if self.pos >= self.input.len() {
                        return Err(self.err("Unterminated JSON array", open_pos));
                    }
                    if self.input[self.pos] == b']' {
                        let close_pos = self.pos;
                        self.pos += 1;
                        events.on_empty_array(open_pos, close_pos, self.input)?;
                        break; // Completed empty `[]` value
                    }

                    events.on_open_array(open_pos, self.input)?;
                } else {
                    let prim_pos = self.pos;
                    let slice = self.scan_primitive()?;
                    events.on_primitive(slice, prim_pos, self.input)?;
                    break;
                }
            }

            // Completed a value; now handle continuation or closing of enclosing containers
            while let Some(container) = events.top_container() {
                self.skip_whitespace();
                match container {
                    ContainerKind::Object => {
                        if self.pos >= self.input.len() {
                            return Err(self.err("Unterminated JSON object", self.pos));
                        }
                        match self.input[self.pos] {
                            b',' => {
                                let comma_pos = self.pos;
                                self.pos += 1;
                                self.skip_whitespace();
                                if self.pos >= self.input.len() {
                                    return Err(self.err("Unterminated JSON object", self.pos));
                                }
                                if self.input[self.pos] == b'}' {
                                    return Err(self.err(
                                        "Trailing comma is not allowed in JSON object",
                                        comma_pos,
                                    ));
                                }
                                let (key_slice, key_pos, colon_pos) =
                                    self.scan_key_and_colon()?;
                                events.on_object_next_key(
                                    comma_pos,
                                    key_slice,
                                    key_pos,
                                    colon_pos,
                                    self.input,
                                )?;
                                self.skip_whitespace();
                                if self.pos >= self.input.len() {
                                    return Err(
                                        self.err("Expected JSON value after ':'", self.pos)
                                    );
                                }
                                continue 'expect_value;
                            }
                            b'}' => {
                                let close_pos = self.pos;
                                self.pos += 1;
                                events.on_close_object(close_pos, self.input)?;
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
                                self.skip_whitespace();
                                if self.pos >= self.input.len() {
                                    return Err(self.err("Unterminated JSON array", self.pos));
                                }
                                if self.input[self.pos] == b']' {
                                    return Err(self.err(
                                        "Trailing comma is not allowed in JSON array",
                                        comma_pos,
                                    ));
                                }
                                events.on_array_comma(comma_pos, self.pos, self.input)?;
                                continue 'expect_value;
                            }
                            b']' => {
                                let close_pos = self.pos;
                                self.pos += 1;
                                events.on_close_array(close_pos, self.input)?;
                            }
                            _ => {
                                return Err(
                                    self.err("Expected ',' or ']' in JSON array", self.pos)
                                );
                            }
                        }
                    }
                }
            }

            break 'expect_value;
        }

        self.skip_whitespace();
        if self.pos < self.input.len() {
            return Err(self.err("Trailing data after root JSON value", self.pos));
        }

        events.on_finish(self.pos, self.input)
    }

    #[inline(always)]
    fn scan_key_and_colon(&mut self) -> Result<(&'a [u8], usize, usize), SyntaxError> {
        let key_pos = self.pos;
        let key_slice = self.scan_object_key()?;
        self.skip_whitespace();
        if self.pos >= self.input.len() || self.input[self.pos] != b':' {
            return Err(self.err("Expected ':' after object key", self.pos));
        }
        let colon_pos = self.pos;
        self.pos += 1;
        Ok((key_slice, key_pos, colon_pos))
    }

    fn scan_object_key(&mut self) -> Result<&'a [u8], SyntaxError> {
        if self.pos >= self.input.len() {
            return Err(self.err("Expected object key, found end of input", self.pos));
        }
        match self.input[self.pos] {
            b'"' => self.scan_string(),
            b'\'' => Err(self.err(
                "Single-quoted strings are not allowed in JSON",
                self.pos,
            )),
            b',' => Err(self.err("Unexpected comma in JSON object", self.pos)),
            _ => Err(self.err(
                "Object keys must be double-quoted strings",
                self.pos,
            )),
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
            b'\'' => Err(self.err(
                "Single-quoted strings are not allowed in JSON",
                self.pos,
            )),
            b'+' => Err(self.err(
                "Leading '+' sign is not allowed in JSON numbers",
                self.pos,
            )),
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
                    return Err(self.err(
                        "Leading zeros are not allowed in JSON numbers",
                        start,
                    ));
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

    /// Strict RFC 8259 string scanner with 8-byte SWAR fast-path (IMP-05),
    /// escape validation, and UTF-16 surrogate pair verification.
    fn scan_string(&mut self) -> Result<&'a [u8], SyntaxError> {
        let start = self.pos;
        self.pos += 1; // Skip opening `"`

        while self.pos < self.input.len() {
            // SWAR (u64) fast-path: skip 8 bytes at a time when all 8 bytes are plain ASCII
            // in 0x20..=0x7F and neither `"` (0x22) nor `\` (0x5C) (IMP-05).
            while self.pos + 8 <= self.input.len() {
                let chunk = u64::from_ne_bytes(
                    self.input[self.pos..self.pos + 8].try_into().unwrap(),
                );
                if is_plain_ascii_string_chunk(chunk) {
                    self.pos += 8;
                } else {
                    break;
                }
            }

            if self.pos >= self.input.len() {
                break;
            }

            let b = self.input[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(&self.input[start..self.pos]);
            } else if b < 0x20 {
                return Err(self.err(
                    "Unescaped control character is not allowed in JSON string",
                    self.pos,
                ));
            } else if b == b'\\' {
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

/// Returns true if all 8 bytes in `chunk` are in `0x20..=0x7F` and none equal `"` (`0x22`) or `\` (`0x5C`).
#[inline(always)]
fn is_plain_ascii_string_chunk(chunk: u64) -> bool {
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

enum EmitFrame<'b, 'a> {
    Array {
        items: &'b [SortedValue<'a>],
        index: usize,
    },
    Object {
        entries: &'b [SortedEntry<'a>],
        index: usize,
    },
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
            SortedValue::Array(items) => {
                if items.is_empty() {
                    out.extend_slice(b"[]")?;
                } else {
                    out.push_byte(b'[')?;
                    let child_depth = stack.len() + 1;
                    if !minify {
                        out.push_byte(b'\n')?;
                        out.push_indent(indent_table, child_depth)?;
                    }
                    stack.push(EmitFrame::Array { items, index: 0 });
                    current = &items[0];
                    continue 'descend;
                }
            }
            SortedValue::Object(entries) => {
                if entries.is_empty() {
                    out.extend_slice(b"{}")?;
                } else {
                    out.push_byte(b'{')?;
                    let child_depth = stack.len() + 1;
                    if !minify {
                        out.push_byte(b'\n')?;
                        out.push_indent(indent_table, child_depth)?;
                    }
                    let first = &entries[0];
                    out.extend_slice(first.raw_key)?;
                    out.push_byte(b':')?;
                    if !minify {
                        out.push_byte(b' ')?;
                    }
                    stack.push(EmitFrame::Object { entries, index: 0 });
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
                EmitFrame::Array { items, index } => {
                    *index += 1;
                    if *index < items.len() {
                        let next_item = &items[*index];
                        out.push_byte(b',')?;
                        if !minify {
                            out.push_byte(b'\n')?;
                            out.push_indent(indent_table, depth)?;
                        }
                        current = next_item;
                        continue 'descend;
                    } else {
                        stack.pop();
                        if !minify {
                            out.push_byte(b'\n')?;
                            out.push_indent(indent_table, stack.len())?;
                        }
                        out.push_byte(b']')?;
                    }
                }
                EmitFrame::Object { entries, index } => {
                    *index += 1;
                    if *index < entries.len() {
                        let next_entry = &entries[*index];
                        out.push_byte(b',')?;
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

/// Decodes a validated JSON string literal (`"..."`) into a `Cow<str>` for lexicographical sorting
/// and duplicate key detection.
fn decode_json_key_for_sort(raw: &[u8]) -> Cow<'_, str> {
    let inner = &raw[1..raw.len() - 1];
    if !inner.contains(&b'\\') {
        if let Ok(s) = std::str::from_utf8(inner) {
            return Cow::Borrowed(s);
        }
    }

    let mut out = String::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        if inner[i] == b'\\' {
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
                        let combined = 0x10000
                            + (((code as u32 - 0xD800) << 10) | (low as u32 - 0xDC00));
                        if let Some(ch) = char::from_u32(combined) {
                            out.push(ch);
                        }
                    } else if let Some(ch) = char::from_u32(code as u32) {
                        out.push(ch);
                    }
                }
                _ => i += 1,
            }
        } else {
            let rest = &inner[i..];
            let len = validate_utf8_char(rest).unwrap_or(1);
            if let Ok(s) = std::str::from_utf8(&rest[..len]) {
                out.push_str(s);
            }
            i += len;
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
fn is_ident_continue(b: u8) -> bool {
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
        let expected = "\
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
        assert_eq!(fmt_default(input).unwrap(), expected);
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
            indent: 2,
            sort_keys: false,
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
            minify: false,
            indent: 4,
            sort_keys: false,
        };
        let out_4 = String::from_utf8(format_json(input.as_bytes(), &opts_4).unwrap()).unwrap();
        let expected_4 = "{\n    \"a\": {\n        \"b\": [\n            1,\n            2\n        ]\n    }\n}\n";
        assert_eq!(out_4, expected_4);

        let opts_tab = FormatOptions {
            minify: false,
            indent: 0,
            sort_keys: false,
        };
        let out_tab = String::from_utf8(format_json(input.as_bytes(), &opts_tab).unwrap()).unwrap();
        let expected_tab = "{\n\t\"a\": {\n\t\t\"b\": [\n\t\t\t1,\n\t\t\t2\n\t\t]\n\t}\n}\n";
        assert_eq!(out_tab, expected_tab);
    }

    #[test]
    fn test_sort_keys_recursive() {
        let input = r#"{"z": 1, "a": {"d": 4, "c": 3}, "m": [{"y": 2, "x": 1}]}"#;
        let opts = FormatOptions {
            minify: false,
            indent: 2,
            sort_keys: true,
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
            minify: false,
            indent: 64,
            sort_keys: false,
        };
        let err = format_json_with_limit(nested.as_bytes(), &opts, 4096).unwrap_err();
        assert!(err.message.contains("exceeds maximum allowed buffer size"));

        let opts_sorted = FormatOptions {
            minify: false,
            indent: 64,
            sort_keys: true,
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
            minify: false,
            indent: 2,
            sort_keys: true,
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
                    indent: 2,
                    sort_keys: true,
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
            indent: 2,
            sort_keys: true,
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
}
