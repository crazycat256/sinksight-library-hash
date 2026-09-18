# SinkSight Library Hash (`slh1`) - Technical Specification

## 1. Status and scope

This document specifies version 1 of the SinkSight Library Hash algorithm,
identified by the `slh1` prefix, together with its extraction API, matching
rules, and binary database format.

The project fingerprints executable JavaScript from its abstract syntax tree
(AST). It serves two purposes:

1. **Extraction:** compute a hash for a complete script and for every eligible
   function or class contained in it.
2. **Detection:** compare those hashes with a prebuilt database to identify
   known libraries in complete files or bundles.

The Rust workspace exposes three implementations of the same core behavior:

- `core`: the Rust implementation and the `slh` command-line program;
- `wasm`: WebAssembly bindings generated with `wasm-bindgen`;
- `napi`: native Node.js bindings generated with `napi-rs`.

The Rust crate and Node.js packages are currently distributed from GitHub, not
from crates.io or npm. A prebuilt WASM package is maintained on the
`wasm-package` branch.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** in this document
are normative requirements.

## 2. Design goals

SinkSight analyzes browser JavaScript for DOM XSS. Well-known libraries can
produce noisy findings, so known library code must be identified without
excluding unrelated application code.

An `slh1` hash is designed to be invariant under:

- whitespace, line-ending, and comment changes;
- consistent renaming of local bindings and function parameters;
- renaming of a function or class root;
- conversion between equivalent function declaration, function expression,
  and block-bodied arrow-function roots;
- reordering of statically named object-literal properties.

It is intentionally sensitive to structural changes, operators, literal
values, property names, control flow, and statement additions or removals.
The input language is executable browser JavaScript. JSX and TypeScript are
outside the scope of `slh1`.

## 3. Hash representation

The external representation is:

```text
slh1-<sha256_hex>
```

`<sha256_hex>` is exactly 64 lowercase hexadecimal characters. The complete
string is therefore 69 characters long.

```text
slh1-a3f2b8c91d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
```

Any incompatible change to token production, traversal order, eligibility, or
normalization MUST use a new prefix such as `slh2`. Existing `slh1` databases
MUST NOT be interpreted with a different algorithm.

## 4. Parsing and semantic analysis

### 4.1 Parser

The reference implementation uses `oxc_parser` with
`SourceType::unambiguous()` and parser error recovery enabled. It accepts
modern JavaScript syntax supported by the configured oxc version, including
modules, classes, private fields, dynamic imports, object rest/spread,
optional chaining, nullish coalescing, and top-level `await`.

The parser attempts to recover from ordinary syntax errors. A parser panic is
an extraction error. Source locations use one-based lines and zero-based
columns.

### 4.2 Binding classification

Before hashing, `oxc_semantic` classifies each identifier occurrence as:

- a **local binding**, declared inside the tree being hashed; or
- a **free reference**, declared outside that tree or implicitly global.

Local bindings are numbered deterministically by declaration position within
their scope. Their declarations and references use `L<n>` tokens.

Distinct free-reference names are numbered by first occurrence during tree
traversal and use `F<n>`. Repeated occurrences of the same name reuse the same
number. Free-reference *relationships* are therefore retained, but their
spelling is normalized. Consistently replacing a sole free reference
`window` with `globalThis` can preserve a hash. Static property names are not
normalized, so replacing `console.log` with `console.warn` changes the hash.

When hashing an individual function or class, bindings declared outside that
root are free references even if they are local in the enclosing program.

## 5. Token stream

### 5.1 Traversal

The AST is visited depth-first in pre-order. Child fields are visited in a
fixed order corresponding to the relevant Babel `VISITOR_KEYS`, not Rust
struct layout. Important examples include:

```text
FunctionDeclaration:     id, params, body
FunctionExpression:      id, params, body
ArrowFunctionExpression: params, body
ClassDeclaration:        id, superClass, body
VariableDeclarator:      id, init
CallExpression:          callee, arguments
MemberExpression:        object, property
BinaryExpression:        left, right
AssignmentExpression:    left, right
IfStatement:             test, consequent, alternate
ForStatement:            init, test, update, body
ReturnStatement:         argument
BlockStatement:          body
Program:                 body
```

Changing child traversal order is an incompatible algorithm change.

### 5.2 Node and operator tokens

Each visited node emits its normalized node-type token. Operators and semantic
flags that distinguish expressions or statements also emit tokens. For
example, `+` and `-`, `&&` and `||`, and `=` and `+=` produce different
hashes. Prefix and postfix update placement is intentionally not distinguished
by `slh1`: `++x` and `x++` produce the same hash.

### 5.3 Root normalization

When a function or class is hashed as an extracted subtree, its root node type
and root name are omitted. Parameters and body remain part of the hash.

```javascript
function add(a, b) { return a + b; }
const add = function (x, y) { return x + y; };
const add = (x, y) => { return x + y; };
```

These equivalent block-bodied forms can share a function hash. This exception
does not apply to a complete-program hash.

### 5.4 Identifiers and properties

Binding identifiers and references emit an `Identifier` token followed by
their normalized `L<n>` or `F<n>` token where applicable.

Static member-property names, object keys, method names, labels, and private
identifiers retain their semantic spelling where required. In particular,
`object.first` differs from `object.second`; a computed property expression is
visited normally.

### 5.5 Literals

Literal kinds and values are encoded so different types cannot collide:

| Literal | Logical value token example |
|---|---|
| String | `S:hello` |
| Number | `N:42` |
| Boolean | `B:true` |
| Null | `NULL` |
| RegExp | pattern and flags |
| BigInt | bigint value |
| Template literal | each quasi plus visited expressions |

Tokens are separated by commas before SHA-256. Literal token contents escape
backslashes and commas, so embedded delimiters or strings resembling node
names MUST NOT collide with token boundaries.

### 5.6 Object literals

Properties of an `ObjectExpression` are sorted by a deterministic static key
before traversal. Static identifier, string, and numeric keys participate in
the sort. Computed properties and spreads use the fallback key while stable
order is preserved among equal keys. Therefore these have the same hash:

```javascript
({ a: 1, b: 2 })
({ b: 2, a: 1 })
```

### 5.7 Digest

The framed token stream is hashed with SHA-256. The lowercase digest is
prefixed with `slh1-` externally. The database stores only the raw 32-byte
digest.

## 6. Extraction

### 6.1 Eligibility

`extract_hashes`/`extractHashes` always returns a complete-program hash and
also returns every eligible nested function or class.

Eligible roots are function declarations, function expressions, block-bodied
arrow functions, class declarations, class expressions, and object methods.
Expression-bodied arrow functions are excluded.

A candidate is included only when its structural statement count is at least
`minStatements`, whose default is `3`. This count includes statements in
relevant nested control-flow structures; it is not merely the direct length
of a block. The same threshold MUST be used to build and query a database.

### 6.2 Result types

```typescript
interface FunctionHashInfo {
  hash: string;
  name: string | null;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  stmtCount: number;
}

interface ExtractResult {
  fileHash: string;
  functions: FunctionHashInfo[];
}
```

`extractHashes(script, minStatements?)` returns an error if parsing cannot
produce a usable program. It MUST NOT invent a fallback hash.

## 7. Database matching

### 7.1 Lifecycle and result

`loadDb(data)` validates and loads a database, returning an opaque unsigned
32-bit handle. `freeDb(handle)` releases it. Callers MUST NOT reuse an invalid
or freed handle.

`checkScript(handle, script)` reads `minStatements` from the database, hashes
the script, and returns:

```typescript
interface LibraryMatch {
  lib: string;
  version: string;
}

interface FunctionMatch {
  libs: LibraryMatch[];
  functionName: string | null;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

interface CheckResult {
  wholeFile: LibraryMatch[];
  functions: FunctionMatch[];
}
```

A hash can map to multiple libraries or versions. Implementations MUST return
all records sharing that hash.

### 7.2 Matching and pruning

1. Compute the complete-program hash.
2. If it matches file records, return all of them in `wholeFile` and no
   function matches.
3. Otherwise traverse eligible roots in top-down depth-first order.
4. Hash each root and query the function table.
5. If it matches, return that range and do not inspect eligible descendants.
6. If it does not match, continue into its descendants.

A matching parent therefore suppresses matching children. If a parent does
not match, matching children are returned independently. If checking cannot
parse a script, the current API returns an empty result rather than excluding
code from analysis.

## 8. Binary database format

All multibyte integers are little-endian. Strings are UTF-8. Hash tables MUST
be sorted lexicographically by their 32 raw digest bytes.

```text
HEADER (17 bytes)
  [0..3]    magic             "SLH"
  [3]       database version  u8 (currently 1)
  [4]       minStatements     u8
  [5..9]    library count     u32
  [9..13]   file-hash count   u32
  [13..17]  function count    u32

LIBRARY TABLE, repeated library count times
  library id                    u16
  name length                   u8
  name                          UTF-8 bytes
  version count                 u16
  repeated versions:
    version length              u8
    version                     UTF-8 bytes

FILE HASH TABLE, repeated file-hash count times
  digest                        [u8; 32]
  library id                    u16
  version index                 u16

FUNCTION HASH TABLE, repeated function count times
  digest                        [u8; 32]
  library id                    u16
  version index                 u16

OPTIONAL FUNCTION BLOOM FILTER
  byte length                   u32 (zero means absent)
  hash-function count           u8
  data                          byte-length bytes
```

The loader MUST reject truncated data, invalid UTF-8, unsupported database
versions, unsorted tables, invalid library/version references, inconsistent
sizes, and malformed Bloom-filter data.

Lookup uses binary search followed by a scan across adjacent equal digests to
collect every match. The optional Bloom filter covers function hashes only. A
negative result skips binary search; a positive result still requires table
confirmation.

The database and hash versions are distinct. An incompatible binary-layout
change MUST increment the database version. An incompatible hash change MUST
introduce a new hash prefix and requires complete database regeneration.

## 9. Public API surface

| Core operation | JavaScript binding | Purpose |
|---|---|---|
| `extract_hashes` | `extractHashes` | Hash a program and eligible roots |
| `load_db` | `loadDb` | Load a binary database |
| `check_script` | `checkScript` | Match a script against a database |
| `free_db` | `freeDb` | Release a database handle |
| `parse_hash_bytes` | `parseHashBytes` | Decode an external `slh1` hash |
| `list_libs` | `listLibs` | List database libraries |
| `build_db` | `buildDb` | Serialize a database |
| `extract_db_contents` | `extractDbContents` | Inspect database records |

The Rust core additionally exposes `extract_detailed_hashes`. JavaScript
bindings MAY expose diagnostics such as `extractIR` behind development
features like `debug-ir`; those diagnostics are not part of the stable hash
format.

## 10. Distribution

The prebuilt Node.js WASM package contains:

```text
package.json
LICENSE
README.md
sinksight_library_hash_bg.wasm
sinksight_library_hash.js
sinksight_library_hash.d.ts
```

It is built with:

```bash
wasm-pack build crates/wasm --target nodejs
```

GitHub Actions copies the generated files to the root of the orphan
`wasm-package` branch. Consumers can install it without Rust or Cargo:

```bash
npm install github:crazycat256/sinksight-library-hash#wasm-package
```

The native NAPI package is built locally with
`napi build --platform --release`. Neither JavaScript package is currently
published to npm.

## 11. Conformance tests

A conforming implementation SHOULD test at least these properties:

- hash syntax is `slh1-` followed by 64 lowercase hexadecimal characters;
- formatting, comments, and LF/CRLF changes preserve hashes;
- local-variable and parameter renaming preserves function hashes;
- root name and equivalent block-bodied function form preserve hashes;
- literal, operator, static property, and structural changes alter hashes;
- object-property reordering preserves hashes;
- escaped token delimiters prevent collisions;
- statement thresholds include and exclude the expected roots;
- nested functions are extracted;
- parent matches prune descendants;
- unmatched parents allow matching descendants;
- duplicate records return every library match;
- malformed databases are rejected;
- hashes remain stable against committed golden values and pinned real-world
  library fixtures.

The repository's JavaScript tests are the compatibility suite for the WASM
surface. Rust tests cover extraction, database, and matching behavior. Any
intentional golden-hash change is an algorithm change and MUST be reviewed as
a potential `slh2` transition.

## 12. Critical invariants

1. Inputs differing only in ignored formatting, comments, line endings, and
   normalized local-binding names MUST produce the same hash.
2. Structural, literal, operator, and retained property-name differences MUST
   influence the hash as specified.
3. Complete-file matches short-circuit function matching.
4. Only highest matching ranges are returned; matching descendants are
   pruned.
5. Failure to recognize a library MUST fall back to normal SinkSight analysis.
   Hashing must never cause unrecognized application code to be skipped.
6. The database stores and enforces the extraction threshold.
7. Traversal and token escaping are deterministic across supported targets.
8. Incompatible behavior requires a new `slh` version and regenerated
   databases.
