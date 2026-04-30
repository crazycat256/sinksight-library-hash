# sinksight-library-hash

AST-based JavaScript library fingerprinting, available as a **Rust crate**, a **WebAssembly** module, and a **native Node.js addon** (NAPI).

Produces deterministic hashes (`slh1`) for JS files and their individual functions, designed to identify known libraries (jQuery, Lodash, React...) even after minification, reformatting, or variable renaming. Used by [SinkSight](https://github.com/crazycat256/sinksight) to filter false positives from DOM XSS analysis.

## Architecture

```
crates/
  core/   ← Pure Rust library (rlib) — all logic lives here
  wasm/   ← WebAssembly bindings (wasm-bindgen)  → npm: @sinksight/library-hash
  napi/   ← Native Node.js bindings (napi-rs)    → npm: @sinksight/library-hash-native
```

All three targets expose the same API surface.

---

## Rust crate

### Install

```toml
# Cargo.toml
[dependencies]
sinksight-library-hash = { git = "https://github.com/crazycat256/sinksight-library-hash" }
```

### API

#### `extract_hashes(script, min_statements) -> Result<ExtractResult, String>`

Parse a JavaScript source and return hashes for the whole file and each eligible function body.

```rust
use sinksight_library_hash::extract_hashes;

let result = extract_hashes(source, None).unwrap();
// result.file_hash  -> "slh1-a3f2b8c9..."
// result.functions  -> Vec<FunctionHashInfo>
for f in &result.functions {
    println!("{:?} -> {}", f.name, f.hash);
}
```

#### `load_db(data) -> Result<u32, String>`

Load a pre-built binary database of known library hashes. Returns an opaque handle.

#### `check_script(handle, script) -> CheckResult`

Match a script against the loaded database.

```rust
use sinksight_library_hash::{load_db, check_script, free_db};

let handle = load_db(&db_bytes).unwrap();
let result = check_script(handle, source);
// result.whole_file  -> Vec<LibraryMatch>  (non-empty on file-level match)
// result.functions   -> Vec<FunctionMatch>
for m in &result.whole_file {
    println!("{} {}", m.lib, m.version);
}
free_db(handle);
```

#### `free_db(handle)`

Release the memory held by a loaded database handle.

#### `parse_hash_bytes(hash) -> Option<[u8; 32]>`

Parse an `slh1-<hex>` hash string into its raw 32-byte digest. Returns `None` if malformed.

#### `list_libs(handle) -> Option<Vec<LibInfo>>`

Return the list of libraries and their versions from a loaded database.

#### `build_db(min_statements, libs, file_hashes, func_hashes) -> Vec<u8>`

Build a binary `.slhdb` database from raw hash data.

### Types

```rust
pub struct ExtractResult {
    pub file_hash: String,          // "slh1-<64 hex chars>"
    pub functions: Vec<FunctionHashInfo>,
}

pub struct FunctionHashInfo {
    pub hash: String,
    pub name: Option<String>,
    pub start_line: u32,   // 1-indexed
    pub start_column: u32, // 0-indexed
    pub end_line: u32,
    pub end_column: u32,
    pub stmt_count: u32,
}

pub struct CheckResult {
    pub whole_file: Vec<LibraryMatch>,
    pub functions: Vec<FunctionMatch>,
}

pub struct LibraryMatch {
    pub lib: String,
    pub version: String,
}

pub struct FunctionMatch {
    pub libs: Vec<LibraryMatch>,
    pub function_name: Option<String>,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}
```

### Building from source

Requires [Rust](https://rustup.rs/).

```bash
cargo build --release
cargo test
```

### CLI

The Rust crate also builds a small CLI binary named `slh` for local debugging.

```bash
cargo run -p sinksight-library-hash --bin slh -- check \
    --db path/to/library.slhdb \
    --script path/to/file.js
```

It prints JSON with:

It prints one match per line:

- `whole-file<TAB><lib>@<version>`
- `function<TAB><startLine>:<startColumn>-<endLine>:<endColumn><TAB><functionName><TAB><lib>@<version>`

Positional form is also supported:

```bash
cargo run -p sinksight-library-hash --bin slh -- check path/to/library.slhdb path/to/file.js
```

---

## JavaScript — WebAssembly (`@sinksight/library-hash`)

The WASM build is optimized for size (`opt-level = "z"`). Best suited for browser extensions and environments where a native addon cannot be used.

### Install

```bash
npm install @sinksight/library-hash
```

### API

All functions listed in the Rust section are available with camelCase naming:

| Rust | JS |
|------|----|
| `extract_hashes` | `extractHashes(script, minStatements?)` |
| `load_db` | `loadDb(data)` |
| `check_script` | `checkScript(handle, script)` |
| `free_db` | `freeDb(handle)` |
| `parse_hash_bytes` | `parseHashBytes(hash)` |
| `list_libs` | `listLibs(handle)` |
| `build_db` | `buildDb(minStatements, libs, fileHashes, funcHashes)` |

```js
import { extractHashes, loadDb, checkScript, freeDb } from "@sinksight/library-hash";

const result = extractHashes(source);
// { fileHash: "slh1-a3f2b8c9...", functions: [{ hash, name, startLine, ... }] }

const handle = loadDb(dbBytes);
const check = checkScript(handle, source);
// { wholeFile: [{ lib, version }], functions: [{ libs, functionName, startLine, ... }] }
freeDb(handle);
```

### Building from source

Requires [Rust](https://rustup.rs/) and [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/).

```bash
npm run build
# equivalent to: wasm-pack build crates/wasm --target nodejs
```

---

## JavaScript — Native addon (`@sinksight/library-hash-native`)

The NAPI build is optimized for speed (`opt-level = 3`). Used by [sinksight-library-db](https://github.com/crazycat256/sinksight-library-db) for batch hashing. Provides full TypeScript types out of the box.

### Install

```bash
# From the repo (not published to npm)
npm install --save file:path/to/sinksight-library-hash/crates/napi
```

### API

Same functions as the WASM target, with the same signatures. Strongly typed — no `any` returns.

```js
import { extractHashes, loadDb, checkScript, freeDb } from "@sinksight/library-hash-native";
// Same usage as the WASM package
```

### Building from source

Requires [Rust](https://rustup.rs/) and [@napi-rs/cli](https://napi.rs/).

```bash
cd crates/napi
npm ci && npm run build
```

---

## Testing

```bash
# Rust unit tests
cargo test

# JS integration tests (fast — synthetic + minification stability on jQuery/Lodash/Moment)
npm run test:fast

# Full test suite (includes golden hash checks on 15 real-world libraries)
npm test
```

---

## Hash format

```txt
slh1-<64 hex chars>
```

`slh1` is the algorithm version. The hex portion is a SHA-256 digest of the normalized AST token stream.

## Hash invariance

The hash is designed to be **stable** across cosmetic changes and **sensitive** to semantic changes.

Rows marked *(function hash)* apply only to the per-function hashes in `functions[]`, not to `fileHash`.

| `Input 1` | `Input 2` | `Same slh` |
| --- | --- | :---: |
| `if(x){y()}` | prettified with newlines and indentation | ✅ |
| `// comment` prepended | comment stripped | ✅ |
| CRLF line endings | LF line endings | ✅ |
| `function f(url, opts)` | `function f(a, b)` | ✅ |
| `function foo(a, b) { ... }` | `function bar(a, b) { ... }` *(function hash)* | ✅ |
| `function f(a) { ... }` | `var f = function(a) { ... }` *(function hash)* | ✅ |
| `function f(a) { ... }` | `var f = (a) => { ... }` *(function hash)* | ✅ |
| `outer: while(...)` | `n: while(...)` | ✅ |
| `!0` | `true` | ✅ |
| `!1` | `false` | ✅ |
| `void 0` | `undefined` | ✅ |
| `return void 0` | `return` | ✅ |
| `{"catch": fn}` | `{catch: fn}` | ✅ |
| `obj["foo"]` | `obj.foo` | ✅ |
| `` `hello` `` | `"hello"` | ✅ |
| `(x) => { return x + 1; }` | `(x) => x + 1` | ✅ |
| `{a: 1, b: 2}` | `{b: 2, a: 1}` | ✅ |
| `;var x = 1` | `var x = 1` | ✅ |
| `"click"` | `"mousedown"` | ❌ |
| `42` | `43` | ❌ |
| `document.getElementById` | `document.querySelector` | ❌ |
| `if (x > 0)` | `if (x >= 0)` | ❌ |
| `function f() { ... }` | `function f() { console.log(); ... }` | ❌ |
| `if (x) f()` | `x && f()` | ❌ |
| `if (x) a; else b` | `x ? a : b` | ❌ |

## License

[GPL-3.0](LICENSE)
