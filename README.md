# sinksight-library-hash

AST-based JavaScript library fingerprinting, available as a **Rust crate** and compiled to **WebAssembly** for JavaScript/Node.js.

Produces deterministic hashes (`slh1`) for JS files and their individual functions, designed to identify known libraries (jQuery, Lodash, React...) even after minification, reformatting, or variable renaming. Used by [SinkSight](https://github.com/crazycat256/sinksight) to filter false positives from DOM XSS analysis.

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

---

## JavaScript / WebAssembly (npm)

### Install

```bash
npm install @sinksight/library-hash
```

### API

#### `extractHashes(script, minStatements?)`

Parse a JavaScript source and return hashes for the whole file and each eligible function.

```js
import { extractHashes } from "@sinksight/library-hash";

const result = extractHashes(source);
// {
//   fileHash: "slh1-a3f2b8c9...",
//   functions: [
//     { hash: "slh1-...", name: "ajax", startLine: 10, startColumn: 0, endLine: 25, endColumn: 1, stmtCount: 8 },
//     ...
//   ]
// }
```

#### `loadDb(data) -> handle`

Load a pre-built binary database of known library hashes. Returns an opaque handle.

#### `checkScript(handle, script) -> CheckResult`

Match a script against the loaded database. Returns whole-file and per-function matches.

```js
const handle = loadDb(dbBytes);
const result = checkScript(handle, source);
// {
//   wholeFile: { lib: "jquery", version: "3.7.1" } | null,
//   functions: [
//     { lib: "lodash", version: "4.17.21", functionName: "chunk", startLine: 1, ... },
//   ]
// }
freeDb(handle);
```

#### `freeDb(handle)`

Release the memory held by a loaded database.

### Building the WASM package from source

Requires [Rust](https://rustup.rs/) and [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/).

```bash
npm run build
# equivalent to: wasm-pack build --target nodejs --out-dir pkg
```

### Testing

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
