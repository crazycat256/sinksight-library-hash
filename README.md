# @sinksight/library-hash

AST-based JavaScript library fingerprinting, compiled to WebAssembly.

Produces deterministic hashes (`slh1`) for JS files and their individual functions, designed to identify known libraries (jQuery, Lodash, React...) even after minification, reformatting, or variable renaming. Used by [SinkSight](https://github.com/crazycat256/sinksight) to filter false positives from DOM XSS analysis.

## Install

```bash
npm install @sinksight/library-hash
```

## API

### `extractHashes(script, minStatements?)`

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

### `loadDb(data) -> handle`

Load a pre-built binary database of known library hashes. Returns an opaque handle.

### `checkScript(handle, script) -> CheckResult`

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

### `freeDb(handle)`

Release the memory held by a loaded database.

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

## Building from source

Requires [Rust](https://rustup.rs/) and [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/).

```bash
wasm-pack build --target nodejs --out-dir pkg
```

## Testing

```bash
# Rust unit tests
cargo test

# JS integration tests (fast — synthetic + minification stability on jQuery/Lodash/Moment)
npm run test:fast

# Full test suite (includes golden hash checks on 15 real-world libraries)
npm test
```

## License

[GPL-3.0](LICENSE)
