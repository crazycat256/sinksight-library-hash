/**
 * Hash stability tests — verify that SLH hashes are invariant to
 * whitespace removal, comment stripping, and variable renaming.
 *
 * For each library we download the original source from cdnjs (SRI-verified),
 * then minify it locally with Terser using only safe transforms:
 *   - compress: false  -> no structural AST rewrites
 *   - mangle: true     -> local variable renaming
 *   - comments: false  -> strip comments
 */

import { describe, expect, it } from "vitest";
import { minify } from "terser";
import { extractHashes } from "../crates/wasm/pkg/sinksight_library_hash.js";
import { fetchLib } from "./cdn.js";

const LIBRARIES = [
  {
    name: "jQuery",
    cdnjsLib: "jquery",
    version: "3.7.1",
    file: "jquery.js",
    sri: "sha512-+k1pnlgt4F1H8L7t3z95o3/KO+o78INEcXTbnoJQ/F2VqDVhWoaiVml/OEHv9HsVgxUaVW+IbiZPUJQfF/YxZw==",
  },
  {
    name: "Lodash",
    cdnjsLib: "lodash.js",
    version: "4.17.21",
    file: "lodash.js",
    sri: "sha512-2iwCHjuj+PmdCyvb88rMOch0UcKQxVHi/gsAml1fN3eg82IDaO/cdzzeXX4iF2VzIIes7pODE1/G0ts3QBwslA==",
  },
  {
    name: "Moment.js",
    cdnjsLib: "moment.js",
    version: "2.30.1",
    file: "moment.js",
    sri: "sha512-3CuraBvy05nIgcoXjVN33mACRyI89ydVHg7y/HMN9wcTVbHeur0SeBzweSd/rxySapO7Tmfu68+JlKkLTnDFNg==",
  },
];

async function minifyMangleOnly(source) {
  const result = await minify(source, {
    compress: false,
    mangle: true,
    format: { comments: false },
  });
  if (result.error) throw result.error;
  return result.code;
}

describe("hash format", () => {
  it("file hash starts with 'slh1-'", () => {
    const result = extractHashes("var x = 1;");
    expect(result.fileHash).toMatch(/^slh1-/);
  });

  it("file hash has correct length (slh1- + 64 hex chars)", () => {
    const result = extractHashes("var x = 1;");
    expect(result.fileHash).toHaveLength(4 + 1 + 64);
  });
});

describe("whitespace and comment invariance", () => {
  it("extra whitespace does not change the file hash", () => {
    const a = extractHashes("var x = 1;\nvar y = 2;");
    const b = extractHashes("var   x   =   1  ;\n\nvar   y   =   2  ;");
    expect(a.fileHash).toBe(b.fileHash);
  });

  it("comments do not change the file hash", () => {
    const a = extractHashes("var x = 1;");
    const b = extractHashes("/* comment */ var x = 1; // inline");
    expect(a.fileHash).toBe(b.fileHash);
  });

  it("CRLF vs LF does not change the file hash", () => {
    const a = extractHashes("var x = 1;\nvar y = 2;");
    const b = extractHashes("var x = 1;\r\nvar y = 2;");
    expect(a.fileHash).toBe(b.fileHash);
  });
});

describe("variable renaming invariance", () => {
  it("renaming parameters and locals does not change the function hash", () => {
    const a = extractHashes("function foo(url, options) { var xhr = 1; return xhr; }", 1);
    const b = extractHashes("function foo(e, t) { var n = 1; return n; }", 1);
    expect(a.functions).toHaveLength(1);
    expect(b.functions).toHaveLength(1);
    expect(a.functions[0].hash).toBe(b.functions[0].hash);
  });

  it("renaming the function expression variable does not change the function hash", () => {
    const a = extractHashes("var foo = function(a, b) { var c = a + b; return c; };", 1);
    const b = extractHashes("var bar = function(x, y) { var z = x + y; return z; };", 1);
    expect(a.functions).toHaveLength(1);
    expect(b.functions).toHaveLength(1);
    expect(a.functions[0].hash).toBe(b.functions[0].hash);
  });
});

describe("function hash invariance — name and type", () => {
  it("renaming a FunctionDeclaration id does not change the function hash", () => {
    const a = extractHashes("function foo(x, y) { var z = x + y; return z; }", 1);
    const b = extractHashes("function bar(x, y) { var z = x + y; return z; }", 1);
    expect(a.functions).toHaveLength(1);
    expect(b.functions).toHaveLength(1);
    expect(a.functions[0].hash).toBe(b.functions[0].hash);
  });

  it("FunctionDeclaration and FunctionExpression with same body produce same function hash", () => {
    const a = extractHashes("function foo(x, y) { var z = x + y; return z; }", 1);
    const b = extractHashes("var foo = function(x, y) { var z = x + y; return z; };", 1);
    expect(a.functions).toHaveLength(1);
    expect(b.functions).toHaveLength(1);
    expect(a.functions[0].hash).toBe(b.functions[0].hash);
  });

  it("FunctionDeclaration and ArrowFunctionExpression with same body produce same function hash", () => {
    const a = extractHashes("function foo(x, y) { var z = x + y; return z; }", 1);
    const b = extractHashes("var foo = (x, y) => { var z = x + y; return z; };", 1);
    expect(a.functions).toHaveLength(1);
    expect(b.functions).toHaveLength(1);
    expect(a.functions[0].hash).toBe(b.functions[0].hash);
  });
});

describe("hash sensitivity to changes", () => {
  it("changing a free reference changes the file hash", () => {
    const a = extractHashes("console.log('hello');");
    const b = extractHashes("console.warn('hello');");
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("changing a member property changes the file hash", () => {
    const a = extractHashes("obj.foo;");
    const b = extractHashes("obj.bar;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("changing a string literal changes the file hash", () => {
    const a = extractHashes("var x = 'hello';");
    const b = extractHashes("var x = 'world';");
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("adding statements changes the file hash", () => {
    const a = extractHashes("var x = 1;");
    const b = extractHashes("var x = 1; var y = 2;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });
});

describe("object key ordering", () => {
  it("reordering object keys does not change the file hash", () => {
    const a = extractHashes("var o = {a: 1, b: 2};");
    const b = extractHashes("var o = {b: 2, a: 1};");
    expect(a.fileHash).toBe(b.fileHash);
  });
});

describe("min statements threshold", () => {
  it("function below threshold is excluded from functions[]", () => {
    const result = extractHashes("function foo() { var a = 1; return a; }", 3);
    expect(result.functions).toHaveLength(0);
  });

  it("function at threshold is included in functions[]", () => {
    const result = extractHashes("function foo() { var a = 1; return a; }", 2);
    expect(result.functions).toHaveLength(1);
  });

  it("arrow with expression body is excluded from functions[]", () => {
    const result = extractHashes("var f = (x) => x + 1;", 1);
    expect(result.functions).toHaveLength(0);
  });

  it("arrow with block body is included in functions[]", () => {
    const result = extractHashes("var f = (x) => { var y = x + 1; return y; };", 1);
    expect(result.functions.length).toBeGreaterThanOrEqual(1);
  });
});

describe("nested functions", () => {
  it("extractHashes returns both outer and inner functions", () => {
    const result = extractHashes(
      `function outer() {
        var a = 1; var b = 2; var c = 3;
        function inner() { var x = 1; var y = 2; var z = 3; return x; }
        return inner;
      }`,
      3
    );
    expect(result.functions.length).toBeGreaterThanOrEqual(2);
  });
});

describe("anti-collision", () => {
  it("comma inside a string does not collide with a statement boundary", () => {
    const a = extractHashes('var x = "BooleanLiteral,B:true";');
    const b = extractHashes('var x = "BooleanLiteral"; true;');
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("comma inside a selector string does not collide with separate calls", () => {
    const a = extractHashes('$("h1, h2, h3");');
    const b = extractHashes('$("h1"); $("h2"); $("h3");');
    expect(a.fileHash).not.toBe(b.fileHash);
  });
});

describe("operator sensitivity", () => {
  it("different binary operators produce different hashes", () => {
    const a = extractHashes("var x = a + b;");
    const b = extractHashes("var x = a - b;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("|| vs && produce different hashes", () => {
    const a = extractHashes("var x = a || b;");
    const b = extractHashes("var x = a && b;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("?? vs || produce different hashes", () => {
    const a = extractHashes("var x = a ?? b;");
    const b = extractHashes("var x = a || b;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("= vs += produce different hashes", () => {
    const a = extractHashes("x = 1;");
    const b = extractHashes("x += 1;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("different unary operators produce different hashes", () => {
    const a = extractHashes("var x = -y;");
    const b = extractHashes("var x = ~y;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("prefix and postfix ++ produce the same hash", () => {
    const a = extractHashes("++x;");
    const b = extractHashes("x++;");
    expect(a.fileHash).toBe(b.fileHash);
  });
});

describe("normalization: !0, !1, void 0", () => {
  it("!0 normalizes to true", () => {
    const a = extractHashes("var x = true;");
    const b = extractHashes("var x = !0;");
    expect(a.fileHash).toBe(b.fileHash);
  });

  it("!1 normalizes to false", () => {
    const a = extractHashes("var x = false;");
    const b = extractHashes("var x = !1;");
    expect(a.fileHash).toBe(b.fileHash);
  });

  it("void 0 normalizes to undefined", () => {
    const a = extractHashes("var x = undefined;");
    const b = extractHashes("var x = void 0;");
    expect(a.fileHash).toBe(b.fileHash);
  });

  it("typeof 0 does not normalize to true", () => {
    const a = extractHashes("var x = typeof 0;");
    const b = extractHashes("var x = true;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("!2 does not normalize to a boolean", () => {
    const a = extractHashes("var x = !2;");
    const b = extractHashes("var x = false;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("void 1 does not normalize to undefined", () => {
    const a = extractHashes("var x = void 1;");
    const b = extractHashes("var x = undefined;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });
});

describe("normalization: bare return", () => {
  it("return bare and return void 0 produce the same hash", () => {
    const a = extractHashes("function f() { return; }");
    const b = extractHashes("function f() { return void 0; }");
    expect(a.fileHash).toBe(b.fileHash);
  });

  it("return bare and return undefined produce the same hash", () => {
    const a = extractHashes("function f() { return; }");
    const b = extractHashes("function f() { return undefined; }");
    expect(a.fileHash).toBe(b.fileHash);
  });

  it("return with a value is not normalized to bare return", () => {
    const a = extractHashes("function f() { return; }");
    const b = extractHashes("function f() { return 42; }");
    expect(a.fileHash).not.toBe(b.fileHash);
  });
});

describe("normalization: object property keys", () => {
  it("quoted key and unquoted key produce the same hash", () => {
    const a = extractHashes('var o = {"catch": 1};');
    const b = extractHashes("var o = {catch: 1};");
    expect(a.fileHash).toBe(b.fileHash);
  });

  it("quoted reserved word keys and unquoted produce the same hash", () => {
    const a = extractHashes('var o = {"class": 1, "for": 2};');
    const b = extractHashes("var o = {class: 1, for: 2};");
    expect(a.fileHash).toBe(b.fileHash);
  });
});

describe("normalization: template literals", () => {
  it("template literal with no expressions equals the equivalent string literal", () => {
    const a = extractHashes("var x = `hello`;");
    const b = extractHashes('var x = "hello";');
    expect(a.fileHash).toBe(b.fileHash);
  });

  it("template literal with expressions is not collapsed to a string literal", () => {
    const a = extractHashes("var x = `hello ${y}`;");
    const b = extractHashes('var x = "hello ";');
    expect(a.fileHash).not.toBe(b.fileHash);
  });
});

describe("normalization: computed member access", () => {
  it('obj["foo"] normalizes to obj.foo', () => {
    const a = extractHashes('var x = obj["foo"];');
    const b = extractHashes("var x = obj.foo;");
    expect(a.fileHash).toBe(b.fileHash);
  });

  it("obj[0] (numeric key) does not normalize to a static property", () => {
    const a = extractHashes("var x = obj[0];");
    const b = extractHashes("var x = obj.foo;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });
});

describe("normalization: arrow functions", () => {
  it("arrow block with single return normalizes to expression body", () => {
    const a = extractHashes("var f = (x) => { return x + 1; };");
    const b = extractHashes("var f = (x) => x + 1;");
    expect(a.fileHash).toBe(b.fileHash);
  });

  it("arrow block with multiple statements does not collapse to expression body", () => {
    const a = extractHashes("var f = (x) => { var y = 1; return x + y; };");
    const b = extractHashes("var f = (x) => x + 1;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });

  it("arrow block with no return value does not collapse to expression body", () => {
    const a = extractHashes("var f = (x) => { x + 1; return; };");
    const b = extractHashes("var f = (x) => x + 1;");
    expect(a.fileHash).not.toBe(b.fileHash);
  });
});

describe("hash stability across minification", () => {
  for (const lib of LIBRARIES) {
    describe(lib.name, () => {
      it("mangle-only: same file hash", async () => {
        const src = await fetchLib(lib.cdnjsLib, lib.version, lib.file, lib.sri);
        const min = await minifyMangleOnly(src);

        const a = extractHashes(src);
        const b = extractHashes(min);

        expect(a.fileHash).toBeDefined();
        expect(b.fileHash).toBeDefined();
        expect(a.fileHash).toBe(b.fileHash);
      });
    });
  }
});
