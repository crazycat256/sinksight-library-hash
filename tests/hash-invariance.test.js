import { describe, expect, it } from "vitest";
import { extractHashes } from "../pkg/sinksight_library_hash.js";

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

describe("object key ordering", () => {
  it("reordering object keys does not change the file hash", () => {
    const a = extractHashes("var o = {a: 1, b: 2};");
    const b = extractHashes("var o = {b: 2, a: 1};");
    expect(a.fileHash).toBe(b.fileHash);
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
