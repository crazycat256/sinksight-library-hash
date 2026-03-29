import { describe, expect, it } from "vitest";
import { extractHashes } from "../pkg/sinksight_library_hash.js";

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
