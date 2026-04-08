import { describe, expect, it } from "vitest";
import { extractHashes } from "../crates/wasm/pkg/sinksight_library_hash.js";

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
