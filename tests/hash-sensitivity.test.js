import { describe, expect, it } from "vitest";
import { extractHashes } from "../pkg/sinksight_library_hash.js";
import { fetchLib } from "./cdn.js";

function replaceFirst(source, search, replacement) {
  const index = source.indexOf(search);
  if (index === -1) {
    throw new Error(
      `Mutation target not found in source: ${JSON.stringify(search)}`
    );
  }
  return source.slice(0, index) + replacement + source.slice(index + search.length);
}

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

const REAL_WORLD_MUTATIONS = [
  {
    lib: { cdnjsLib: "jquery", version: "3.7.1", file: "jquery.js", sri: "sha512-+k1pnlgt4F1H8L7t3z95o3/KO+o78INEcXTbnoJQ/F2VqDVhWoaiVml/OEHv9HsVgxUaVW+IbiZPUJQfF/YxZw==" },
    label: "jQuery 3.7.1: version string changed",
    apply: (src) => replaceFirst(src, '"3.7.1"', '"3.7.1-x"'),
  },
  {
    lib: { cdnjsLib: "jquery", version: "3.7.1", file: "jquery.js", sri: "sha512-+k1pnlgt4F1H8L7t3z95o3/KO+o78INEcXTbnoJQ/F2VqDVhWoaiVml/OEHv9HsVgxUaVW+IbiZPUJQfF/YxZw==" },
    label: "jQuery 3.7.1: identifier string changed",
    apply: (src) => replaceFirst(src, '"jQuery"', '"jQuer_"'),
  },
  {
    lib: { cdnjsLib: "jquery", version: "3.7.1", file: "jquery.js", sri: "sha512-+k1pnlgt4F1H8L7t3z95o3/KO+o78INEcXTbnoJQ/F2VqDVhWoaiVml/OEHv9HsVgxUaVW+IbiZPUJQfF/YxZw==" },
    label: "jQuery 3.7.1: statement appended",
    apply: (src) => src + "\nvoid 0;",
  },
  {
    lib: { cdnjsLib: "lodash.js", version: "4.17.21", file: "lodash.js", sri: "sha512-2iwCHjuj+PmdCyvb88rMOch0UcKQxVHi/gsAml1fN3eg82IDaO/cdzzeXX4iF2VzIIes7pODE1/G0ts3QBwslA==" },
    label: "Lodash 4.17.21: version string changed",
    apply: (src) => replaceFirst(src, "'4.17.21'", "'4.17.21-x'"),
  },
  {
    lib: { cdnjsLib: "lodash.js", version: "4.17.21", file: "lodash.js", sri: "sha512-2iwCHjuj+PmdCyvb88rMOch0UcKQxVHi/gsAml1fN3eg82IDaO/cdzzeXX4iF2VzIIes7pODE1/G0ts3QBwslA==" },
    label: "Lodash 4.17.21: internal placeholder string changed",
    apply: (src) => replaceFirst(src, "'__lodash_placeholder__'", "'__loda_h_placeholder__'"),
  },
  {
    lib: { cdnjsLib: "lodash.js", version: "4.17.21", file: "lodash.js", sri: "sha512-2iwCHjuj+PmdCyvb88rMOch0UcKQxVHi/gsAml1fN3eg82IDaO/cdzzeXX4iF2VzIIes7pODE1/G0ts3QBwslA==" },
    label: "Lodash 4.17.21: statement appended",
    apply: (src) => src + "\nvoid 0;",
  },
  {
    lib: { cdnjsLib: "moment.js", version: "2.30.1", file: "moment.js", sri: "sha512-3CuraBvy05nIgcoXjVN33mACRyI89ydVHg7y/HMN9wcTVbHeur0SeBzweSd/rxySapO7Tmfu68+JlKkLTnDFNg==" },
    label: "Moment.js 2.30.1: version string changed",
    apply: (src) => replaceFirst(src, "'2.30.1'", "'2.30.1-x'"),
  },
  {
    lib: { cdnjsLib: "moment.js", version: "2.30.1", file: "moment.js", sri: "sha512-3CuraBvy05nIgcoXjVN33mACRyI89ydVHg7y/HMN9wcTVbHeur0SeBzweSd/rxySapO7Tmfu68+JlKkLTnDFNg==" },
    label: "Moment.js 2.30.1: identifier string changed",
    apply: (src) => replaceFirst(src, "'moment'", "'momen_'"),
  },
  {
    lib: { cdnjsLib: "moment.js", version: "2.30.1", file: "moment.js", sri: "sha512-3CuraBvy05nIgcoXjVN33mACRyI89ydVHg7y/HMN9wcTVbHeur0SeBzweSd/rxySapO7Tmfu68+JlKkLTnDFNg==" },
    label: "Moment.js 2.30.1: statement appended",
    apply: (src) => src + "\nvoid 0;",
  },
];

describe("hash sensitivity on real-world libraries", () => {
  for (const { lib, label, apply } of REAL_WORLD_MUTATIONS) {
    it(label, async () => {
      const src = await fetchLib(lib.cdnjsLib, lib.version, lib.file, lib.sri);
      const { fileHash: original } = extractHashes(src);
      const { fileHash: changed } = extractHashes(apply(src));
      expect(changed).not.toBe(original);
    });
  }
});
