/**
 * Stability tests against real-world libraries — verify that SLH hashes are
 * invariant to mangle-only minification (variable renaming + comment stripping,
 * no structural AST rewrites).
 */

import { describe, expect, it } from "vitest";
import { minify } from "terser";
import { extractHashes } from "../pkg/sinksight_library_hash.js";
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
