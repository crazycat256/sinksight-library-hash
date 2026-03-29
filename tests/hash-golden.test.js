// Run with UPDATE_GOLDEN=1 to regenerate golden-hashes.json after an intentional algorithm change.

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { extractHashes } from "../pkg/sinksight_library_hash.js";
import { fetchLib, fetchUrl } from "./cdn.js";

const GOLDEN_PATH = join(import.meta.dirname, "golden-hashes.json");
const UPDATE = process.env.UPDATE_GOLDEN === "1";

const LIBRARIES = [
  {
    name: "jQuery 3.7.1",
    fetch: () => fetchLib("jquery", "3.7.1", "jquery.js", "sha512-+k1pnlgt4F1H8L7t3z95o3/KO+o78INEcXTbnoJQ/F2VqDVhWoaiVml/OEHv9HsVgxUaVW+IbiZPUJQfF/YxZw=="),
  },
  {
    name: "Lodash 4.17.21",
    fetch: () => fetchLib("lodash.js", "4.17.21", "lodash.js", "sha512-2iwCHjuj+PmdCyvb88rMOch0UcKQxVHi/gsAml1fN3eg82IDaO/cdzzeXX4iF2VzIIes7pODE1/G0ts3QBwslA=="),
  },
  {
    name: "Moment.js 2.30.1",
    fetch: () => fetchLib("moment.js", "2.30.1", "moment.js", "sha512-3CuraBvy05nIgcoXjVN33mACRyI89ydVHg7y/HMN9wcTVbHeur0SeBzweSd/rxySapO7Tmfu68+JlKkLTnDFNg=="),
  },
  {
    name: "alpine.min.js",
    fetch: () => fetchUrl("https://unpkg.com/alpinejs@3.13.5/dist/cdn.min.js", "sha256-ygV4Me+b49juR+FAeAif0jgdx4ILS7f724WkkPW49ow="),
  },
  {
    name: "angular.min.js",
    fetch: () => fetchUrl("https://unpkg.com/angular@1.8.3/angular.min.js", "sha256-OW3BoD1swC6cUagCRuDbU8XI35vQcofjtRvOSinas1U="),
  },
  {
    name: "bootstrap.bundle.min.js",
    fetch: () => fetchUrl("https://unpkg.com/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js", "sha256-CDOy6cOibCWEdsRiZuaHf8dSGGJRYuBGC+mjoJimHGw="),
  },
  {
    name: "d3.min.js",
    fetch: () => fetchUrl("https://unpkg.com/d3@7.9.0/dist/d3.min.js", "sha256-8glLv2FBs1lyLE/kVOtsSw8OQswQzHr5IfwVj864ZTk="),
  },
  {
    name: "htmx.min.js",
    fetch: () => fetchUrl("https://unpkg.com/htmx.org@1.9.10/dist/htmx.min.js", "sha256-s73PXHQYl6U2SLEgf/8EaaDWGQFCm6H26I+Y69hOZp4="),
  },
  {
    name: "jquery.min.js",
    fetch: () => fetchUrl("https://unpkg.com/jquery@3.7.1/dist/jquery.min.js", "sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo="),
  },
  {
    name: "lodash.min.js",
    fetch: () => fetchUrl("https://unpkg.com/lodash@4.17.21/lodash.min.js", "sha256-qXBd/EfAdjOA2FGrGAG+b3YBn2tn5A6bhz+LSgYD96k="),
  },
  {
    name: "pdf.min.js",
    fetch: () => fetchUrl("https://unpkg.com/pdfjs-dist@5.4.624/build/pdf.min.mjs", "sha256-XxF3F1eQ3PW1sKiIIF8TK+ppDDUZTkYTCZ1CGhZCPQs="),
  },
  {
    name: "react-dom.production.min.js",
    fetch: () => fetchUrl("https://unpkg.com/react-dom@18.2.0/umd/react-dom.production.min.js", "sha256-IXWO0ITNDjfnNXIu5POVfqlgYoop36bDzhodR6LW5Pc="),
  },
  {
    name: "three.core.js",
    fetch: () => fetchUrl("https://unpkg.com/three@0.183.1/build/three.core.js", "sha256-an/INDeBhTTV4wzoyODOdiMMoiRURuokdEuz2IxDZYM="),
  },
  {
    name: "typescript.js",
    fetch: () => fetchUrl("https://unpkg.com/typescript@5.9.3/lib/typescript.js", "sha256-OukCySzETazhdcDmnhOksImfaYPGEh12uauN1XlednU="),
  },
  {
    name: "vue.global.js",
    fetch: () => fetchUrl("https://unpkg.com/vue@3.4.21/dist/vue.global.js", "sha256-JpdI604wSHrHzZo7nygsRBWsr0GzFzmtj91vqeY0M80="),
  },
];

function loadGolden() {
  if (existsSync(GOLDEN_PATH)) {
    return JSON.parse(readFileSync(GOLDEN_PATH, "utf-8"));
  }
  return {};
}

function saveGolden(golden) {
  writeFileSync(GOLDEN_PATH, JSON.stringify(golden, null, 2) + "\n");
}

describe("golden hash stability on real-world libraries", () => {
  const golden = loadGolden();

  for (const lib of LIBRARIES) {
    it(`${lib.name}: hash is stable across runs`, async () => {
      const src = await lib.fetch();
      const { fileHash } = extractHashes(src);

      if (UPDATE || !(lib.name in golden)) {
        golden[lib.name] = fileHash;
        saveGolden(golden);
        return;
      }

      expect(fileHash).toBe(golden[lib.name]);
    });
  }
});
