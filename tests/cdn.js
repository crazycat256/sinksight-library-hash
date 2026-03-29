/**
 * CDN download helper with SRI verification and local caching.
 *
 * Usage:
 *   const source = await fetchLib("jquery", "3.7.1", "jquery.min.js", "sha512-...");
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const CACHE_DIR = join(import.meta.dirname, ".cache");

/**
 * Verify the SRI hash of a buffer.
 * @param {Buffer} buf
 * @param {string} expectedSri  e.g. "sha512-abc123..."
 * @returns {boolean}
 */
function verifySri(buf, expectedSri) {
  const [algo, expectedB64] = expectedSri.split("-", 2);
  const actual = createHash(algo).update(buf).digest("base64");
  return actual === expectedB64;
}

/**
 * Download a file from cdnjs, verify its SRI, cache it locally, and return
 * its contents as a UTF-8 string.
 *
 * @param {string} lib       Library name on cdnjs (e.g. "jquery")
 * @param {string} version   Version string        (e.g. "3.7.1")
 * @param {string} file      File name              (e.g. "jquery.min.js")
 * @param {string} sri       SRI hash               (e.g. "sha512-...")
 * @returns {Promise<string>}
 */
export async function fetchLib(lib, version, file, sri) {
  mkdirSync(CACHE_DIR, { recursive: true });

  const cacheKey = `${lib}@${version}--${file}`;
  const cachePath = join(CACHE_DIR, cacheKey);

  if (existsSync(cachePath)) {
    const buf = readFileSync(cachePath);
    if (!verifySri(buf, sri)) {
      throw new Error(
        `SRI mismatch for cached ${cacheKey} — cache may be corrupted`
      );
    }
    return buf.toString("utf-8");
  }

  const url = `https://cdnjs.cloudflare.com/ajax/libs/${lib}/${version}/${file}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch ${url}: ${res.status} ${res.statusText}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());

  if (!verifySri(buf, sri)) {
    throw new Error(
      `SRI mismatch for ${url} — expected ${sri}`
    );
  }

  writeFileSync(cachePath, buf);
  return buf.toString("utf-8");
}

/**
 * Download a file from an arbitrary URL, verify its SRI, cache it locally,
 * and return its contents as a UTF-8 string.
 *
 * @param {string} url  Full URL to fetch
 * @param {string} sri  SRI hash (e.g. "sha256-...")
 * @returns {Promise<string>}
 */
export async function fetchUrl(url, sri) {
  mkdirSync(CACHE_DIR, { recursive: true });

  const cacheKey = url.replace(/[^a-zA-Z0-9._-]/g, "_");
  const cachePath = join(CACHE_DIR, cacheKey);

  if (existsSync(cachePath)) {
    const buf = readFileSync(cachePath);
    if (!verifySri(buf, sri)) {
      throw new Error(`SRI mismatch for cached ${url} — cache may be corrupted`);
    }
    return buf.toString("utf-8");
  }

  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch ${url}: ${res.status} ${res.statusText}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());

  if (!verifySri(buf, sri)) {
    throw new Error(`SRI mismatch for ${url} — expected ${sri}`);
  }

  writeFileSync(cachePath, buf);
  return buf.toString("utf-8");
}
