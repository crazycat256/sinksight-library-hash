/* tslint:disable */
/* eslint-disable */
export interface BuildDbLib {
    name: string;
    versions: string[];
}

export interface CheckResult {
    wholeFile: LibraryMatch[];
    functions: FunctionMatch[];
}

export interface DbContents {
    libs: LibInfo[];
    fileHashes: DbHashRecord[];
    funcHashes: DbHashRecord[];
}

export interface DbHashRecord {
    hash: string;
    lib: string;
    version: string;
}

export interface ExtractResult {
    fileHash: string;
    functions: FunctionHashInfo[];
}

export interface FunctionHashInfo {
    hash: string;
    name: string | null;
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
    stmtCount: number;
}

export interface FunctionMatch {
    libs: LibraryMatch[];
    functionName: string | null;
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
}

export interface HashEntry {
    hash: string;
    libId: number;
    versionIndex: number;
}

export interface LibInfo {
    name: string;
    versions: string[];
}

export interface LibraryMatch {
    lib: string;
    version: string;
}


/**
 * Build a binary `.slhdb` database from structured hash data.
 *
 * Hash strings must be in `slh1-<hex>` format.
 */
export function buildDb(minStatements: number, libs: BuildDbLib[], fileHashes: HashEntry[], funcHashes: HashEntry[]): Uint8Array;

/**
 * Match a script against a loaded database.
 */
export function checkScript(dbHandle: number, script: string): CheckResult;

/**
 * Returns `null` if the handle is invalid.
 */
export function extractDbContents(dbHandle: number): DbContents | null;

/**
 * Parse a JavaScript source and return file hash + per-function hashes.
 */
export function extractHashes(script: string, minStatements?: number | null): ExtractResult;

/**
 * Release the memory held by a loaded database handle.
 */
export function freeDb(dbHandle: number): void;

/**
 * Return the list of libraries and their versions from a loaded database.
 * Returns `null` if the handle is invalid.
 */
export function listLibs(dbHandle: number): LibInfo[] | null;

/**
 * Load a pre-built binary `.slhdb` database into memory.
 * Returns an opaque handle.
 */
export function loadDb(data: Uint8Array): number;

/**
 * Parse an `slh1-<hex>` hash string into its raw 32-byte digest.
 * Returns `null` if the string is malformed.
 */
export function parseHashBytes(hash: string): Uint8Array | null;
