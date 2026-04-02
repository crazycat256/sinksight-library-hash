use serde::{Deserialize, Serialize};

/// Input for [`crate::build_db`]. Each entry is a raw 32-byte SHA-256 hash
/// plus the library / version indices that produced it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildDbInput {
    pub min_statements: u8,
    pub libs: Vec<BuildDbLib>,
    pub file_hashes: Vec<BuildDbHashEntry>,
    pub func_hashes: Vec<BuildDbHashEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BuildDbLib {
    pub name: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildDbHashEntry {
    /// Raw 32-byte SHA-256 hash (without the `slh1-` prefix).
    pub hash: Vec<u8>,
    pub lib_id: u16,
    pub version_index: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractResult {
    pub file_hash: String,
    pub functions: Vec<FunctionHashInfo>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionHashInfo {
    /// `slh1-<hex>`
    pub hash: String,
    pub name: Option<String>,
    /// 1-indexed
    pub start_line: u32,
    /// 0-indexed
    pub start_column: u32,
    /// 1-indexed
    pub end_line: u32,
    /// 0-indexed
    pub end_column: u32,
    pub stmt_count: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    /// All libs whose file hash matches. Empty if no whole-file match.
    pub whole_file: Vec<LibraryMatch>,
    /// Pruned: parent match => children skipped.
    pub functions: Vec<FunctionMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LibraryMatch {
    pub lib: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionMatch {
    pub libs: Vec<LibraryMatch>,
    pub function_name: Option<String>,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}
