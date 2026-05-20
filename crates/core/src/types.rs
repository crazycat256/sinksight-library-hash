use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LibInfo {
    pub name: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractResult {
    pub file_hash: String,
    pub functions: Vec<FunctionHashInfo>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetailedExtractResult {
    pub file_hash: String,
    pub file_canonical: String,
    pub functions: Vec<DetailedFunctionHashInfo>,
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
pub struct DetailedFunctionHashInfo {
    /// `slh1-<hex>`
    pub hash: String,
    pub canonical: String,
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

/// A resolved hash record extracted from a loaded database.
#[derive(Debug, Clone, Serialize)]
pub struct DbHashRecord {
    /// `slh1-<hex>`
    pub hash: String,
    pub lib: String,
    pub version: String,
}

/// All data extracted from a loaded `.slhdb` database.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DbContents {
    pub libs: Vec<LibInfo>,
    pub file_hashes: Vec<DbHashRecord>,
    pub func_hashes: Vec<DbHashRecord>,
}
