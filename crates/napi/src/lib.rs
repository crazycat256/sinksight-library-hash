use napi::bindgen_prelude::*;
use napi_derive::napi;
use sinksight_library_hash::{
    self as slh, CheckResult, DbContents, DbHashRecord, ExtractResult, FunctionHashInfo,
    FunctionMatch, LibInfo, LibraryMatch,
};

#[napi(object)]
pub struct JsExtractResult {
    pub file_hash: String,
    pub functions: Vec<JsFunctionHashInfo>,
}

#[napi(object)]
pub struct JsFunctionHashInfo {
    pub hash: String,
    pub name: Option<String>,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub stmt_count: u32,
}

impl From<ExtractResult> for JsExtractResult {
    fn from(r: ExtractResult) -> Self {
        Self {
            file_hash: r.file_hash,
            functions: r.functions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<FunctionHashInfo> for JsFunctionHashInfo {
    fn from(f: FunctionHashInfo) -> Self {
        Self {
            hash: f.hash,
            name: f.name,
            start_line: f.start_line,
            start_column: f.start_column,
            end_line: f.end_line,
            end_column: f.end_column,
            stmt_count: f.stmt_count,
        }
    }
}

/// Parse a JavaScript source and return file hash + per-function hashes.
#[napi(js_name = "extractHashes")]
pub fn extract_hashes(script: String, min_statements: Option<u32>) -> Result<JsExtractResult> {
    slh::extract_hashes(&script, min_statements)
        .map(Into::into)
        .map_err(Error::from_reason)
}

/// Parse an `slh1-<hex>` hash string into its raw 32-byte digest.
/// Returns `null` if the string is malformed.
#[napi(js_name = "parseHashBytes")]
pub fn parse_hash_bytes(hash: String) -> Option<Buffer> {
    slh::parse_hash_bytes(&hash).map(|bytes| Buffer::from(bytes.to_vec()))
}

#[napi(object)]
pub struct JsBuildDbLib {
    pub name: String,
    pub versions: Vec<String>,
}

#[napi(object)]
pub struct JsHashEntry {
    pub hash: String,
    pub lib_id: u16,
    pub version_index: u16,
}

/// Build a binary `.slhdb` database from structured hash data.
///
/// Hash strings must be in `slh1-<hex>` format. They are parsed and validated
/// internally - no manual binary packing required on the JS side.
#[napi(js_name = "buildDb")]
pub fn build_db(
    min_statements: u8,
    libs: Vec<JsBuildDbLib>,
    file_hashes: Vec<JsHashEntry>,
    func_hashes: Vec<JsHashEntry>,
) -> Result<Buffer> {
    let libs_vec: Vec<(String, Vec<String>)> =
        libs.into_iter().map(|l| (l.name, l.versions)).collect();

    let parse_entries = |entries: Vec<JsHashEntry>,
                         label: &str|
     -> std::result::Result<Vec<([u8; 32], u16, u16)>, String> {
        entries
            .into_iter()
            .map(|e| {
                let hash = slh::parse_hash_bytes(&e.hash)
                    .ok_or_else(|| format!("{label}: malformed hash: {}", e.hash))?;
                Ok((hash, e.lib_id, e.version_index))
            })
            .collect()
    };

    let file = parse_entries(file_hashes, "file_hashes").map_err(Error::from_reason)?;
    let func = parse_entries(func_hashes, "func_hashes").map_err(Error::from_reason)?;

    let db =
        slh::db::try_build_db(min_statements, &libs_vec, file, func).map_err(Error::from_reason)?;
    Ok(Buffer::from(db))
}

/// Load a pre-built binary `.slhdb` database into memory.
/// Returns an opaque handle for use with `checkScript` / `freeDb` / `listLibs`.
#[napi(js_name = "loadDb")]
pub fn load_db(data: Buffer) -> Result<u32> {
    slh::load_db(&data).map_err(Error::from_reason)
}

#[napi(object)]
pub struct JsCheckResult {
    pub whole_file: Vec<JsLibraryMatch>,
    pub functions: Vec<JsFunctionMatch>,
}

#[napi(object)]
pub struct JsLibraryMatch {
    pub lib: String,
    pub version: String,
}

#[napi(object)]
pub struct JsFunctionMatch {
    pub libs: Vec<JsLibraryMatch>,
    pub function_name: Option<String>,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

impl From<LibraryMatch> for JsLibraryMatch {
    fn from(m: LibraryMatch) -> Self {
        Self {
            lib: m.lib,
            version: m.version,
        }
    }
}

impl From<FunctionMatch> for JsFunctionMatch {
    fn from(f: FunctionMatch) -> Self {
        Self {
            libs: f.libs.into_iter().map(Into::into).collect(),
            function_name: f.function_name,
            start_line: f.start_line,
            start_column: f.start_column,
            end_line: f.end_line,
            end_column: f.end_column,
        }
    }
}

impl From<CheckResult> for JsCheckResult {
    fn from(r: CheckResult) -> Self {
        Self {
            whole_file: r.whole_file.into_iter().map(Into::into).collect(),
            functions: r.functions.into_iter().map(Into::into).collect(),
        }
    }
}

#[napi(object)]
pub struct JsDbHashRecord {
    pub hash: String,
    pub lib: String,
    pub version: String,
}

impl From<DbHashRecord> for JsDbHashRecord {
    fn from(r: DbHashRecord) -> Self {
        Self {
            hash: r.hash,
            lib: r.lib,
            version: r.version,
        }
    }
}

#[napi(object)]
pub struct JsDbContents {
    pub libs: Vec<JsLibInfo>,
    pub file_hashes: Vec<JsDbHashRecord>,
    pub func_hashes: Vec<JsDbHashRecord>,
}

impl From<DbContents> for JsDbContents {
    fn from(c: DbContents) -> Self {
        Self {
            libs: c.libs.into_iter().map(Into::into).collect(),
            file_hashes: c.file_hashes.into_iter().map(Into::into).collect(),
            func_hashes: c.func_hashes.into_iter().map(Into::into).collect(),
        }
    }
}

/// Extract all libraries and hash records from a loaded database.
/// Returns `null` if the handle is invalid.
#[napi(js_name = "extractDbContents")]
pub fn extract_db_contents(db_handle: u32) -> Option<JsDbContents> {
    slh::extract_db_contents(db_handle).map(Into::into)
}

/// Match a script against a loaded database. Returns whole-file and per-function matches.
#[napi(js_name = "checkScript")]
pub fn check_script(db_handle: u32, script: String) -> JsCheckResult {
    slh::check_script(db_handle, &script).into()
}

/// Release the memory held by a loaded database handle.
#[napi(js_name = "freeDb")]
pub fn free_db(db_handle: u32) {
    slh::free_db(db_handle);
}

#[napi(object)]
pub struct JsLibInfo {
    pub name: String,
    pub versions: Vec<String>,
}

impl From<LibInfo> for JsLibInfo {
    fn from(l: LibInfo) -> Self {
        Self {
            name: l.name,
            versions: l.versions,
        }
    }
}

/// Return the list of libraries and versions from a loaded database.
/// Returns `null` if the handle is invalid.
#[napi(js_name = "listLibs")]
pub fn list_libs(db_handle: u32) -> Option<Vec<JsLibInfo>> {
    slh::list_libs(db_handle).map(|libs| libs.into_iter().map(Into::into).collect())
}

#[cfg(feature = "debug-ir")]
/// Return the normalized token stream (IR) for a script. Debug/development only.
#[napi(js_name = "extractIR")]
pub fn extract_ir(script: String) -> Result<Vec<String>> {
    slh::hash::extract_ir(&script).map_err(Error::from_reason)
}
