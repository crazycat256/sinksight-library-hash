#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

use sinksight_library_hash as slh;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "BuildDbLib[]")]
    pub type BuildDbLibArray;

    #[wasm_bindgen(typescript_type = "HashEntry[]")]
    pub type HashEntryArray;

    #[wasm_bindgen(typescript_type = "Uint8Array | null")]
    pub type Uint8ArrayOrNull;

    #[wasm_bindgen(typescript_type = "LibInfo[] | null")]
    pub type LibInfoArrayOrNull;
}

#[derive(Serialize, Tsify)]
#[tsify(into_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct ExtractResult {
    pub file_hash: String,
    pub functions: Vec<FunctionHashInfo>,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct FunctionHashInfo {
    pub hash: String,
    pub name: Option<String>,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub stmt_count: u32,
}

#[derive(Serialize, Tsify)]
#[tsify(into_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub whole_file: Vec<LibraryMatch>,
    pub functions: Vec<FunctionMatch>,
}

#[derive(Serialize, Tsify)]
pub struct LibraryMatch {
    pub lib: String,
    pub version: String,
}

#[derive(Serialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct FunctionMatch {
    pub libs: Vec<LibraryMatch>,
    pub function_name: Option<String>,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(Serialize, Tsify)]
pub struct LibInfo {
    pub name: String,
    pub versions: Vec<String>,
}

#[derive(Deserialize, Tsify)]
pub struct BuildDbLib {
    pub name: String,
    pub versions: Vec<String>,
}

#[derive(Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
pub struct HashEntry {
    pub hash: String,
    pub lib_id: u16,
    pub version_index: u16,
}

impl From<slh::ExtractResult> for ExtractResult {
    fn from(r: slh::ExtractResult) -> Self {
        Self {
            file_hash: r.file_hash,
            functions: r.functions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<slh::FunctionHashInfo> for FunctionHashInfo {
    fn from(f: slh::FunctionHashInfo) -> Self {
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

impl From<slh::CheckResult> for CheckResult {
    fn from(r: slh::CheckResult) -> Self {
        Self {
            whole_file: r.whole_file.into_iter().map(Into::into).collect(),
            functions: r.functions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<slh::LibraryMatch> for LibraryMatch {
    fn from(m: slh::LibraryMatch) -> Self {
        Self { lib: m.lib, version: m.version }
    }
}

impl From<slh::FunctionMatch> for FunctionMatch {
    fn from(f: slh::FunctionMatch) -> Self {
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

impl From<slh::LibInfo> for LibInfo {
    fn from(l: slh::LibInfo) -> Self {
        Self { name: l.name, versions: l.versions }
    }
}

/// Parse a JavaScript source and return file hash + per-function hashes.
#[wasm_bindgen(js_name = extractHashes)]
pub fn extract_hashes(script: &str, minStatements: Option<u32>) -> Result<ExtractResult, JsValue> {
    slh::extract_hashes(script, minStatements)
        .map(Into::into)
        .map_err(|e| JsValue::from_str(&e))
}

/// Load a pre-built binary `.slhdb` database into memory.
/// Returns an opaque handle.
#[wasm_bindgen(js_name = loadDb)]
pub fn load_db(data: &[u8]) -> Result<u32, JsValue> {
    slh::load_db(data).map_err(|e| JsValue::from_str(&e))
}

/// Match a script against a loaded database.
#[wasm_bindgen(js_name = checkScript)]
pub fn check_script(dbHandle: u32, script: &str) -> CheckResult {
    slh::check_script(dbHandle, script).into()
}

/// Release the memory held by a loaded database handle.
#[wasm_bindgen(js_name = freeDb)]
pub fn free_db(dbHandle: u32) {
    slh::free_db(dbHandle);
}

/// Build a binary `.slhdb` database from structured hash data.
///
/// Hash strings must be in `slh1-<hex>` format.
#[wasm_bindgen(js_name = buildDb)]
pub fn build_db(
    minStatements: u8,
    libs: BuildDbLibArray,
    fileHashes: HashEntryArray,
    funcHashes: HashEntryArray,
) -> Result<Vec<u8>, JsValue> {
    let libs: Vec<BuildDbLib> = serde_wasm_bindgen::from_value(libs.into())
        .map_err(|e| JsValue::from_str(&format!("invalid libs: {e}")))?;
    let file_hashes: Vec<HashEntry> = serde_wasm_bindgen::from_value(fileHashes.into())
        .map_err(|e| JsValue::from_str(&format!("invalid fileHashes: {e}")))?;
    let func_hashes: Vec<HashEntry> = serde_wasm_bindgen::from_value(funcHashes.into())
        .map_err(|e| JsValue::from_str(&format!("invalid funcHashes: {e}")))?;

    let libs_vec: Vec<(String, Vec<String>)> =
        libs.into_iter().map(|l| (l.name, l.versions)).collect();

    let parse = |entries: Vec<HashEntry>, label: &str| -> Result<Vec<([u8; 32], u16, u16)>, JsValue> {
        entries
            .into_iter()
            .map(|e| {
                let hash = slh::parse_hash_bytes(&e.hash)
                    .ok_or_else(|| JsValue::from_str(&format!("{label}: malformed hash: {}", e.hash)))?;
                Ok((hash, e.lib_id, e.version_index))
            })
            .collect()
    };

    let file = parse(file_hashes, "fileHashes")?;
    let func = parse(func_hashes, "funcHashes")?;

    Ok(slh::db::build_db(minStatements, &libs_vec, file, func))
}

/// Parse an `slh1-<hex>` hash string into its raw 32-byte digest.
/// Returns `null` if the string is malformed.
#[wasm_bindgen(js_name = parseHashBytes)]
pub fn parse_hash_bytes(hash: &str) -> Uint8ArrayOrNull {
    let val = match slh::parse_hash_bytes(hash) {
        Some(bytes) => {
            let arr = js_sys::Uint8Array::new_with_length(32);
            arr.copy_from(&bytes);
            arr.into()
        }
        None => JsValue::NULL,
    };
    val.unchecked_into()
}

/// Return the list of libraries and their versions from a loaded database.
/// Returns `null` if the handle is invalid.
#[wasm_bindgen(js_name = listLibs)]
pub fn list_libs(dbHandle: u32) -> LibInfoArrayOrNull {
    let val = match slh::list_libs(dbHandle) {
        Some(libs) => {
            let typed: Vec<LibInfo> = libs.into_iter().map(Into::into).collect();
            serde_wasm_bindgen::to_value(&typed).unwrap_or(JsValue::NULL)
        }
        None => JsValue::NULL,
    };
    val.unchecked_into()
}

#[cfg(feature = "debug-ir")]
/// Return the normalized token stream (IR) for a script. Debug/development only.
#[wasm_bindgen(js_name = extractIR)]
pub fn extract_ir(script: &str) -> Result<Vec<String>, JsValue> {
    slh::hash::extract_ir(script).map_err(|e| JsValue::from_str(&e))
}
