use serde::Deserialize;
use wasm_bindgen::prelude::*;

use sinksight_library_hash as slh;

#[wasm_bindgen(js_name = extractHashes)]
pub fn extract_hashes(script: &str, min_statements: Option<u32>) -> Result<JsValue, JsValue> {
    let result =
        slh::hash::extract_hashes(script, min_statements).map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen(js_name = loadDb)]
pub fn load_db(data: &[u8]) -> Result<u32, JsValue> {
    slh::db::load_db(data).map_err(|e| JsValue::from_str(&e))
}

/// Parse error -> `{ wholeFile: [], functions: [] }`.
#[wasm_bindgen(js_name = checkScript)]
pub fn check_script(db_handle: u32, script: &str) -> JsValue {
    let result = slh::check::check_script(db_handle, script);
    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen(js_name = freeDb)]
pub fn free_db(db_handle: u32) {
    slh::db::free_db(db_handle);
}

#[derive(Deserialize)]
struct JsBuildDbLib {
    name: String,
    versions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsHashEntry {
    hash: String,
    lib_id: u16,
    version_index: u16,
}

/// Build a binary `.slhdb` database from structured hash data.
///
/// Hash strings must be in `slh1-<hex>` format. They are parsed and validated
/// internally — no manual binary packing required on the JS side.
#[wasm_bindgen(js_name = buildDb)]
pub fn build_db(
    min_statements: u8,
    libs: JsValue,
    file_hashes: JsValue,
    func_hashes: JsValue,
) -> Result<Vec<u8>, JsValue> {
    let libs: Vec<JsBuildDbLib> = serde_wasm_bindgen::from_value(libs)
        .map_err(|e| JsValue::from_str(&format!("invalid libs: {e}")))?;
    let file_hashes: Vec<JsHashEntry> = serde_wasm_bindgen::from_value(file_hashes)
        .map_err(|e| JsValue::from_str(&format!("invalid file_hashes: {e}")))?;
    let func_hashes: Vec<JsHashEntry> = serde_wasm_bindgen::from_value(func_hashes)
        .map_err(|e| JsValue::from_str(&format!("invalid func_hashes: {e}")))?;

    let libs_vec: Vec<(String, Vec<String>)> =
        libs.into_iter().map(|l| (l.name, l.versions)).collect();

    let parse_entries =
        |entries: Vec<JsHashEntry>,
         label: &str|
         -> Result<Vec<([u8; 32], u16, u16)>, JsValue> {
            entries
                .into_iter()
                .map(|e| {
                    let hash = slh::parse_hash_bytes(&e.hash).ok_or_else(|| {
                        JsValue::from_str(&format!("{label}: malformed hash: {}", e.hash))
                    })?;
                    Ok((hash, e.lib_id, e.version_index))
                })
                .collect()
        };

    let file = parse_entries(file_hashes, "file_hashes")?;
    let func = parse_entries(func_hashes, "func_hashes")?;

    Ok(slh::db::build_db(min_statements, &libs_vec, file, func))
}

/// Parse an `slh1-<hex>` hash string into its raw 32-byte digest.
///
/// Returns `null` if the string is malformed.
#[wasm_bindgen(js_name = parseHashBytes)]
pub fn parse_hash_bytes(hash: &str) -> JsValue {
    match slh::hash::parse_hash_bytes(hash) {
        Some(bytes) => {
            let arr = js_sys::Uint8Array::new_with_length(32);
            arr.copy_from(&bytes);
            arr.into()
        }
        None => JsValue::NULL,
    }
}

/// Return the list of libraries and their versions from a loaded database.
///
/// Returns `null` if the handle is invalid.
#[wasm_bindgen(js_name = listLibs)]
pub fn list_libs(db_handle: u32) -> JsValue {
    match slh::list_libs(db_handle) {
        Some(libs) => serde_wasm_bindgen::to_value(&libs).unwrap_or(JsValue::NULL),
        None => JsValue::NULL,
    }
}

#[cfg(feature = "debug-ir")]
#[wasm_bindgen(js_name = extractIR)]
pub fn extract_ir(script: &str) -> Result<JsValue, JsValue> {
    let tokens = slh::hash::extract_ir(script).map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&tokens).map_err(|e| JsValue::from_str(&e.to_string()))
}
