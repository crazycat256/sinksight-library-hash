//! `@sinksight/library-hash` - Rust/WASM implementation of the slh1 hashing algorithm.

mod check;
mod db;
mod hash;
mod types;
mod visitor;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = extractHashes)]
pub fn extract_hashes(script: &str, min_statements: Option<u32>) -> Result<JsValue, JsValue> {
    let result = hash::extract_hashes(script, min_statements)
        .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen(js_name = loadDb)]
pub fn load_db(data: &[u8]) -> Result<u32, JsValue> {
    db::load_db(data).map_err(|e| JsValue::from_str(&e))
}

/// Parse error -> `{ wholeFile: null, functions: [] }`.
#[wasm_bindgen(js_name = checkScript)]
pub fn check_script(db_handle: u32, script: &str) -> JsValue {
    let result = check::check_script(db_handle, script);
    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

#[wasm_bindgen(js_name = freeDb)]
pub fn free_db(db_handle: u32) {
    db::free_db(db_handle);
}

#[cfg(feature = "debug-ir")]
#[wasm_bindgen(js_name = extractIR)]
pub fn extract_ir(script: &str) -> Result<JsValue, JsValue> {
    let tokens = hash::extract_ir(script)
        .map_err(|e| JsValue::from_str(&e))?;
    serde_wasm_bindgen::to_value(&tokens).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_load_invalid_magic() {
        let data = b"XXXX\x01\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(db::load_db(data).is_err());
    }

    #[test]
    fn test_db_roundtrip() {
        let db_data = db::build_db(
            3,
            &[
                ("jquery".to_string(), vec!["3.7.1".to_string()]),
                ("lodash".to_string(), vec!["4.17.21".to_string()]),
            ],
            vec![
                ([0xAA; 32], 0, 0), // jQuery file hash
            ],
            vec![
                ([0xBB; 32], 1, 0), // Lodash function hash
            ],
        );

        let handle = db::load_db(&db_data).unwrap();

        let file_result = db::with_db(handle, |db| {
            db.lookup_file_hash(&[0xAA; 32])
        })
        .flatten();
        assert!(file_result.is_some());
        let m = file_result.unwrap();
        assert_eq!(m.lib_name, "jquery");
        assert_eq!(m.version, "3.7.1");

        let func_result = db::with_db(handle, |db| {
            db.lookup_func_hash(&[0xBB; 32])
        })
        .flatten();
        assert!(func_result.is_some());
        let m = func_result.unwrap();
        assert_eq!(m.lib_name, "lodash");
        assert_eq!(m.version, "4.17.21");

        let missing = db::with_db(handle, |db| {
            db.lookup_file_hash(&[0xCC; 32])
        })
        .flatten();
        assert!(missing.is_none());

        db::free_db(handle);
    }

    #[test]
    fn test_check_script_whole_file_match() {
        let script = "var x = 1; var y = 2; var z = 3;";
        let extract = hash::extract_hashes(script, Some(3)).unwrap();
        let hash_bytes = hash::parse_hash_bytes(&extract.file_hash).unwrap();

        let db_data = db::build_db(
            3,
            &[("testlib".to_string(), vec!["1.0.0".to_string()])],
            vec![(hash_bytes, 0, 0)],
            vec![],
        );

        let handle = db::load_db(&db_data).unwrap();
        let result = check::check_script(handle, script);

        assert!(result.whole_file.is_some());
        let wf = result.whole_file.unwrap();
        assert_eq!(wf.lib, "testlib");
        assert_eq!(wf.version, "1.0.0");
        assert!(result.functions.is_empty());

        db::free_db(handle);
    }

    #[test]
    fn test_check_script_function_match() {
        let script = r#"
            function helper(a, b) {
                var c = a + b;
                var d = c * 2;
                return d;
            }
            function other() {
                var x = 1;
                var y = 2;
                var z = 3;
                return x + y + z;
            }
        "#;

        let extract = hash::extract_hashes(script, Some(3)).unwrap();
        assert!(extract.functions.len() >= 2);

        let first_func_hash = hash::parse_hash_bytes(&extract.functions[0].hash).unwrap();

        let db_data = db::build_db(
            3,
            &[("mylib".to_string(), vec!["2.0.0".to_string()])],
            vec![],
            vec![(first_func_hash, 0, 0)],
        );

        let handle = db::load_db(&db_data).unwrap();
        let result = check::check_script(handle, script);

        assert!(result.whole_file.is_none());
        assert_eq!(result.functions.len(), 1);
        assert_eq!(result.functions[0].lib, "mylib");
        assert_eq!(result.functions[0].version, "2.0.0");

        db::free_db(handle);
    }

    #[test]
    fn test_check_script_no_match() {
        let db_data = db::build_db(
            3,
            &[("testlib".to_string(), vec!["1.0.0".to_string()])],
            vec![([0xFF; 32], 0, 0)],
            vec![],
        );

        let handle = db::load_db(&db_data).unwrap();
        let result = check::check_script(handle, "var x = 1;");

        assert!(result.whole_file.is_none());
        assert!(result.functions.is_empty());

        db::free_db(handle);
    }

    #[test]
    fn test_pruning_parent_match_skips_children() {
        let script = r#"
            function outer() {
                var a = 1;
                var b = 2;
                var c = 3;
                function inner() {
                    var x = 1;
                    var y = 2;
                    var z = 3;
                    return x;
                }
                return inner;
            }
        "#;

        let extract = hash::extract_hashes(script, Some(3)).unwrap();
        assert!(extract.functions.len() >= 2);

        let outer = extract.functions.iter().find(|f| f.name.as_deref() == Some("outer")).unwrap();
        let inner = extract.functions.iter().find(|f| f.name.as_deref() == Some("inner")).unwrap();
        let outer_hash = hash::parse_hash_bytes(&outer.hash).unwrap();
        let inner_hash = hash::parse_hash_bytes(&inner.hash).unwrap();

        let db_data = db::build_db(
            3,
            &[("mylib".to_string(), vec!["1.0.0".to_string()])],
            vec![],
            vec![(outer_hash, 0, 0), (inner_hash, 0, 0)],
        );

        let handle = db::load_db(&db_data).unwrap();
        let result = check::check_script(handle, script);

        assert_eq!(result.functions.len(), 1);
        assert_eq!(result.functions[0].function_name.as_deref(), Some("outer"));

        db::free_db(handle);
    }

    #[test]
    fn test_children_returned_when_parent_doesnt_match() {
        let script = r#"
            function outer() {
                var a = 1;
                var b = 2;
                var c = 3;
                function inner() {
                    var x = 1;
                    var y = 2;
                    var z = 3;
                    return x;
                }
                return inner;
            }
        "#;

        let extract = hash::extract_hashes(script, Some(3)).unwrap();
        let inner = extract.functions.iter().find(|f| f.name.as_deref() == Some("inner")).unwrap();
        let inner_hash = hash::parse_hash_bytes(&inner.hash).unwrap();

        let db_data = db::build_db(
            3,
            &[("mylib".to_string(), vec!["1.0.0".to_string()])],
            vec![],
            vec![(inner_hash, 0, 0)],
        );

        let handle = db::load_db(&db_data).unwrap();
        let result = check::check_script(handle, script);

        assert_eq!(result.functions.len(), 1);
        assert_eq!(result.functions[0].function_name.as_deref(), Some("inner"));

        db::free_db(handle);
    }
}
