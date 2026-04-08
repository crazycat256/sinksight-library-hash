//! `sinksight-library-hash` — AST-based JavaScript library fingerprinting.
//!
//! Produces deterministic [`slh1`](https://github.com/crazycat256/sinksight-library-hash)
//! hashes for JS files and their individual functions. Hashes are stable across
//! minification, re-formatting, and variable renaming, making them suitable for
//! identifying known libraries (jQuery, Lodash, React …).
//!
//! # Usage
//!
//! ```rust
//! use sinksight_library_hash::{extract_hashes, load_db, check_script, free_db};
//!
//! # let source = "function f(a,b){var c=a+b;return c;}";
//! let result = extract_hashes(source, None).unwrap();
//! println!("file hash: {}", result.file_hash);
//! for f in &result.functions {
//!     println!("  {} -> {}", f.name.as_deref().unwrap_or("<anon>"), f.hash);
//! }
//! ```

pub mod check;
pub mod db;
pub mod hash;
pub mod types;
pub(crate) mod visitor;

pub use types::{
    CheckResult, ExtractResult, FunctionHashInfo,
    FunctionMatch, LibInfo, LibraryMatch,
};

pub fn extract_hashes(script: &str, min_statements: Option<u32>) -> Result<ExtractResult, String> {
    hash::extract_hashes(script, min_statements)
}

pub fn load_db(data: &[u8]) -> Result<u32, String> {
    db::load_db(data)
}

pub fn check_script(db_handle: u32, script: &str) -> CheckResult {
    check::check_script(db_handle, script)
}

pub fn free_db(db_handle: u32) {
    db::free_db(db_handle);
}

pub fn parse_hash_bytes(hash: &str) -> Option<[u8; 32]> {
    hash::parse_hash_bytes(hash)
}

pub fn list_libs(db_handle: u32) -> Option<Vec<types::LibInfo>> {
    db::with_db(db_handle, |db| {
        db.libs
            .iter()
            .map(|lib| types::LibInfo {
                name: lib.name.clone(),
                versions: lib.versions.clone(),
            })
            .collect()
    })
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
            vec![([0xAA; 32], 0, 0)],
            vec![([0xBB; 32], 1, 0)],
        );

        let handle = db::load_db(&db_data).unwrap();

        let file_result = db::with_db(handle, |db| db.lookup_file_hash(&[0xAA; 32])).unwrap();
        assert_eq!(file_result.len(), 1);
        assert_eq!(file_result[0].lib_name, "jquery");
        assert_eq!(file_result[0].version, "3.7.1");

        let func_result = db::with_db(handle, |db| db.lookup_func_hash(&[0xBB; 32])).unwrap();
        assert_eq!(func_result.len(), 1);
        assert_eq!(func_result[0].lib_name, "lodash");
        assert_eq!(func_result[0].version, "4.17.21");

        let missing = db::with_db(handle, |db| db.lookup_file_hash(&[0xCC; 32])).unwrap();
        assert!(missing.is_empty());

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

        assert!(!result.whole_file.is_empty());
        assert_eq!(result.whole_file[0].lib, "testlib");
        assert_eq!(result.whole_file[0].version, "1.0.0");
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

        assert!(result.whole_file.is_empty());
        assert_eq!(result.functions.len(), 1);
        assert_eq!(result.functions[0].libs[0].lib, "mylib");

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

        assert!(result.whole_file.is_empty());
        assert!(result.functions.is_empty());

        db::free_db(handle);
    }

    #[test]
    fn test_pruning_parent_match_skips_children() {
        let script = r#"
            function outer() {
                var a = 1; var b = 2; var c = 3;
                function inner() { var x = 1; var y = 2; var z = 3; return x; }
                return inner;
            }
        "#;

        let extract = hash::extract_hashes(script, Some(3)).unwrap();
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
                var a = 1; var b = 2; var c = 3;
                function inner() { var x = 1; var y = 2; var z = 3; return x; }
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

    #[test]
    fn test_multi_lib_lookup() {
        let shared_hash = [0xDD; 32];
        let db_data = db::build_db(
            3,
            &[
                ("lib-a".to_string(), vec!["1.0.0".to_string()]),
                ("lib-b".to_string(), vec!["2.0.0".to_string()]),
            ],
            vec![],
            vec![(shared_hash, 0, 0), (shared_hash, 1, 0)],
        );

        let handle = db::load_db(&db_data).unwrap();
        let results = db::with_db(handle, |db| db.lookup_func_hash(&shared_hash)).unwrap();
        assert_eq!(results.len(), 2);
        let names: Vec<&str> = results.iter().map(|r| r.lib_name.as_str()).collect();
        assert!(names.contains(&"lib-a"));
        assert!(names.contains(&"lib-b"));

        db::free_db(handle);
    }

    #[test]
    fn test_multi_lib_check_script_function() {
        let script = r#"
            function helper(a, b) {
                var c = a + b;
                var d = c * 2;
                return d;
            }
        "#;

        let extract = hash::extract_hashes(script, Some(3)).unwrap();
        let func_hash = hash::parse_hash_bytes(&extract.functions[0].hash).unwrap();

        let db_data = db::build_db(
            3,
            &[
                ("lib-x".to_string(), vec!["1.0.0".to_string()]),
                ("lib-y".to_string(), vec!["3.0.0".to_string()]),
            ],
            vec![],
            vec![(func_hash, 0, 0), (func_hash, 1, 0)],
        );

        let handle = db::load_db(&db_data).unwrap();
        let result = check::check_script(handle, script);
        assert_eq!(result.functions.len(), 1);
        assert_eq!(result.functions[0].libs.len(), 2);

        db::free_db(handle);
    }
}
