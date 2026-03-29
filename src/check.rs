use crate::db;
use crate::hash;
use crate::types::{CheckResult, FunctionMatch, LibraryMatch};

pub fn check_script(db_handle: u32, script: &str) -> CheckResult {
    let empty = CheckResult {
        whole_file: Vec::new(),
        functions: Vec::new(),
    };

    let min_stmts = match db::with_db(db_handle, |db| db.min_statements) {
        Some(ms) => ms as u32,
        None => return empty,
    };

    let analysis = match hash::analyze_for_check(script, min_stmts) {
        Some(a) => a,
        None => return empty, // Parse error -> empty result
    };

    db::with_db(db_handle, |db| {
        let file_matches = db.lookup_file_hash(&analysis.file_hash);
        if !file_matches.is_empty() {
            return CheckResult {
                whole_file: file_matches
                    .into_iter()
                    .map(|m| LibraryMatch {
                        lib: m.lib_name,
                        version: m.version,
                    })
                    .collect(),
                functions: Vec::new(),
            };
        }

        // DFS pruning: functions are in pre-order, so a matched parent skips all its children
        let mut matched_functions: Vec<FunctionMatch> = Vec::new();
        let mut matched_ranges: Vec<(u32, u32)> = Vec::new();

        for func_info in &analysis.functions {
            let func_start = func_info.span.start;
            let func_end = func_info.span.end;

            let is_inside_matched = matched_ranges
                .iter()
                .any(|&(start, end)| func_start >= start && func_end <= end);

            if is_inside_matched {
                continue;
            }

            let func_matches = db.lookup_func_hash(&func_info.hash);
            if !func_matches.is_empty() {
                matched_ranges.push((func_start, func_end));
                matched_functions.push(FunctionMatch {
                    libs: func_matches
                        .into_iter()
                        .map(|m| LibraryMatch {
                            lib: m.lib_name,
                            version: m.version,
                        })
                        .collect(),
                    function_name: func_info.name.clone(),
                    start_line: func_info.position.start_line,
                    start_column: func_info.position.start_column,
                    end_line: func_info.position.end_line,
                    end_column: func_info.position.end_column,
                });
            }
        }

        CheckResult {
            whole_file: Vec::new(),
            functions: matched_functions,
        }
    })
    .unwrap_or(empty)
}
