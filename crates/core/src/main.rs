use std::env;
use std::fs;
use std::process;

use sinksight_library_hash::{check_script, free_db, load_db, CheckResult, FunctionMatch, LibraryMatch};

fn main() {
    if let Err(error) = run(env::args().skip(1)) {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run<I>(args: I) -> Result<(), String>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    match parse_args(args)? {
        Command::Check { db_path, script_path } => run_check(&db_path, &script_path),
        Command::Help => {
            print_usage();
            Ok(())
        }
    }
}

#[derive(Debug)]
enum Command {
    Check { db_path: String, script_path: String },
    Help,
}

fn parse_args<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let Some(command) = args.next() else {
        return Ok(Command::Help);
    };

    match command.as_str() {
        "help" | "--help" | "-h" => Ok(Command::Help),
        "check" => parse_check_args(args),
        other => Err(format!(
            "unknown command `{other}`\n\n{}",
            usage_text()
        )),
    }
}

fn parse_check_args<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let mut db_path = None;
    let mut script_path = None;
    let mut positional = Vec::new();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--db" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value after --db".to_string())?;
                db_path = Some(value);
            }
            "--script" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value after --script".to_string())?;
                script_path = Some(value);
            }
            "--help" | "-h" => return Ok(Command::Help),
            value if value.starts_with('-') => {
                return Err(format!(
                    "unknown option `{value}`\n\n{}",
                    usage_text()
                ));
            }
            value => positional.push(value.to_string()),
        }
    }

    if db_path.is_none() && script_path.is_none() && positional.len() == 2 {
        db_path = positional.first().cloned();
        script_path = positional.get(1).cloned();
    } else if !positional.is_empty() {
        return Err(format!(
            "unexpected positional arguments: {}\n\n{}",
            positional.join(" "),
            usage_text()
        ));
    }

    let db_path = db_path.ok_or_else(|| format!("missing --db\n\n{}", usage_text()))?;
    let script_path =
        script_path.ok_or_else(|| format!("missing --script\n\n{}", usage_text()))?;

    Ok(Command::Check {
        db_path,
        script_path,
    })
}

fn run_check(db_path: &str, script_path: &str) -> Result<(), String> {
    let db_bytes = fs::read(db_path)
        .map_err(|error| format!("failed to read database `{db_path}`: {error}"))?;
    let script = fs::read_to_string(script_path)
        .map_err(|error| format!("failed to read script `{script_path}`: {error}"))?;

    let handle = load_db(&db_bytes)?;
    let result = check_script(handle, &script);
    free_db(handle);

    let output = render_check_result(&result);
    if !output.is_empty() {
        print!("{output}");
    }
    Ok(())
}

fn render_check_result(result: &CheckResult) -> String {
    let mut lines = Vec::new();

    for lib in &result.whole_file {
        lines.push(render_whole_file_match(lib));
    }

    for function in &result.functions {
        for lib in &function.libs {
            lines.push(render_function_match(function, lib));
        }
    }

    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

fn render_whole_file_match(lib: &LibraryMatch) -> String {
    format!("whole-file\t{}@{}", lib.lib, lib.version)
}

fn render_function_match(function: &FunctionMatch, lib: &LibraryMatch) -> String {
    let name = function.function_name.as_deref().unwrap_or("<anonymous>");
    format!(
        "function\t{}:{}-{}:{}\t{}\t{}@{}",
        function.start_line,
        function.start_column,
        function.end_line,
        function.end_column,
        name,
        lib.lib,
        lib.version
    )
}

fn usage_text() -> &'static str {
    "Usage:\n  slh check --db <database.slhdb> --script <file.js>\n  slh check <database.slhdb> <file.js>\n\nOutput:\n  One match per line.\n  whole-file<TAB><lib>@<version>\n  function<TAB><startLine>:<startColumn>-<endLine>:<endColumn><TAB><functionName><TAB><lib>@<version>"
}

fn print_usage() {
    println!("{}", usage_text());
}

#[cfg(test)]
mod tests {
    use super::{parse_args, render_check_result, CheckResult, Command, FunctionMatch, LibraryMatch};

    #[test]
    fn parse_check_flags() {
        let command = parse_args(["check", "--db", "db.slhdb", "--script", "file.js"])
            .expect("check command should parse");
        match command {
            Command::Check { db_path, script_path } => {
                assert_eq!(db_path, "db.slhdb");
                assert_eq!(script_path, "file.js");
            }
            Command::Help => panic!("expected check command"),
        }
    }

    #[test]
    fn parse_check_positionals() {
        let command =
            parse_args(["check", "db.slhdb", "file.js"]).expect("check command should parse");
        match command {
            Command::Check { db_path, script_path } => {
                assert_eq!(db_path, "db.slhdb");
                assert_eq!(script_path, "file.js");
            }
            Command::Help => panic!("expected check command"),
        }
    }

    #[test]
    fn parse_check_requires_paths() {
        let error = parse_args(["check", "--db", "db.slhdb"]).expect_err("expected error");
        assert!(error.contains("missing --script"));
    }

    #[test]
    fn render_empty_result() {
        let output = render_check_result(&CheckResult {
            whole_file: Vec::new(),
            functions: Vec::new(),
        });
        assert_eq!(output, "");
    }

    #[test]
    fn render_one_line_per_match() {
        let output = render_check_result(&CheckResult {
            whole_file: vec![LibraryMatch {
                lib: "crypto-js".to_string(),
                version: "4.2.0".to_string(),
            }],
            functions: vec![FunctionMatch {
                libs: vec![LibraryMatch {
                    lib: "crypto-js".to_string(),
                    version: "3.1.2".to_string(),
                }],
                function_name: None,
                start_line: 149,
                start_column: 12,
                end_line: 153,
                end_column: 5,
            }],
        });

        assert_eq!(
            output,
            "whole-file\tcrypto-js@4.2.0\nfunction\t149:12-153:5\t<anonymous>\tcrypto-js@3.1.2\n"
        );
    }
}