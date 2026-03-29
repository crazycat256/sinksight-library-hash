use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;
use sha2::{Digest, Sha256};

use crate::types::{ExtractResult, FunctionHashInfo};
use crate::visitor::{ScopeInfo, TokenCollector};

const HASH_PREFIX: &str = "slh1";
const DEFAULT_MIN_STATEMENTS: u32 = 3;

struct HashContext<'a> {
    source: &'a str,
    scoping: &'a oxc_semantic::Scoping,
    scope_info: &'a ScopeInfo,
    min_stmts: u32,
}

#[allow(dead_code)]
fn hash_to_bytes(tokens: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (i, token) in tokens.iter().enumerate() {
        if i > 0 {
            hasher.update(b",");
        }
        let bytes = token.as_bytes();
        let mut start = 0;
        for (pos, &b) in bytes.iter().enumerate() {
            if b == b'\\' || b == b',' {
                if start < pos {
                    hasher.update(&bytes[start..pos]);
                }
                if b == b'\\' {
                    hasher.update(b"\\\\");
                } else {
                    hasher.update(b"\\,");
                }
                start = pos + 1;
            }
        }
        if start < bytes.len() {
            hasher.update(&bytes[start..]);
        }
    }
    let digest = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

fn bytes_to_slh1(bytes: &[u8; 32]) -> String {
    let mut result = String::with_capacity(4 + 1 + 64);
    result.push_str(HASH_PREFIX);
    result.push('-');
    for &b in bytes {
        result.push(HEX_CHARS[(b >> 4) as usize] as char);
        result.push(HEX_CHARS[(b & 0xf) as usize] as char);
    }
    result
}

#[allow(dead_code)]
pub fn parse_hash_bytes(hash: &str) -> Option<[u8; 32]> {
    let (prefix, hex) = hash.split_once('-')?;
    if prefix != HASH_PREFIX || hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_char(chunk[0])?;
        let lo = hex_char(chunk[1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Some(bytes)
}

#[allow(dead_code)]
fn hex_char(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Line is 1-indexed, column is 0-indexed.
#[derive(Debug, Clone, Copy)]
pub struct SpanPosition {
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

struct LineIndex {
    line_starts: Vec<u32>,
}

impl LineIndex {
    fn new(source: &str) -> Self {
        let mut line_starts = vec![0u32];
        for (i, b) in source.bytes().enumerate() {
            if b == b'\n' {
                line_starts.push((i + 1) as u32);
            }
        }
        Self { line_starts }
    }

    fn offset_to_line_col(&self, source: &str, offset: u32) -> (u32, u32) {
        let line_idx = self.line_starts.partition_point(|&start| start <= offset);
        let line = line_idx as u32;
        let line_start = self.line_starts[line_idx - 1] as usize;
        let col = source[line_start..offset as usize].chars().count() as u32;
        (line, col)
    }
}

fn span_position(line_index: &LineIndex, source: &str, span: oxc_span::Span) -> SpanPosition {
    let (start_line, start_column) = line_index.offset_to_line_col(source, span.start);
    let (end_line, end_column) = line_index.offset_to_line_col(source, span.end);
    SpanPosition {
        start_line,
        start_column,
        end_line,
        end_column,
    }
}

fn parse_js<'a>(
    allocator: &'a Allocator,
    source: &'a str,
) -> oxc_parser::ParserReturn<'a> {
    let source_type = SourceType::unambiguous();
    let options = ParseOptions {
        allow_return_outside_function: true,
        preserve_parens: false,
        ..ParseOptions::default()
    };
    Parser::new(allocator, source, source_type)
        .with_options(options)
        .parse()
}

struct RawFunctionInfo {
    hash: [u8; 32],
    span: oxc_span::Span,
    name: Option<String>,
    stmt_count: u32,
}

pub fn extract_hashes(source: &str, min_statements: Option<u32>) -> Result<ExtractResult, String> {
    let min_stmts = min_statements.unwrap_or(DEFAULT_MIN_STATEMENTS);
    let allocator = Allocator::default();
    let parse_ret = parse_js(&allocator, source);

    if parse_ret.panicked {
        return Err("Parse error: parser panicked".to_string());
    }

    let program = &parse_ret.program;
    let sem_ret = SemanticBuilder::new().build(program);
    let scoping = sem_ret.semantic.scoping();

    let scope_info = ScopeInfo::new(scoping);
    let mut collector = TokenCollector::for_program(scoping, source, &scope_info);
    collector.visit_program(program);
    let file_hash = bytes_to_slh1(&collector.finish());

    let ctx = HashContext { source, scoping, scope_info: &scope_info, min_stmts };
    let mut raw: Vec<RawFunctionInfo> = Vec::new();
    collect_functions(program, &ctx, &mut raw);

    let line_index = LineIndex::new(source);
    let functions = raw
        .into_iter()
        .map(|r| {
            let pos = span_position(&line_index, source, r.span);
            FunctionHashInfo {
                hash: bytes_to_slh1(&r.hash),
                name: r.name,
                start_line: pos.start_line,
                start_column: pos.start_column,
                end_line: pos.end_line,
                end_column: pos.end_column,
                stmt_count: r.stmt_count,
            }
        })
        .collect();

    Ok(ExtractResult { file_hash, functions })
}

#[cfg(feature = "debug-ir")]
pub fn extract_ir(source: &str) -> Result<Vec<String>, String> {
    let allocator = Allocator::default();
    let parse_ret = parse_js(&allocator, source);

    if parse_ret.panicked {
        return Err("Parse error: parser panicked".to_string());
    }

    let program = &parse_ret.program;
    let sem_ret = SemanticBuilder::new().build(program);
    let scoping = sem_ret.semantic.scoping();

    let scope_info = ScopeInfo::new(scoping);
    let mut collector = TokenCollector::for_program(scoping, source, &scope_info);
    collector.visit_program(program);
    Ok(collector.tokens)
}

fn collect_functions(
    program: &Program,
    ctx: &HashContext,
    out: &mut Vec<RawFunctionInfo>,
) {
    for stmt in &program.body {
        collect_from_statement(stmt, ctx, out);
    }
}

fn collect_from_statement(
    stmt: &Statement,
    ctx: &HashContext,
    out: &mut Vec<RawFunctionInfo>,
) {
    match stmt {
        Statement::FunctionDeclaration(f) => {
            try_hash_function(f, ctx, out);
            if let Some(body) = &f.body {
                for inner_stmt in &body.statements {
                    collect_from_statement(inner_stmt, ctx, out);
                }
            }
        }
        Statement::ClassDeclaration(c) => {
            try_hash_class(c, ctx, out);
        }
        Statement::VariableDeclaration(d) => {
            for decl in &d.declarations {
                if let Some(init) = &decl.init {
                    collect_from_expression(init, ctx, out);
                }
            }
        }
        Statement::ExpressionStatement(s) => {
            collect_from_expression(&s.expression, ctx, out);
        }
        Statement::BlockStatement(s) => {
            for inner in &s.body {
                collect_from_statement(inner, ctx, out);
            }
        }
        Statement::IfStatement(s) => {
            collect_from_expression(&s.test, ctx, out);
            collect_from_statement(&s.consequent, ctx, out);
            if let Some(alt) = &s.alternate {
                collect_from_statement(alt, ctx, out);
            }
        }
        Statement::ForStatement(s) => {
            if let Some(init) = &s.init {
                if let ForStatementInit::VariableDeclaration(d) = init {
                    for decl in &d.declarations {
                        if let Some(init_expr) = &decl.init {
                            collect_from_expression(init_expr, ctx, out);
                        }
                    }
                }
            }
            collect_from_statement(&s.body, ctx, out);
        }
        Statement::WhileStatement(s) => {
            collect_from_statement(&s.body, ctx, out);
        }
        Statement::DoWhileStatement(s) => {
            collect_from_statement(&s.body, ctx, out);
        }
        Statement::ForInStatement(s) => {
            collect_from_statement(&s.body, ctx, out);
        }
        Statement::ForOfStatement(s) => {
            collect_from_statement(&s.body, ctx, out);
        }
        Statement::TryStatement(s) => {
            for inner in &s.block.body {
                collect_from_statement(inner, ctx, out);
            }
            if let Some(handler) = &s.handler {
                for inner in &handler.body.body {
                    collect_from_statement(inner, ctx, out);
                }
            }
            if let Some(finalizer) = &s.finalizer {
                for inner in &finalizer.body {
                    collect_from_statement(inner, ctx, out);
                }
            }
        }
        Statement::SwitchStatement(s) => {
            for case in &s.cases {
                for inner in &case.consequent {
                    collect_from_statement(inner, ctx, out);
                }
            }
        }
        Statement::LabeledStatement(s) => {
            collect_from_statement(&s.body, ctx, out);
        }
        Statement::ReturnStatement(s) => {
            if let Some(arg) = &s.argument {
                collect_from_expression(arg, ctx, out);
            }
        }
        Statement::ThrowStatement(s) => {
            collect_from_expression(&s.argument, ctx, out);
        }
        Statement::ExportDefaultDeclaration(d) => {
            match &d.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                    try_hash_function(f, ctx, out);
                    if let Some(body) = &f.body {
                        for inner in &body.statements {
                            collect_from_statement(inner, ctx, out);
                        }
                    }
                }
                ExportDefaultDeclarationKind::ClassDeclaration(c) => {
                    try_hash_class(c, ctx, out);
                }
                _ => {
                    if let Some(expr) = d.declaration.as_expression() {
                        collect_from_expression(expr, ctx, out);
                    }
                }
            }
        }
        Statement::ExportNamedDeclaration(d) => {
            if let Some(decl) = &d.declaration {
                match decl {
                    Declaration::FunctionDeclaration(f) => {
                        try_hash_function(f, ctx, out);
                        if let Some(body) = &f.body {
                            for inner in &body.statements {
                                collect_from_statement(inner, ctx, out);
                            }
                        }
                    }
                    Declaration::ClassDeclaration(c) => {
                        try_hash_class(c, ctx, out);
                    }
                    Declaration::VariableDeclaration(v) => {
                        for vd in &v.declarations {
                            if let Some(init) = &vd.init {
                                collect_from_expression(init, ctx, out);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn collect_from_expression(
    expr: &Expression,
    ctx: &HashContext,
    out: &mut Vec<RawFunctionInfo>,
) {
    match expr {
        Expression::FunctionExpression(f) => {
            try_hash_function(f, ctx, out);
            if let Some(body) = &f.body {
                for inner in &body.statements {
                    collect_from_statement(inner, ctx, out);
                }
            }
        }
        Expression::ArrowFunctionExpression(f) => {
            try_hash_arrow(f, ctx, out);
            for inner in &f.body.statements {
                collect_from_statement(inner, ctx, out);
            }
        }
        Expression::ClassExpression(c) => {
            try_hash_class(c, ctx, out);
        }
        Expression::ObjectExpression(e) => {
            for prop in &e.properties {
                match prop {
                    ObjectPropertyKind::ObjectProperty(p) => {
                        if p.method || p.kind != PropertyKind::Init {
                            if let Expression::FunctionExpression(func) = &p.value {
                                try_hash_function(func, ctx, out);
                                if let Some(body) = &func.body {
                                    for inner in &body.statements {
                                        collect_from_statement(inner, ctx, out);
                                    }
                                }
                            }
                        } else {
                            collect_from_expression(&p.value, ctx, out);
                        }
                    }
                    ObjectPropertyKind::SpreadProperty(s) => {
                        collect_from_expression(&s.argument, ctx, out);
                    }
                }
            }
        }
        Expression::CallExpression(e) => {
            collect_from_expression(&e.callee, ctx, out);
            for arg in &e.arguments {
                if let Some(a_expr) = arg.as_expression() {
                    collect_from_expression(a_expr, ctx, out);
                }
            }
        }
        Expression::AssignmentExpression(e) => {
            collect_from_expression(&e.right, ctx, out);
        }
        Expression::SequenceExpression(e) => {
            for inner in &e.expressions {
                collect_from_expression(inner, ctx, out);
            }
        }
        Expression::ConditionalExpression(e) => {
            collect_from_expression(&e.consequent, ctx, out);
            collect_from_expression(&e.alternate, ctx, out);
        }
        Expression::LogicalExpression(e) => {
            collect_from_expression(&e.left, ctx, out);
            collect_from_expression(&e.right, ctx, out);
        }
        Expression::ParenthesizedExpression(e) => {
            collect_from_expression(&e.expression, ctx, out);
        }
        Expression::ArrayExpression(e) => {
            for element in &e.elements {
                if let Some(inner_expr) = element.as_expression() {
                    collect_from_expression(inner_expr, ctx, out);
                }
            }
        }
        Expression::NewExpression(e) => {
            collect_from_expression(&e.callee, ctx, out);
            for arg in &e.arguments {
                if let Some(a_expr) = arg.as_expression() {
                    collect_from_expression(a_expr, ctx, out);
                }
            }
        }
        _ => {}
    }
}

fn try_hash_function(
    f: &Function,
    ctx: &HashContext,
    out: &mut Vec<RawFunctionInfo>,
) {
    let body = match &f.body {
        Some(b) => b,
        None => return,
    };
    let stmt_count = body.statements.len() as u32;
    if stmt_count < ctx.min_stmts {
        return;
    }
    let scope_id = match f.scope_id.get() {
        Some(id) => id,
        None => return,
    };

    let mut collector = TokenCollector::for_subtree(ctx.scoping, ctx.source, ctx.scope_info, scope_id);
    collector.visit_function_content(f);

    out.push(RawFunctionInfo {
        hash: collector.finish(),
        span: f.span,
        name: f.id.as_ref().map(|id| id.name.to_string()),
        stmt_count,
    });
}

fn try_hash_arrow(
    f: &ArrowFunctionExpression,
    ctx: &HashContext,
    out: &mut Vec<RawFunctionInfo>,
) {
    if f.expression {
        return;
    }
    let stmt_count = f.body.statements.len() as u32;
    if stmt_count < ctx.min_stmts {
        return;
    }
    let scope_id = match f.scope_id.get() {
        Some(id) => id,
        None => return,
    };

    let mut collector = TokenCollector::for_subtree(ctx.scoping, ctx.source, ctx.scope_info, scope_id);
    collector.visit_arrow_function_content(f);

    out.push(RawFunctionInfo {
        hash: collector.finish(),
        span: f.span,
        name: None,
        stmt_count,
    });
}

fn try_hash_class(
    c: &Class,
    ctx: &HashContext,
    out: &mut Vec<RawFunctionInfo>,
) {
    let stmt_count = c.body.body.len() as u32;
    if stmt_count < ctx.min_stmts {
        return;
    }
    let scope_id = match c.scope_id.get() {
        Some(id) => id,
        None => return,
    };

    let mut collector = TokenCollector::for_subtree(ctx.scoping, ctx.source, ctx.scope_info, scope_id);
    collector.visit_class_content(c);

    out.push(RawFunctionInfo {
        hash: collector.finish(),
        span: c.span,
        name: c.id.as_ref().map(|id| id.name.to_string()),
        stmt_count,
    });

    for element in &c.body.body {
        if let ClassElement::MethodDefinition(m) = element {
            try_hash_function(&m.value, ctx, out);
            if let Some(body) = &m.value.body {
                for inner in &body.statements {
                    collect_from_statement(inner, ctx, out);
                }
            }
        }
    }
}

pub struct CheckAnalysis {
    pub file_hash: [u8; 32],
    pub functions: Vec<CheckFunctionInfo>,
}

pub struct CheckFunctionInfo {
    pub hash: [u8; 32],
    pub span: oxc_span::Span,
    pub name: Option<String>,
    pub position: SpanPosition,
}

pub fn analyze_for_check(source: &str, min_stmts: u32) -> Option<CheckAnalysis> {
    let allocator = Allocator::default();
    let parse_ret = parse_js(&allocator, source);
    if parse_ret.panicked {
        return None;
    }

    let sem_ret = SemanticBuilder::new().build(&parse_ret.program);
    let scoping = sem_ret.semantic.scoping();

    let scope_info = ScopeInfo::new(scoping);
    let mut collector = TokenCollector::for_program(scoping, source, &scope_info);
    collector.visit_program(&parse_ret.program);
    let file_hash = collector.finish();

    let ctx = HashContext { source, scoping, scope_info: &scope_info, min_stmts };
    let mut raw: Vec<RawFunctionInfo> = Vec::new();
    collect_functions(&parse_ret.program, &ctx, &mut raw);

    let line_index = LineIndex::new(source);
    let functions = raw
        .into_iter()
        .map(|r| {
            let position = span_position(&line_index, source, r.span);
            CheckFunctionInfo {
                hash: r.hash,
                span: r.span,
                name: r.name,
                position,
            }
        })
        .collect();

    Some(CheckAnalysis { file_hash, functions })
}

