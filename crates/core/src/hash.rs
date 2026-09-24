use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::{ParseOptions, Parser};
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;

use crate::types::{
    DetailedExtractResult, DetailedFunctionHashInfo, ExtractResult, FunctionHashInfo,
};
use crate::visitor::{ScopeInfo, TokenCollector};

const HASH_PREFIX: &str = "slh1";
const DEFAULT_MIN_STATEMENTS: u32 = 3;
const STRUCTURAL_UNITS_PER_STATEMENT: u32 = 2;

struct HashContext<'a> {
    source: &'a str,
    scoping: &'a oxc_semantic::Scoping,
    scope_info: &'a ScopeInfo,
    min_stmts: u32,
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

pub fn bytes_to_slh1(bytes: &[u8; 32]) -> String {
    let mut result = String::with_capacity(4 + 1 + 64);
    result.push_str(HASH_PREFIX);
    result.push('-');
    for &b in bytes {
        result.push(HEX_CHARS[(b >> 4) as usize] as char);
        result.push(HEX_CHARS[(b & 0xf) as usize] as char);
    }
    result
}

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

fn parse_js<'a>(allocator: &'a Allocator, source: &'a str) -> oxc_parser::ParserReturn<'a> {
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
    canonical: String,
    span: oxc_span::Span,
    name: Option<String>,
    stmt_count: u32,
}

fn min_structural_units(min_stmts: u32) -> u32 {
    min_stmts
        .saturating_mul(STRUCTURAL_UNITS_PER_STATEMENT)
        .saturating_sub(1)
}

fn meets_min_complexity(stmt_count: u32, structural_units: u32, min_stmts: u32) -> bool {
    stmt_count >= min_stmts || structural_units >= min_structural_units(min_stmts)
}

fn count_function_body_units(body: &FunctionBody) -> u32 {
    body.statements.iter().map(count_statement_units).sum()
}

fn count_arrow_body_units(body: &ArrowFunctionBody) -> u32 {
    match body {
        ArrowFunctionBody::FunctionBody(body) => count_function_body_units(body),
        _ => body
            .as_expression()
            .map(count_expression_units)
            .unwrap_or(0),
    }
}

fn count_class_body_units(body: &ClassBody) -> u32 {
    body.body.iter().map(count_class_element_units).sum()
}

fn count_class_element_units(element: &ClassElement) -> u32 {
    match element {
        ClassElement::MethodDefinition(m) => 1 + count_function_units(&m.value),
        ClassElement::PropertyDefinition(p) => {
            1 + p.value.as_ref().map(count_expression_units).unwrap_or(0)
        }
        ClassElement::AccessorProperty(p) => {
            1 + p.value.as_ref().map(count_expression_units).unwrap_or(0)
        }
        ClassElement::StaticBlock(block) => {
            1 + block.body.iter().map(count_statement_units).sum::<u32>()
        }
        _ => 1,
    }
}

fn count_function_units(function: &Function) -> u32 {
    function
        .body
        .as_ref()
        .map(|body| count_function_body_units(body))
        .unwrap_or(1)
}

fn count_statement_units(stmt: &Statement) -> u32 {
    match stmt {
        Statement::ExpressionStatement(s) => 1 + count_expression_units(&s.expression),
        Statement::ReturnStatement(s) => {
            1 + s.argument.as_ref().map(count_expression_units).unwrap_or(0)
        }
        Statement::ThrowStatement(s) => 1 + count_expression_units(&s.argument),
        Statement::VariableDeclaration(d) => {
            1 + d
                .declarations
                .iter()
                .map(|decl| decl.init.as_ref().map(count_expression_units).unwrap_or(0))
                .sum::<u32>()
        }
        Statement::BlockStatement(s) => s.body.iter().map(count_statement_units).sum(),
        Statement::IfStatement(s) => {
            1 + count_expression_units(&s.test)
                + count_statement_units(&s.consequent)
                + s.alternate
                    .as_ref()
                    .map(|alt| count_statement_units(alt))
                    .unwrap_or(0)
        }
        Statement::ForStatement(s) => {
            1 + s
                .init
                .as_ref()
                .map(|init| {
                    if let ForStatementInit::VariableDeclaration(d) = init {
                        1 + d
                            .declarations
                            .iter()
                            .map(|decl| decl.init.as_ref().map(count_expression_units).unwrap_or(0))
                            .sum::<u32>()
                    } else if let Some(expr) = init.as_expression() {
                        count_expression_units(expr)
                    } else {
                        1
                    }
                })
                .unwrap_or(0)
                + s.test.as_ref().map(count_expression_units).unwrap_or(0)
                + s.update.as_ref().map(count_expression_units).unwrap_or(0)
                + count_statement_units(&s.body)
        }
        Statement::ForInStatement(s) => {
            1 + count_for_statement_left_units(&s.left)
                + count_expression_units(&s.right)
                + count_statement_units(&s.body)
        }
        Statement::ForOfStatement(s) => {
            1 + count_for_statement_left_units(&s.left)
                + count_expression_units(&s.right)
                + count_statement_units(&s.body)
        }
        Statement::WhileStatement(s) => {
            1 + count_expression_units(&s.test) + count_statement_units(&s.body)
        }
        Statement::DoWhileStatement(s) => {
            1 + count_statement_units(&s.body) + count_expression_units(&s.test)
        }
        Statement::TryStatement(s) => {
            1 + s.block.body.iter().map(count_statement_units).sum::<u32>()
                + s.handler
                    .as_ref()
                    .map(|handler| {
                        handler
                            .body
                            .body
                            .iter()
                            .map(count_statement_units)
                            .sum::<u32>()
                    })
                    .unwrap_or(0)
                + s.finalizer
                    .as_ref()
                    .map(|finalizer| {
                        finalizer
                            .body
                            .iter()
                            .map(count_statement_units)
                            .sum::<u32>()
                    })
                    .unwrap_or(0)
        }
        Statement::SwitchStatement(s) => {
            1 + count_expression_units(&s.discriminant)
                + s.cases
                    .iter()
                    .map(|case| {
                        case.test.as_ref().map(count_expression_units).unwrap_or(0)
                            + case
                                .consequent
                                .iter()
                                .map(count_statement_units)
                                .sum::<u32>()
                    })
                    .sum::<u32>()
        }
        Statement::LabeledStatement(s) => 1 + count_statement_units(&s.body),
        Statement::WithStatement(s) => {
            1 + count_expression_units(&s.object) + count_statement_units(&s.body)
        }
        Statement::FunctionDeclaration(f) => 1 + count_function_units(f),
        Statement::ClassDeclaration(c) => 1 + count_class_body_units(&c.body),
        Statement::ExportDefaultDeclaration(d) => {
            1 + match &d.declaration {
                ExportDefaultDeclarationKind::FunctionDeclaration(f) => count_function_units(f),
                ExportDefaultDeclarationKind::ClassDeclaration(c) => {
                    count_class_body_units(&c.body)
                }
                _ => d
                    .declaration
                    .as_expression()
                    .map(count_expression_units)
                    .unwrap_or(0),
            }
        }
        Statement::ExportDeclaration(d) => {
            1 + match &d.declaration {
                Declaration::FunctionDeclaration(f) => count_function_units(f),
                Declaration::ClassDeclaration(c) => count_class_body_units(&c.body),
                Declaration::VariableDeclaration(v) => {
                    1 + v
                        .declarations
                        .iter()
                        .map(|decl| decl.init.as_ref().map(count_expression_units).unwrap_or(0))
                        .sum::<u32>()
                }
                _ => 1,
            }
        }
        Statement::ExportNamedDeclaration(_) | Statement::ExportFromDeclaration(_) => 1,
        Statement::ExportAllDeclaration(_) => 1,
        Statement::ImportDeclaration(_) => 1,
        _ => 1,
    }
}

fn count_for_statement_left_units(left: &ForStatementLeft) -> u32 {
    match left {
        ForStatementLeft::VariableDeclaration(d) => {
            1 + d
                .declarations
                .iter()
                .map(|decl| decl.init.as_ref().map(count_expression_units).unwrap_or(0))
                .sum::<u32>()
        }
        _ => left
            .as_assignment_target()
            .map(count_assignment_target_units)
            .unwrap_or(1),
    }
}

fn count_assignment_target_units(target: &AssignmentTarget) -> u32 {
    match target {
        AssignmentTarget::AssignmentTargetIdentifier(_) => 0,
        AssignmentTarget::ComputedMemberExpression(m) => {
            1 + count_expression_units(&m.object) + count_expression_units(&m.expression)
        }
        AssignmentTarget::StaticMemberExpression(m) => 1 + count_expression_units(&m.object),
        AssignmentTarget::PrivateFieldExpression(m) => 1 + count_expression_units(&m.object),
        AssignmentTarget::ArrayAssignmentTarget(a) => {
            1 + a
                .elements
                .iter()
                .map(|element| {
                    element
                        .as_ref()
                        .map(count_assignment_target_maybe_default_units)
                        .unwrap_or(0)
                })
                .sum::<u32>()
                + a.rest
                    .as_ref()
                    .map(|rest| count_assignment_target_units(&rest.target))
                    .unwrap_or(0)
        }
        AssignmentTarget::ObjectAssignmentTarget(o) => {
            1 + o
                .properties
                .iter()
                .map(|prop| match prop {
                    AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(p) => {
                        1 + p.init.as_ref().map(count_expression_units).unwrap_or(0)
                    }
                    AssignmentTargetProperty::AssignmentTargetPropertyProperty(p) => {
                        1 + count_assignment_target_maybe_default_units(&p.binding)
                    }
                })
                .sum::<u32>()
                + o.rest
                    .as_ref()
                    .map(|rest| count_assignment_target_units(&rest.target))
                    .unwrap_or(0)
        }
        _ => 0,
    }
}

fn count_assignment_target_maybe_default_units(target: &AssignmentTargetMaybeDefault) -> u32 {
    match target {
        AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(d) => {
            1 + count_assignment_target_units(&d.binding) + count_expression_units(&d.init)
        }
        _ => target
            .as_assignment_target()
            .map(count_assignment_target_units)
            .unwrap_or(0),
    }
}

fn count_expression_units(expr: &Expression) -> u32 {
    match expr {
        Expression::Identifier(_)
        | Expression::ThisExpression(_)
        | Expression::Super(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::PrivateInExpression(_) => 0,
        Expression::FunctionExpression(f) => 1 + count_function_units(f),
        Expression::ArrowFunctionExpression(f) => 1 + count_arrow_body_units(&f.body),
        Expression::ClassExpression(c) => 1 + count_class_body_units(&c.body),
        Expression::StaticMemberExpression(m) => 1 + count_expression_units(&m.object),
        Expression::ComputedMemberExpression(m) => {
            1 + count_expression_units(&m.object) + count_expression_units(&m.expression)
        }
        Expression::PrivateFieldExpression(m) => 1 + count_expression_units(&m.object),
        Expression::CallExpression(e) => {
            1 + count_expression_units(&e.callee)
                + e.arguments
                    .iter()
                    .map(|arg| arg.as_expression().map(count_expression_units).unwrap_or(0))
                    .sum::<u32>()
        }
        Expression::NewExpression(e) => {
            1 + count_expression_units(&e.callee)
                + e.arguments
                    .iter()
                    .map(|arg| arg.as_expression().map(count_expression_units).unwrap_or(0))
                    .sum::<u32>()
        }
        Expression::AssignmentExpression(e) => {
            1 + count_assignment_target_units(&e.left) + count_expression_units(&e.right)
        }
        Expression::SequenceExpression(e) => {
            1 + e
                .expressions
                .iter()
                .map(count_expression_units)
                .sum::<u32>()
        }
        Expression::ConditionalExpression(e) => {
            1 + count_expression_units(&e.test)
                + count_expression_units(&e.consequent)
                + count_expression_units(&e.alternate)
        }
        Expression::LogicalExpression(e) => {
            1 + count_expression_units(&e.left) + count_expression_units(&e.right)
        }
        Expression::BinaryExpression(e) => {
            1 + count_expression_units(&e.left) + count_expression_units(&e.right)
        }
        Expression::UnaryExpression(e) => 1 + count_expression_units(&e.argument),
        Expression::UpdateExpression(_) => 1,
        Expression::AwaitExpression(e) => 1 + count_expression_units(&e.argument),
        Expression::YieldExpression(e) => {
            1 + e.argument.as_ref().map(count_expression_units).unwrap_or(0)
        }
        Expression::ParenthesizedExpression(e) => count_expression_units(&e.expression),
        Expression::ArrayExpression(e) => {
            1 + e
                .elements
                .iter()
                .map(|element| {
                    element
                        .as_expression()
                        .map(count_expression_units)
                        .unwrap_or(0)
                })
                .sum::<u32>()
        }
        Expression::ObjectExpression(e) => {
            1 + e
                .properties
                .iter()
                .map(|prop| match prop {
                    ObjectPropertyKind::ObjectProperty(p) => 1 + count_expression_units(&p.value),
                    ObjectPropertyKind::SpreadProperty(s) => {
                        1 + count_expression_units(&s.argument)
                    }
                })
                .sum::<u32>()
        }
        Expression::TemplateLiteral(lit) => {
            1 + lit
                .expressions
                .iter()
                .map(count_expression_units)
                .sum::<u32>()
        }
        Expression::TaggedTemplateExpression(e) => {
            1 + count_expression_units(&e.tag)
                + e.quasi
                    .expressions
                    .iter()
                    .map(count_expression_units)
                    .sum::<u32>()
        }
        Expression::ImportExpression(e) => 1 + count_expression_units(&e.source),
        Expression::ChainExpression(e) => 1 + count_chain_element_units(&e.expression),
        Expression::ImportMeta(_) | Expression::NewTarget(_) => 1,
        Expression::JSXElement(_) | Expression::JSXFragment(_) => 1,
        _ => 1,
    }
}

fn count_chain_element_units(element: &ChainElement) -> u32 {
    match element {
        ChainElement::CallExpression(call) => {
            1 + count_expression_units(&call.callee)
                + call
                    .arguments
                    .iter()
                    .map(|arg| arg.as_expression().map(count_expression_units).unwrap_or(0))
                    .sum::<u32>()
        }
        ChainElement::ComputedMemberExpression(m) => {
            1 + count_expression_units(&m.object) + count_expression_units(&m.expression)
        }
        ChainElement::StaticMemberExpression(m) => 1 + count_expression_units(&m.object),
        ChainElement::PrivateFieldExpression(m) => 1 + count_expression_units(&m.object),
        _ => 1,
    }
}

pub fn extract_hashes(source: &str, min_statements: Option<u32>) -> Result<ExtractResult, String> {
    let min_stmts = min_statements.unwrap_or(DEFAULT_MIN_STATEMENTS);
    let allocator = Allocator::default();
    let parse_ret = parse_js(&allocator, source);

    if parse_ret.fatal_error {
        return Err("Parse error: parser panicked".to_string());
    }

    let program = &parse_ret.program;
    let sem_ret = SemanticBuilder::new().build(program);
    let scoping = sem_ret.semantic.scoping();

    let scope_info = ScopeInfo::new(scoping);
    let mut collector = TokenCollector::for_program(scoping, source, &scope_info);
    collector.visit_program(program);
    let file_hash = bytes_to_slh1(&collector.finish());

    let ctx = HashContext {
        source,
        scoping,
        scope_info: &scope_info,
        min_stmts,
    };
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

    Ok(ExtractResult {
        file_hash,
        functions,
    })
}

pub fn extract_detailed_hashes(
    source: &str,
    min_statements: Option<u32>,
) -> Result<DetailedExtractResult, String> {
    let min_stmts = min_statements.unwrap_or(DEFAULT_MIN_STATEMENTS);
    let allocator = Allocator::default();
    let parse_ret = parse_js(&allocator, source);

    if parse_ret.fatal_error {
        return Err("Parse error: parser panicked".to_string());
    }

    let program = &parse_ret.program;
    let sem_ret = SemanticBuilder::new().build(program);
    let scoping = sem_ret.semantic.scoping();

    let scope_info = ScopeInfo::new(scoping);
    let mut collector = TokenCollector::for_program(scoping, source, &scope_info);
    collector.visit_program(program);
    let (file_hash, file_canonical) = collector.finish_with_canonical();

    let ctx = HashContext {
        source,
        scoping,
        scope_info: &scope_info,
        min_stmts,
    };
    let mut raw: Vec<RawFunctionInfo> = Vec::new();
    collect_functions(program, &ctx, &mut raw);

    let line_index = LineIndex::new(source);
    let functions = raw
        .into_iter()
        .map(|r| {
            let pos = span_position(&line_index, source, r.span);
            DetailedFunctionHashInfo {
                hash: bytes_to_slh1(&r.hash),
                canonical: r.canonical,
                name: r.name,
                start_line: pos.start_line,
                start_column: pos.start_column,
                end_line: pos.end_line,
                end_column: pos.end_column,
                stmt_count: r.stmt_count,
            }
        })
        .collect();

    Ok(DetailedExtractResult {
        file_hash: bytes_to_slh1(&file_hash),
        file_canonical,
        functions,
    })
}

#[cfg(feature = "debug-ir")]
pub fn extract_ir(source: &str) -> Result<Vec<String>, String> {
    let allocator = Allocator::default();
    let parse_ret = parse_js(&allocator, source);

    if parse_ret.fatal_error {
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

fn collect_functions(program: &Program, ctx: &HashContext, out: &mut Vec<RawFunctionInfo>) {
    for stmt in &program.body {
        collect_from_statement(stmt, ctx, out);
    }
}

fn collect_from_statement(stmt: &Statement, ctx: &HashContext, out: &mut Vec<RawFunctionInfo>) {
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
            match &s.init {
                Some(ForStatementInit::VariableDeclaration(d)) => {
                    for decl in &d.declarations {
                        if let Some(init_expr) = &decl.init {
                            collect_from_expression(init_expr, ctx, out);
                        }
                    }
                }
                Some(init) => {
                    if let Some(expr) = init.as_expression() {
                        collect_from_expression(expr, ctx, out);
                    }
                }
                None => {}
            }
            if let Some(test) = &s.test {
                collect_from_expression(test, ctx, out);
            }
            if let Some(update) = &s.update {
                collect_from_expression(update, ctx, out);
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
            collect_from_expression(&s.right, ctx, out);
            collect_from_statement(&s.body, ctx, out);
        }
        Statement::ForOfStatement(s) => {
            collect_from_expression(&s.right, ctx, out);
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
        Statement::ExportDefaultDeclaration(d) => match &d.declaration {
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
        },
        Statement::ExportDeclaration(d) => match &d.declaration {
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
        },
        _ => {}
    }
}

fn collect_from_expression(expr: &Expression, ctx: &HashContext, out: &mut Vec<RawFunctionInfo>) {
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
            if let Some(body) = f.get_function_body() {
                for inner in &body.statements {
                    collect_from_statement(inner, ctx, out);
                }
            } else if let Some(expr) = f.get_expression() {
                collect_from_expression(expr, ctx, out);
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
            collect_from_expression(&e.test, ctx, out);
            collect_from_expression(&e.consequent, ctx, out);
            collect_from_expression(&e.alternate, ctx, out);
        }
        Expression::LogicalExpression(e) => {
            collect_from_expression(&e.left, ctx, out);
            collect_from_expression(&e.right, ctx, out);
        }
        Expression::BinaryExpression(e) => {
            collect_from_expression(&e.left, ctx, out);
            collect_from_expression(&e.right, ctx, out);
        }
        Expression::UnaryExpression(e) => {
            collect_from_expression(&e.argument, ctx, out);
        }
        Expression::AwaitExpression(e) => {
            collect_from_expression(&e.argument, ctx, out);
        }
        Expression::YieldExpression(e) => {
            if let Some(arg) = &e.argument {
                collect_from_expression(arg, ctx, out);
            }
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
        Expression::StaticMemberExpression(e) => {
            collect_from_expression(&e.object, ctx, out);
        }
        Expression::ComputedMemberExpression(e) => {
            collect_from_expression(&e.object, ctx, out);
            collect_from_expression(&e.expression, ctx, out);
        }
        Expression::PrivateFieldExpression(e) => {
            collect_from_expression(&e.object, ctx, out);
        }
        Expression::ChainExpression(e) => match &e.expression {
            ChainElement::CallExpression(call) => {
                collect_from_expression(&call.callee, ctx, out);
                for arg in &call.arguments {
                    if let Some(a_expr) = arg.as_expression() {
                        collect_from_expression(a_expr, ctx, out);
                    }
                }
            }
            ChainElement::StaticMemberExpression(m) => {
                collect_from_expression(&m.object, ctx, out);
            }
            ChainElement::ComputedMemberExpression(m) => {
                collect_from_expression(&m.object, ctx, out);
                collect_from_expression(&m.expression, ctx, out);
            }
            ChainElement::PrivateFieldExpression(m) => {
                collect_from_expression(&m.object, ctx, out);
            }
            _ => {}
        },
        Expression::TemplateLiteral(lit) => {
            for inner in &lit.expressions {
                collect_from_expression(inner, ctx, out);
            }
        }
        Expression::TaggedTemplateExpression(e) => {
            collect_from_expression(&e.tag, ctx, out);
            for inner in &e.quasi.expressions {
                collect_from_expression(inner, ctx, out);
            }
        }
        Expression::ImportExpression(e) => {
            collect_from_expression(&e.source, ctx, out);
        }
        _ => {}
    }
}

fn try_hash_function(f: &Function, ctx: &HashContext, out: &mut Vec<RawFunctionInfo>) {
    let body = match &f.body {
        Some(b) => b,
        None => return,
    };
    let stmt_count = body.statements.len() as u32;
    let structural_units = count_function_body_units(body);
    if !meets_min_complexity(stmt_count, structural_units, ctx.min_stmts) {
        return;
    }
    let scope_id = match f.scope_id.get() {
        Some(id) => id,
        None => return,
    };

    let mut collector =
        TokenCollector::for_subtree(ctx.scoping, ctx.source, ctx.scope_info, scope_id);
    collector.visit_function_content(f);
    let (hash, canonical) = collector.finish_with_canonical();

    out.push(RawFunctionInfo {
        hash,
        canonical,
        span: f.span,
        name: f.id.as_ref().map(|id| id.name.to_string()),
        stmt_count,
    });
}

fn try_hash_arrow(f: &ArrowFunctionExpression, ctx: &HashContext, out: &mut Vec<RawFunctionInfo>) {
    let Some(body) = f.get_function_body() else {
        return;
    };
    let stmt_count = body.statements.len() as u32;
    let structural_units = count_function_body_units(body);
    if !meets_min_complexity(stmt_count, structural_units, ctx.min_stmts) {
        return;
    }
    let scope_id = match f.scope_id.get() {
        Some(id) => id,
        None => return,
    };

    let mut collector =
        TokenCollector::for_subtree(ctx.scoping, ctx.source, ctx.scope_info, scope_id);
    collector.visit_arrow_function_content(f);
    let (hash, canonical) = collector.finish_with_canonical();

    out.push(RawFunctionInfo {
        hash,
        canonical,
        span: f.span,
        name: None,
        stmt_count,
    });
}

fn try_hash_class(c: &Class, ctx: &HashContext, out: &mut Vec<RawFunctionInfo>) {
    let stmt_count = c.body.body.len() as u32;
    let structural_units = count_class_body_units(&c.body);
    if !meets_min_complexity(stmt_count, structural_units, ctx.min_stmts) {
        return;
    }
    let scope_id = match c.scope_id.get() {
        Some(id) => id,
        None => return,
    };

    let mut collector =
        TokenCollector::for_subtree(ctx.scoping, ctx.source, ctx.scope_info, scope_id);
    collector.visit_class_content(c);
    let (hash, canonical) = collector.finish_with_canonical();

    out.push(RawFunctionInfo {
        hash,
        canonical,
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
    if parse_ret.fatal_error {
        return None;
    }

    let sem_ret = SemanticBuilder::new().build(&parse_ret.program);
    let scoping = sem_ret.semantic.scoping();

    let scope_info = ScopeInfo::new(scoping);
    let mut collector = TokenCollector::for_program(scoping, source, &scope_info);
    collector.visit_program(&parse_ret.program);
    let file_hash = collector.finish();

    let ctx = HashContext {
        source,
        scoping,
        scope_info: &scope_info,
        min_stmts,
    };
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

    Some(CheckAnalysis {
        file_hash,
        functions,
    })
}
