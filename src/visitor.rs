use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use oxc_ast::ast::*;
use oxc_semantic::{ScopeId, Scoping, SymbolId};
use oxc_span::Span;
use sha2::{Digest, Sha256};

/// Equivalent to JS `name.replace(/[0-9]+/g, "")`.
fn strip_digits(name: &str) -> Cow<'_, str> {
    if name.bytes().any(|b| b.is_ascii_digit()) {
        Cow::Owned(name.chars().filter(|c| !c.is_ascii_digit()).collect())
    } else {
        Cow::Borrowed(name)
    }
}

pub struct ScopeInfo {
    children: HashMap<ScopeId, Vec<ScopeId>>,
    binding_numbers: HashMap<SymbolId, u32>,
}

impl ScopeInfo {
    pub fn new(scoping: &Scoping) -> Self {
        let mut children: HashMap<ScopeId, Vec<ScopeId>> = HashMap::new();
        let mut binding_numbers = HashMap::new();
        for scope_id in scoping.scope_descendants_from_root() {
            if let Some(parent) = scoping.scope_parent_id(scope_id) {
                children.entry(parent).or_default().push(scope_id);
            }
            // Per-scope counter starting at 0, symbols sorted by declaration position.
            let mut symbols: Vec<(SymbolId, Span)> = scoping
                .iter_bindings_in(scope_id)
                .map(|sym_id| (sym_id, scoping.symbol_span(sym_id)))
                .collect();
            symbols.sort_by_key(|(_, span)| span.start);
            for (i, (sym_id, _)) in symbols.iter().enumerate() {
                binding_numbers.insert(*sym_id, i as u32);
            }
        }
        Self { children, binding_numbers }
    }

    fn descendant_scopes(&self, root: ScopeId) -> HashSet<ScopeId> {
        let mut out = HashSet::new();
        let mut stack = vec![root];
        while let Some(current) = stack.pop() {
            out.insert(current);
            if let Some(kids) = self.children.get(&current) {
                stack.extend(kids);
            }
        }
        out
    }
}

pub struct TokenCollector<'a> {
    hasher: Sha256,
    has_previous: bool,
    #[cfg(feature = "debug-ir")]
    pub tokens: Vec<String>,
    scoping: &'a Scoping,
    #[allow(dead_code)]
    source_text: &'a str,
    local_scopes: HashSet<ScopeId>,
    scope_info: &'a ScopeInfo,
    label_numbers: HashMap<String, usize>,
    label_counter: usize,
}

impl<'a> TokenCollector<'a> {
    pub fn for_program(scoping: &'a Scoping, source_text: &'a str, scope_info: &'a ScopeInfo) -> Self {
        let mut local_scopes = HashSet::new();
        for scope_id in scoping.scope_descendants_from_root() {
            local_scopes.insert(scope_id);
        }
        Self {
            hasher: Sha256::new(),
            has_previous: false,
            #[cfg(feature = "debug-ir")]
            tokens: Vec::new(),
            scoping,
            source_text,
            local_scopes,
            scope_info,
            label_numbers: HashMap::new(),
            label_counter: 0,
        }
    }

    pub fn for_subtree(
        scoping: &'a Scoping,
        source_text: &'a str,
        scope_info: &'a ScopeInfo,
        root_scope_id: ScopeId,
    ) -> Self {
        let local_scopes = scope_info.descendant_scopes(root_scope_id);
        Self {
            hasher: Sha256::new(),
            has_previous: false,
            #[cfg(feature = "debug-ir")]
            tokens: Vec::new(),
            scoping,
            source_text,
            local_scopes,
            scope_info,
            label_numbers: HashMap::new(),
            label_counter: 0,
        }
    }

    fn push(&mut self, token: &str) {
        #[cfg(feature = "debug-ir")]
        self.tokens.push(token.to_string());
        self.emit_separator();
        self.escape_to_hasher(token.as_bytes());
    }

    /// Push a token of the form `{prefix}{value}`, only escaping the value part.
    fn push_prefixed(&mut self, prefix: &str, value: &str) {
        #[cfg(feature = "debug-ir")]
        self.tokens.push(format!("{prefix}{value}"));
        self.emit_separator();
        self.hasher.update(prefix.as_bytes());
        self.escape_to_hasher(value.as_bytes());
    }

    fn push_regex(&mut self, pattern: &str, flags: &str) {
        #[cfg(feature = "debug-ir")]
        self.tokens.push(format!("R:{pattern}:{flags}"));
        self.emit_separator();
        self.hasher.update(b"R:");
        self.escape_to_hasher(pattern.as_bytes());
        self.hasher.update(b":");
        self.escape_to_hasher(flags.as_bytes());
    }

    fn push_binding(&mut self, index: u32) {
        #[cfg(feature = "debug-ir")]
        self.tokens.push(format!("L{index}"));
        self.emit_separator();
        self.hasher.update(b"L");
        self.hash_u32(index);
    }

    fn push_label(&mut self, index: usize) {
        #[cfg(feature = "debug-ir")]
        self.tokens.push(format!("$L{index}"));
        self.emit_separator();
        self.hasher.update(b"$L");
        self.hash_u32(index as u32);
    }

    fn emit_separator(&mut self) {
        if self.has_previous {
            self.hasher.update(b",");
        }
        self.has_previous = true;
    }

    fn escape_to_hasher(&mut self, bytes: &[u8]) {
        let mut start = 0;
        for (pos, &b) in bytes.iter().enumerate() {
            if b == b'\\' || b == b',' {
                if start < pos {
                    self.hasher.update(&bytes[start..pos]);
                }
                if b == b'\\' {
                    self.hasher.update(b"\\\\");
                } else {
                    self.hasher.update(b"\\,");
                }
                start = pos + 1;
            }
        }
        if start < bytes.len() {
            self.hasher.update(&bytes[start..]);
        }
    }

    fn hash_u32(&mut self, n: u32) {
        if n == 0 {
            self.hasher.update(b"0");
            return;
        }
        let mut buf = [0u8; 10];
        let mut pos = 10;
        let mut val = n;
        while val > 0 {
            pos -= 1;
            buf[pos] = b'0' + (val % 10) as u8;
            val /= 10;
        }
        self.hasher.update(&buf[pos..]);
    }

    pub fn finish(self) -> [u8; 32] {
        let digest = self.hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest);
        result
    }

    fn is_local_symbol(&self, sym_id: SymbolId) -> bool {
        let scope_id = self.scoping.symbol_scope_id(sym_id);
        self.local_scopes.contains(&scope_id)
    }

    fn is_void_zero(expr: &Expression) -> bool {
        if let Expression::UnaryExpression(e) = expr {
            if e.operator == UnaryOperator::Void {
                if let Expression::NumericLiteral(lit) = &e.argument {
                    return lit.value == 0.0;
                }
            }
        }
        false
    }

    fn is_undefined_ident(expr: &Expression) -> bool {
        if let Expression::Identifier(id) = expr {
            return id.name == "undefined";
        }
        false
    }

    fn emit_identifier_ref(&mut self, ident: &IdentifierReference) {
        self.push("Identifier");
        if let Some(ref_id) = ident.reference_id.get() {
            let reference = self.scoping.get_reference(ref_id);
            if let Some(sym_id) = reference.symbol_id() {
                if self.is_local_symbol(sym_id) {
                    if let Some(&index) = self.scope_info.binding_numbers.get(&sym_id) {
                        self.push_binding(index);
                        return;
                    }
                }
            }
        }
        self.push(&strip_digits(&ident.name));
    }

    fn emit_binding_ident(&mut self, ident: &BindingIdentifier) {
        self.push("Identifier");
        if let Some(sym_id) = ident.symbol_id.get() {
            if self.is_local_symbol(sym_id) {
                if let Some(&index) = self.scope_info.binding_numbers.get(&sym_id) {
                    self.push_binding(index);
                    return;
                }
            }
        }
        self.push(&strip_digits(&ident.name));
    }

    fn emit_label_ident(&mut self, ident: &LabelIdentifier) {
        self.push("Identifier");
        let name = ident.name.to_string();
        if let Some(&num) = self.label_numbers.get(&name) {
            self.push_label(num);
        } else {
            let num = self.label_counter;
            self.label_counter += 1;
            self.label_numbers.insert(name, num);
            self.push_label(num);
        }
    }

    pub fn visit_program(&mut self, program: &Program) {
        self.push("Program");
        for dir in &program.directives {
            self.visit_directive(dir);
        }
        for stmt in &program.body {
            self.visit_statement(stmt);
        }
    }

    fn visit_directive(&mut self, dir: &Directive) {
        self.push("ExpressionStatement");
        self.push("StringLiteral");
        self.push_prefixed("S:", &dir.expression.value);
    }

    pub fn visit_statement(&mut self, stmt: &Statement) {
        match stmt {
            Statement::BlockStatement(s) => self.visit_block_statement(s),
            Statement::BreakStatement(s) => self.visit_break_statement(s),
            Statement::ContinueStatement(s) => self.visit_continue_statement(s),
            Statement::DebuggerStatement(_) => { self.push("DebuggerStatement"); }
            Statement::DoWhileStatement(s) => self.visit_do_while_statement(s),
            Statement::EmptyStatement(_) => {}
            Statement::ExpressionStatement(s) => self.visit_expression_statement(s),
            Statement::ForInStatement(s) => self.visit_for_in_statement(s),
            Statement::ForOfStatement(s) => self.visit_for_of_statement(s),
            Statement::ForStatement(s) => self.visit_for_statement(s),
            Statement::IfStatement(s) => self.visit_if_statement(s),
            Statement::LabeledStatement(s) => self.visit_labeled_statement(s),
            Statement::ReturnStatement(s) => self.visit_return_statement(s),
            Statement::SwitchStatement(s) => self.visit_switch_statement(s),
            Statement::ThrowStatement(s) => self.visit_throw_statement(s),
            Statement::TryStatement(s) => self.visit_try_statement(s),
            Statement::WhileStatement(s) => self.visit_while_statement(s),
            Statement::WithStatement(s) => self.visit_with_statement(s),
            Statement::VariableDeclaration(d) => self.visit_variable_declaration(d),
            Statement::FunctionDeclaration(f) => self.visit_function(f, "FunctionDeclaration"),
            Statement::ClassDeclaration(c) => self.visit_class(c, "ClassDeclaration"),
            Statement::ImportDeclaration(d) => self.visit_import_declaration(d),
            Statement::ExportAllDeclaration(d) => self.visit_export_all_declaration(d),
            Statement::ExportDefaultDeclaration(d) => self.visit_export_default_declaration(d),
            Statement::ExportNamedDeclaration(d) => self.visit_export_named_declaration(d),
            _ => {}
        }
    }

    fn visit_block_statement(&mut self, s: &BlockStatement) {
        self.push("BlockStatement");
        for stmt in &s.body {
            self.visit_statement(stmt);
        }
    }

    fn visit_expression_statement(&mut self, s: &ExpressionStatement) {
        self.push("ExpressionStatement");
        self.visit_expression(&s.expression);
    }

    fn visit_if_statement(&mut self, s: &IfStatement) {
        self.push("IfStatement");
        self.visit_expression(&s.test);
        self.visit_statement(&s.consequent);
        if let Some(alt) = &s.alternate {
            self.visit_statement(alt);
        }
    }

    fn visit_for_statement(&mut self, s: &ForStatement) {
        self.push("ForStatement");
        if let Some(init) = &s.init {
            self.visit_for_statement_init(init);
        }
        if let Some(test) = &s.test {
            self.visit_expression(test);
        }
        if let Some(update) = &s.update {
            self.visit_expression(update);
        }
        self.visit_statement(&s.body);
    }

    fn visit_for_statement_init(&mut self, init: &ForStatementInit) {
        match init {
            ForStatementInit::VariableDeclaration(d) => self.visit_variable_declaration(d),
            _ => {
                if let Some(expr) = init.as_expression() {
                    self.visit_expression(expr);
                }
            }
        }
    }

    fn visit_for_in_statement(&mut self, s: &ForInStatement) {
        self.push("ForInStatement");
        self.visit_for_statement_left(&s.left);
        self.visit_expression(&s.right);
        self.visit_statement(&s.body);
    }

    fn visit_for_of_statement(&mut self, s: &ForOfStatement) {
        self.push("ForOfStatement");
        self.visit_for_statement_left(&s.left);
        self.visit_expression(&s.right);
        self.visit_statement(&s.body);
    }

    fn visit_for_statement_left(&mut self, left: &ForStatementLeft) {
        match left {
            ForStatementLeft::VariableDeclaration(d) => self.visit_variable_declaration(d),
            _ => {
                if let Some(target) = left.as_assignment_target() {
                    self.visit_assignment_target(target);
                }
            }
        }
    }

    fn visit_while_statement(&mut self, s: &WhileStatement) {
        self.push("WhileStatement");
        self.visit_expression(&s.test);
        self.visit_statement(&s.body);
    }

    fn visit_do_while_statement(&mut self, s: &DoWhileStatement) {
        self.push("DoWhileStatement");
        // Babel field order: body before test
        self.visit_statement(&s.body);
        self.visit_expression(&s.test);
    }

    fn visit_switch_statement(&mut self, s: &SwitchStatement) {
        self.push("SwitchStatement");
        self.visit_expression(&s.discriminant);
        for case in &s.cases {
            self.visit_switch_case(case);
        }
    }

    fn visit_switch_case(&mut self, c: &SwitchCase) {
        self.push("SwitchCase");
        if let Some(test) = &c.test {
            self.visit_expression(test);
        }
        for stmt in &c.consequent {
            self.visit_statement(stmt);
        }
    }

    fn visit_return_statement(&mut self, s: &ReturnStatement) {
        self.push("ReturnStatement");
        if let Some(arg) = &s.argument {
            if Self::is_void_zero(arg) || Self::is_undefined_ident(arg) {
                return;
            }
            self.visit_expression(arg);
        }
    }

    fn visit_throw_statement(&mut self, s: &ThrowStatement) {
        self.push("ThrowStatement");
        self.visit_expression(&s.argument);
    }

    fn visit_try_statement(&mut self, s: &TryStatement) {
        self.push("TryStatement");
        self.visit_block_statement(&s.block);
        if let Some(handler) = &s.handler {
            self.visit_catch_clause(handler);
        }
        if let Some(finalizer) = &s.finalizer {
            self.visit_block_statement(finalizer);
        }
    }

    fn visit_catch_clause(&mut self, c: &CatchClause) {
        self.push("CatchClause");
        if let Some(param) = &c.param {
            self.visit_binding_pattern(&param.pattern);
        }
        self.visit_block_statement(&c.body);
    }

    fn visit_labeled_statement(&mut self, s: &LabeledStatement) {
        self.push("LabeledStatement");
        self.emit_label_ident(&s.label);
        self.visit_statement(&s.body);
    }

    fn visit_break_statement(&mut self, s: &BreakStatement) {
        self.push("BreakStatement");
        if let Some(label) = &s.label {
            self.emit_label_ident(label);
        }
    }

    fn visit_continue_statement(&mut self, s: &ContinueStatement) {
        self.push("ContinueStatement");
        if let Some(label) = &s.label {
            self.emit_label_ident(label);
        }
    }

    fn visit_with_statement(&mut self, s: &WithStatement) {
        self.push("WithStatement");
        self.visit_expression(&s.object);
        self.visit_statement(&s.body);
    }

    fn visit_variable_declaration(&mut self, d: &VariableDeclaration) {
        self.push("VariableDeclaration");
        for decl in &d.declarations {
            self.visit_variable_declarator(decl);
        }
    }

    fn visit_variable_declarator(&mut self, d: &VariableDeclarator) {
        self.push("VariableDeclarator");
        self.visit_binding_pattern(&d.id);
        if let Some(init) = &d.init {
            self.visit_expression(init);
        }
    }

    pub fn visit_function(&mut self, f: &Function, type_name: &str) {
        self.push(type_name);
        if let Some(id) = &f.id {
            self.emit_binding_ident(id);
        }
        self.visit_formal_parameters(&f.params);
        if let Some(body) = &f.body {
            self.visit_function_body(body);
        }
    }

    /// Hash entry-point for a standalone function: omits the type token and name identifier.
    /// Used by extractHashes / checkScript so the hash covers only params + body.
    pub fn visit_function_content(&mut self, f: &Function) {
        self.visit_formal_parameters(&f.params);
        if let Some(body) = &f.body {
            self.visit_function_body(body);
        }
    }

    pub fn visit_arrow_function(&mut self, f: &ArrowFunctionExpression) {
        self.push("ArrowFunctionExpression");
        self.visit_formal_parameters(&f.params);
        // Normalize both arrow body forms to emit just the expression:
        //   (x) => expr             -> Arrow, [params], [expr]
        //   (x) => { return expr; } -> Arrow, [params], [expr]
        if f.body.directives.is_empty() && f.body.statements.len() == 1 {
            match &f.body.statements[0] {
                Statement::ExpressionStatement(es) => {
                    self.visit_expression(&es.expression);
                    return;
                }
                Statement::ReturnStatement(ret) => {
                    if let Some(arg) = &ret.argument {
                        if !Self::is_void_zero(arg) && !Self::is_undefined_ident(arg) {
                            self.visit_expression(arg);
                            return;
                        }
                    }
                }
                _ => {}
            }
        }
        self.visit_function_body(&f.body);
    }

    /// Hash entry-point for a standalone arrow function: omits the type token.
    pub fn visit_arrow_function_content(&mut self, f: &ArrowFunctionExpression) {
        self.visit_formal_parameters(&f.params);
        if f.body.directives.is_empty() && f.body.statements.len() == 1 {
            match &f.body.statements[0] {
                Statement::ExpressionStatement(es) => {
                    self.visit_expression(&es.expression);
                    return;
                }
                Statement::ReturnStatement(ret) => {
                    if let Some(arg) = &ret.argument {
                        if !Self::is_void_zero(arg) && !Self::is_undefined_ident(arg) {
                            self.visit_expression(arg);
                            return;
                        }
                    }
                }
                _ => {}
            }
        }
        self.visit_function_body(&f.body);
    }

    fn visit_formal_parameters(&mut self, params: &FormalParameters) {
        // Babel flattens FormalParameters: each param is visited directly
        for param in &params.items {
            self.visit_formal_parameter(param);
        }
        if let Some(rest) = &params.rest {
            self.visit_binding_rest_element(&rest.rest);
        }
    }

    fn visit_formal_parameter(&mut self, param: &FormalParameter) {
        // Babel has no FormalParameter wrapper; default value -> AssignmentPattern
        if let Some(init) = &param.initializer {
            self.push("AssignmentPattern");
            self.visit_binding_pattern(&param.pattern);
            self.visit_expression(init);
        } else {
            self.visit_binding_pattern(&param.pattern);
        }
    }

    fn visit_function_body(&mut self, body: &FunctionBody) {
        self.push("BlockStatement");
        for dir in &body.directives {
            self.visit_directive(dir);
        }
        for stmt in &body.statements {
            self.visit_statement(stmt);
        }
    }

    pub fn visit_class(&mut self, c: &Class, type_name: &str) {
        self.push(type_name);
        // Babel field order: decorators, id, superClass, body
        for dec in &c.decorators {
            self.visit_decorator(dec);
        }
        if let Some(id) = &c.id {
            self.emit_binding_ident(id);
        }
        if let Some(super_class) = &c.super_class {
            self.visit_expression(super_class);
        }
        self.visit_class_body(&c.body);
    }

    /// Hash entry-point for a standalone class: omits the type token and name identifier.
    pub fn visit_class_content(&mut self, c: &Class) {
        for dec in &c.decorators {
            self.visit_decorator(dec);
        }
        if let Some(super_class) = &c.super_class {
            self.visit_expression(super_class);
        }
        self.visit_class_body(&c.body);
    }

    fn visit_decorator(&mut self, d: &Decorator) {
        self.push("Decorator");
        self.visit_expression(&d.expression);
    }

    fn visit_class_body(&mut self, body: &ClassBody) {
        self.push("ClassBody");
        for element in &body.body {
            self.visit_class_element(element);
        }
    }

    fn visit_class_element(&mut self, element: &ClassElement) {
        match element {
            ClassElement::MethodDefinition(m) => self.visit_method_definition(m),
            ClassElement::PropertyDefinition(p) => self.visit_property_definition(p),
            ClassElement::StaticBlock(s) => self.visit_static_block(s),
            ClassElement::AccessorProperty(a) => self.visit_accessor_property(a),
            ClassElement::TSIndexSignature(_) => {}
        }
    }

    fn visit_method_definition(&mut self, m: &MethodDefinition) {
        // Babel: ClassMethod / ClassPrivateMethod (unwraps FunctionExpression)
        let is_private = matches!(&m.key, PropertyKey::PrivateIdentifier(_));
        if is_private {
            self.push("ClassPrivateMethod");
        } else {
            self.push("ClassMethod");
        }
        for dec in &m.decorators {
            self.visit_decorator(dec);
        }
        self.visit_property_key(&m.key);
        // Unwrap: Babel has params/body directly on ClassMethod
        self.visit_formal_parameters(&m.value.params);
        if let Some(body) = &m.value.body {
            self.visit_function_body(body);
        }
    }

    fn visit_property_definition(&mut self, p: &PropertyDefinition) {
        // Babel: ClassProperty / ClassPrivateProperty
        let is_private = matches!(&p.key, PropertyKey::PrivateIdentifier(_));
        if is_private {
            self.push("ClassPrivateProperty");
        } else {
            self.push("ClassProperty");
        }
        for dec in &p.decorators {
            self.visit_decorator(dec);
        }
        self.visit_property_key(&p.key);
        if let Some(value) = &p.value {
            self.visit_expression(value);
        }
    }

    fn visit_static_block(&mut self, s: &StaticBlock) {
        self.push("StaticBlock");
        for stmt in &s.body {
            self.visit_statement(stmt);
        }
    }

    fn visit_accessor_property(&mut self, a: &AccessorProperty) {
        self.push("ClassAccessorProperty");
        for dec in &a.decorators {
            self.visit_decorator(dec);
        }
        self.visit_property_key(&a.key);
        if let Some(value) = &a.value {
            self.visit_expression(value);
        }
    }

    pub fn visit_expression(&mut self, expr: &Expression) {
        match expr {
            Expression::BooleanLiteral(lit) => {
                self.push("BooleanLiteral");
                self.push(if lit.value { "B:true" } else { "B:false" });
            }
            Expression::NullLiteral(_) => {
                self.push("NullLiteral");
                self.push("NULL");
            }
            Expression::NumericLiteral(lit) => {
                self.push("NumericLiteral");
                self.push_prefixed("N:", &format_number(lit.value));
            }
            Expression::BigIntLiteral(lit) => {
                self.push("BigIntLiteral");
                self.push_prefixed("I:", &format!("{}", lit.value));
            }
            Expression::RegExpLiteral(lit) => {
                self.push("RegExpLiteral");
                let flags = lit.regex.flags.to_string();
                self.push_regex(&lit.regex.pattern.text, &flags);
            }
            Expression::StringLiteral(lit) => {
                self.push("StringLiteral");
                self.push_prefixed("S:", &lit.value);
            }
            Expression::TemplateLiteral(lit) => {
                self.visit_template_literal(lit);
            }

            Expression::Identifier(ident) => {
                self.emit_identifier_ref(ident);
            }

            Expression::MetaProperty(m) => {
                self.push("MetaProperty");
                self.push("Identifier");
                self.push(&strip_digits(&m.meta.name));
                self.push("Identifier");
                self.push(&strip_digits(&m.property.name));
            }
            Expression::Super(_) => {
                self.push("Super");
            }
            Expression::ThisExpression(_) => {
                self.push("ThisExpression");
            }

            Expression::ArrayExpression(e) => self.visit_array_expression(e),
            Expression::ArrowFunctionExpression(f) => self.visit_arrow_function(f),
            Expression::AssignmentExpression(e) => self.visit_assignment_expression(e),
            Expression::AwaitExpression(e) => {
                self.push("AwaitExpression");
                self.visit_expression(&e.argument);
            }
            Expression::BinaryExpression(e) => self.visit_binary_expression(e),
            Expression::CallExpression(e) => self.visit_call_expression(e, false),
            Expression::ChainExpression(e) => self.visit_chain_expression(e),
            Expression::ClassExpression(c) => self.visit_class(c, "ClassExpression"),
            Expression::ConditionalExpression(e) => self.visit_conditional_expression(e),
            Expression::FunctionExpression(f) => self.visit_function(f, "FunctionExpression"),
            Expression::ImportExpression(e) => {
                self.push("ImportExpression");
                self.visit_expression(&e.source);
            }
            Expression::LogicalExpression(e) => self.visit_logical_expression(e),
            Expression::NewExpression(e) => self.visit_new_expression(e),
            Expression::ObjectExpression(e) => self.visit_object_expression(e),
            Expression::ParenthesizedExpression(e) => {
                // Babel strips parens (preserve_parens=false), so no node emitted
                self.visit_expression(&e.expression);
            }
            Expression::SequenceExpression(e) => {
                self.push("SequenceExpression");
                for expr in &e.expressions {
                    self.visit_expression(expr);
                }
            }
            Expression::TaggedTemplateExpression(e) => {
                self.push("TaggedTemplateExpression");
                self.visit_expression(&e.tag);
                self.visit_template_literal(&e.quasi);
            }
            Expression::UnaryExpression(e) => {
                // Normalize: !0 -> true, !1 -> false, void 0 -> undefined
                if e.operator == UnaryOperator::LogicalNot {
                    if let Expression::NumericLiteral(lit) = &e.argument {
                        if lit.value == 0.0 {
                            self.push("BooleanLiteral");
                            self.push("B:true");
                            return;
                        } else if lit.value == 1.0 {
                            self.push("BooleanLiteral");
                            self.push("B:false");
                            return;
                        }
                    }
                }
                if e.operator == UnaryOperator::Void {
                    if let Expression::NumericLiteral(lit) = &e.argument {
                        if lit.value == 0.0 {
                            self.push("Identifier");
                            self.push("undefined");
                            return;
                        }
                    }
                }
                self.push("UnaryExpression");
                self.push(e.operator.as_str());
                self.visit_expression(&e.argument);
            }
            Expression::UpdateExpression(e) => {
                self.push("UpdateExpression");
                self.push(e.operator.as_str());
                self.visit_simple_assignment_target(&e.argument);
            }
            Expression::YieldExpression(e) => {
                self.push("YieldExpression");
                if let Some(arg) = &e.argument {
                    self.visit_expression(arg);
                }
            }
            Expression::PrivateInExpression(e) => {
                self.push("BinaryExpression");
                self.visit_private_identifier(&e.left);
                self.visit_expression(&e.right);
            }

            Expression::ComputedMemberExpression(m) => self.visit_computed_member(m, false),
            Expression::StaticMemberExpression(m) => self.visit_static_member(m, false),
            Expression::PrivateFieldExpression(m) => self.visit_private_field(m, false),

            _ => {}
        }
    }

    fn visit_template_literal(&mut self, lit: &TemplateLiteral) {
        if lit.expressions.is_empty() && lit.quasis.len() == 1 {
            self.push("StringLiteral");
            self.push_prefixed("S:", &lit.quasis[0].value.raw);
            return;
        }
        self.push("TemplateLiteral");
        for quasi in &lit.quasis {
            self.push("TemplateElement");
            self.push_prefixed("T:", &quasi.value.raw);
        }
        for expr in &lit.expressions {
            self.visit_expression(expr);
        }
    }

    fn visit_array_expression(&mut self, e: &ArrayExpression) {
        self.push("ArrayExpression");
        for element in &e.elements {
            match element {
                ArrayExpressionElement::SpreadElement(s) => {
                    self.push("SpreadElement");
                    self.visit_expression(&s.argument);
                }
                ArrayExpressionElement::Elision(_) => {
                }
                _ => {
                    if let Some(expr) = element.as_expression() {
                        self.visit_expression(expr);
                    }
                }
            }
        }
    }

    fn visit_object_expression(&mut self, e: &ObjectExpression) {
        self.push("ObjectExpression");

        // Sort properties by key name for hash stability
        let mut props_with_keys: Vec<(String, usize)> = e
            .properties
            .iter()
            .enumerate()
            .map(|(i, prop)| {
                let key = match prop {
                    ObjectPropertyKind::ObjectProperty(p) => self.property_sort_key(&p.key, p.computed),
                    ObjectPropertyKind::SpreadProperty(_) => String::new(),
                };
                (key, i)
            })
            .collect();

        props_with_keys.sort_by(|a, b| a.0.cmp(&b.0));

        for (_, idx) in props_with_keys {
            match &e.properties[idx] {
                ObjectPropertyKind::ObjectProperty(p) => self.visit_object_property(p),
                ObjectPropertyKind::SpreadProperty(s) => {
                    self.push("SpreadElement");
                    self.visit_expression(&s.argument);
                }
            }
        }
    }

    fn property_sort_key(&self, key: &PropertyKey, computed: bool) -> String {
        if computed {
            return String::new();
        }
        match key {
            PropertyKey::StaticIdentifier(id) => id.name.to_string(),
            _ => {
                if let Some(expr) = key.as_expression() {
                    match expr {
                        Expression::StringLiteral(s) => s.value.to_string(),
                        Expression::NumericLiteral(n) => format_number(n.value),
                        _ => String::new(),
                    }
                } else {
                    String::new()
                }
            }
        }
    }

    fn visit_object_property(&mut self, p: &ObjectProperty) {
        // Babel: method/getter/setter -> ObjectMethod (unwraps FunctionExpression)
        let is_method = p.method || p.kind != PropertyKind::Init;
        if is_method {
            self.push("ObjectMethod");
            self.visit_property_key(&p.key);
            if let Expression::FunctionExpression(func) = &p.value {
                self.visit_formal_parameters(&func.params);
                if let Some(body) = &func.body {
                    self.visit_function_body(body);
                }
            }
        } else {
            self.push("ObjectProperty");
            self.visit_property_key(&p.key);
            self.visit_expression(&p.value);
        }
    }

    fn visit_property_key(&mut self, key: &PropertyKey) {
        match key {
            PropertyKey::StaticIdentifier(id) => {
                self.push("Identifier");
                self.push(&strip_digits(&id.name));
            }
            PropertyKey::PrivateIdentifier(id) => {
                self.visit_private_identifier(id);
            }
            _ => {
                if let Some(expr) = key.as_expression() {
                    // Normalize: {"catch": v} and {catch: v} emit the same tokens
                    if let Expression::StringLiteral(s) = expr {
                        self.push("Identifier");
                        self.push(&strip_digits(&s.value));
                        return;
                    }
                    self.visit_expression(expr);
                }
            }
        }
    }

    fn visit_private_identifier(&mut self, id: &PrivateIdentifier) {
        self.push("PrivateName");
        self.push("Identifier");
        self.push(&strip_digits(&id.name));
    }

    fn visit_assignment_expression(&mut self, e: &AssignmentExpression) {
        self.push("AssignmentExpression");
        self.push(e.operator.as_str());
        self.visit_assignment_target(&e.left);
        self.visit_expression(&e.right);
    }

    fn visit_binary_expression(&mut self, e: &BinaryExpression) {
        self.push("BinaryExpression");
        self.push(e.operator.as_str());
        self.visit_expression(&e.left);
        self.visit_expression(&e.right);
    }

    fn visit_logical_expression(&mut self, e: &LogicalExpression) {
        self.push("LogicalExpression");
        self.push(e.operator.as_str());
        self.visit_expression(&e.left);
        self.visit_expression(&e.right);
    }

    fn visit_conditional_expression(&mut self, e: &ConditionalExpression) {
        self.push("ConditionalExpression");
        self.visit_expression(&e.test);
        self.visit_expression(&e.consequent);
        self.visit_expression(&e.alternate);
    }

    fn visit_call_expression(&mut self, e: &CallExpression, in_chain: bool) {
        if in_chain {
            self.push("OptionalCallExpression");
        } else {
            self.push("CallExpression");
        }
        self.visit_expression(&e.callee);
        for arg in &e.arguments {
            self.visit_argument(arg);
        }
    }

    fn visit_new_expression(&mut self, e: &NewExpression) {
        self.push("NewExpression");
        self.visit_expression(&e.callee);
        for arg in &e.arguments {
            self.visit_argument(arg);
        }
    }

    fn visit_argument(&mut self, arg: &Argument) {
        match arg {
            Argument::SpreadElement(s) => {
                self.push("SpreadElement");
                self.visit_expression(&s.argument);
            }
            _ => {
                if let Some(expr) = arg.as_expression() {
                    self.visit_expression(expr);
                }
            }
        }
    }

    fn visit_static_member(&mut self, m: &StaticMemberExpression, in_chain: bool) {
        if in_chain {
            self.push("OptionalMemberExpression");
        } else {
            self.push("MemberExpression");
        }
        self.visit_expression(&m.object);
        // Static property is always a free identifier (not a binding)
        self.push("Identifier");
        self.push(&strip_digits(&m.property.name));
    }

    fn visit_computed_member(&mut self, m: &ComputedMemberExpression, in_chain: bool) {
        if in_chain {
            self.push("OptionalMemberExpression");
        } else {
            self.push("MemberExpression");
        }
        self.visit_expression(&m.object);
        // Normalize: obj["foo"] -> same as obj.foo
        if let Expression::StringLiteral(s) = &m.expression {
            self.push("Identifier");
            self.push(&strip_digits(&s.value));
            return;
        }
        self.visit_expression(&m.expression);
    }

    fn visit_private_field(&mut self, m: &PrivateFieldExpression, in_chain: bool) {
        if in_chain {
            self.push("OptionalMemberExpression");
        } else {
            self.push("MemberExpression");
        }
        self.visit_expression(&m.object);
        self.visit_private_identifier(&m.field);
    }

    fn visit_chain_expression(&mut self, e: &ChainExpression) {
        // Babel has no ChainExpression; uses Optional* node types directly
        match &e.expression {
            ChainElement::CallExpression(call) => self.visit_call_expression(call, true),
            ChainElement::ComputedMemberExpression(m) => self.visit_computed_member(m, true),
            ChainElement::StaticMemberExpression(m) => self.visit_static_member(m, true),
            ChainElement::PrivateFieldExpression(m) => self.visit_private_field(m, true),
            _ => {}
        }
    }

    fn visit_binding_pattern(&mut self, pattern: &BindingPattern) {
        match pattern {
            BindingPattern::BindingIdentifier(id) => {
                self.emit_binding_ident(id);
            }
            BindingPattern::ObjectPattern(p) => {
                self.push("ObjectPattern");
                for prop in &p.properties {
                    self.visit_binding_property(prop);
                }
                if let Some(rest) = &p.rest {
                    self.visit_binding_rest_element(rest);
                }
            }
            BindingPattern::ArrayPattern(p) => {
                self.push("ArrayPattern");
                for element in &p.elements {
                    if let Some(pat) = element {
                        self.visit_binding_pattern(pat);
                    }
                }
                if let Some(rest) = &p.rest {
                    self.visit_binding_rest_element(rest);
                }
            }
            BindingPattern::AssignmentPattern(p) => {
                self.push("AssignmentPattern");
                self.visit_binding_pattern(&p.left);
                self.visit_expression(&p.right);
            }
        }
    }

    fn visit_binding_property(&mut self, prop: &BindingProperty) {
        self.push("ObjectProperty");
        self.visit_property_key(&prop.key);
        self.visit_binding_pattern(&prop.value);
    }

    fn visit_binding_rest_element(&mut self, rest: &BindingRestElement) {
        self.push("RestElement");
        self.visit_binding_pattern(&rest.argument);
    }

    fn visit_simple_assignment_target(&mut self, target: &SimpleAssignmentTarget) {
        match target {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(id) => {
                self.emit_identifier_ref(id);
            }
            SimpleAssignmentTarget::ComputedMemberExpression(m) => {
                self.visit_computed_member(m, false);
            }
            SimpleAssignmentTarget::StaticMemberExpression(m) => {
                self.visit_static_member(m, false);
            }
            SimpleAssignmentTarget::PrivateFieldExpression(m) => {
                self.visit_private_field(m, false);
            }
            _ => {}
        }
    }

    fn visit_assignment_target(&mut self, target: &AssignmentTarget) {
        match target {
            AssignmentTarget::AssignmentTargetIdentifier(id) => {
                self.emit_identifier_ref(id);
            }
            AssignmentTarget::ComputedMemberExpression(m) => {
                self.visit_computed_member(m, false);
            }
            AssignmentTarget::StaticMemberExpression(m) => {
                self.visit_static_member(m, false);
            }
            AssignmentTarget::PrivateFieldExpression(m) => {
                self.visit_private_field(m, false);
            }
            AssignmentTarget::ArrayAssignmentTarget(a) => {
                self.push("ArrayPattern");
                for element in &a.elements {
                    if let Some(el) = element {
                        self.visit_assignment_target_maybe_default(el);
                    }
                }
                if let Some(rest) = &a.rest {
                    self.push("RestElement");
                    self.visit_assignment_target(&rest.target);
                }
            }
            AssignmentTarget::ObjectAssignmentTarget(o) => {
                self.push("ObjectPattern");
                for prop in &o.properties {
                    self.visit_assignment_target_property(prop);
                }
                if let Some(rest) = &o.rest {
                    self.push("RestElement");
                    self.visit_assignment_target(&rest.target);
                }
            }
            _ => {}
        }
    }

    fn visit_assignment_target_maybe_default(&mut self, target: &AssignmentTargetMaybeDefault) {
        match target {
            AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(d) => {
                self.push("AssignmentPattern");
                self.visit_assignment_target(&d.binding);
                self.visit_expression(&d.init);
            }
            _ => {
                if let Some(t) = target.as_assignment_target() {
                    self.visit_assignment_target(t);
                }
            }
        }
    }

    fn visit_assignment_target_property(&mut self, prop: &AssignmentTargetProperty) {
        match prop {
            AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(p) => {
                self.push("ObjectProperty");
                // Shorthand: key = value = identifier
                self.emit_identifier_ref(&p.binding);
                if let Some(init) = &p.init {
                    self.push("AssignmentPattern");
                    self.emit_identifier_ref(&p.binding);
                    self.visit_expression(init);
                }
            }
            AssignmentTargetProperty::AssignmentTargetPropertyProperty(p) => {
                self.push("ObjectProperty");
                self.visit_property_key(&p.name);
                self.visit_assignment_target_maybe_default(&p.binding);
            }
        }
    }

    fn visit_import_declaration(&mut self, d: &ImportDeclaration) {
        self.push("ImportDeclaration");
        // Babel: specifiers before source
        if let Some(specifiers) = &d.specifiers {
            for spec in specifiers {
                match spec {
                    ImportDeclarationSpecifier::ImportSpecifier(s) => {
                        self.push("ImportSpecifier");
                        self.visit_module_export_name(&s.imported);
                        self.emit_binding_ident(&s.local);
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                        self.push("ImportDefaultSpecifier");
                        self.emit_binding_ident(&s.local);
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                        self.push("ImportNamespaceSpecifier");
                        self.emit_binding_ident(&s.local);
                    }
                }
            }
        }
        self.push("StringLiteral");
        self.push_prefixed("S:", &d.source.value);
    }

    fn visit_export_named_declaration(&mut self, d: &ExportNamedDeclaration) {
        self.push("ExportNamedDeclaration");
        if let Some(decl) = &d.declaration {
            match decl {
                Declaration::VariableDeclaration(v) => self.visit_variable_declaration(v),
                Declaration::FunctionDeclaration(f) => self.visit_function(f, "FunctionDeclaration"),
                Declaration::ClassDeclaration(c) => self.visit_class(c, "ClassDeclaration"),
                _ => {}
            }
        }
        for spec in &d.specifiers {
            self.push("ExportSpecifier");
            self.visit_module_export_name(&spec.local);
            self.visit_module_export_name(&spec.exported);
        }
        if let Some(source) = &d.source {
            self.push("StringLiteral");
            self.push_prefixed("S:", &source.value);
        }
    }

    fn visit_export_default_declaration(&mut self, d: &ExportDefaultDeclaration) {
        self.push("ExportDefaultDeclaration");
        match &d.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(f) => {
                self.visit_function(f, "FunctionDeclaration");
            }
            ExportDefaultDeclarationKind::ClassDeclaration(c) => {
                self.visit_class(c, "ClassDeclaration");
            }
            _ => {
                if let Some(expr) = d.declaration.as_expression() {
                    self.visit_expression(expr);
                }
            }
        }
    }

    fn visit_export_all_declaration(&mut self, d: &ExportAllDeclaration) {
        self.push("ExportAllDeclaration");
        self.push("StringLiteral");
        self.push_prefixed("S:", &d.source.value);
    }

    fn visit_module_export_name(&mut self, name: &ModuleExportName) {
        match name {
            ModuleExportName::IdentifierName(id) => {
                self.push("Identifier");
                self.push(&strip_digits(&id.name));
            }
            ModuleExportName::IdentifierReference(id) => {
                self.emit_identifier_ref(id);
            }
            ModuleExportName::StringLiteral(s) => {
                self.push("StringLiteral");
                self.push_prefixed("S:", &s.value);
            }
        }
    }
}

/// Format a number for the hash token. Uses JS-like formatting.
fn format_number(value: f64) -> String {
    if value.fract() == 0.0 && value.is_finite() && value.abs() < 1e20 {
        format!("{}", value as i64)
    } else {
        format!("{}", value)
    }
}
