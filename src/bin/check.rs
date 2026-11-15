//! The conformance project's own fixture validator, for the Rust harness.
//!
//! The protocol judge only ever sees the plugin's statements about the rendered crate. This
//! binary is the second judgment: it reads `src/lib.rs` with `syn` - no protocol, no plugin,
//! no driver build in the path - and confirms each fixture-shaped property from the source
//! that is supposed to realize it. The suite requires the two verdict lists to agree.
//!
//! Contract (docs/harness-authoring.md, section 12): stdout is exactly one JSON
//! `TemplateReport` and nothing else; exit 0 even when a property fails; non-zero only when
//! this validator itself could not run; the seven fixture-shaped ids only.
//!
//! Usage:
//!   afz-rust-check [path/to/src/lib.rs]

use std::io::Write as _;

use serde::Serialize;
use syn::visit::Visit;
use syn::{Expr, Fields, File, ImplItem, Item, Type, Visibility};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckReport {
    version: u32,
    properties: Vec<PropertyResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PropertyResult {
    id: String,
    verdict: String,
    detail: String,
}

fn pass(id: &str, detail: impl Into<String>) -> PropertyResult {
    PropertyResult { id: id.to_string(), verdict: "pass".into(), detail: detail.into() }
}

fn fail(id: &str, detail: impl Into<String>) -> PropertyResult {
    PropertyResult { id: id.to_string(), verdict: "fail".into(), detail: detail.into() }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "src/lib.rs".to_string());
    let report = match std::fs::read_to_string(&path) {
        Ok(text) => match syn::parse_file(&text) {
            Ok(file) => judge(&file, &path),
            Err(e) => {
                // The fixture is not valid Rust: every property is unjudged from source, and
                // the protocol judge will disagree, which is the point of two verdicts.
                let ids = ["crash-unguarded", "guard-refusal", "private-symbol", "unrepresentable-symbol", "unconstructible-receiver", "method-receiver", "coverage-digest-live"];
                CheckReport {
                    version: 1,
                    properties: ids.iter().map(|id| fail(id, format!("{path} does not parse: {e}"))).collect(),
                }
            }
        },
        Err(e) => {
            let message = format!("cannot read {path}: {e}");
            eprintln!("{message}");
            std::process::exit(1);
        }
    };
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{}", serde_json::to_string(&report).expect("a report serializes"));
}

fn judge(file: &File, path: &str) -> CheckReport {
    let functions: Vec<&syn::ItemFn> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) => Some(function),
            _ => None,
        })
        .collect();
    let mut properties = Vec::new();

    properties.push(match functions.iter().find(|f| f.sig.ident == "crash") {
        Some(function) if is_public(function) && contains_index(&function.block) => {
            pass("crash-unguarded", "pub fn crash indexes its input into a fixed vector, so the panic is in fixture source")
        }
        Some(_) => fail("crash-unguarded", "crash is public but does not index into a fixed collection"),
        None => fail("crash-unguarded", format!("{path} declares no fn crash")),
    });

    properties.push(match functions.iter().find(|f| f.sig.ident == "bounded") {
        Some(function) if is_public(function) && returns_result(function) && contains_return_err(&function.block) => {
            pass("guard-refusal", "pub fn bounded validates and returns Err through its declared Result")
        }
        Some(_) => fail("guard-refusal", "bounded exists but is not a public Result-returning guard"),
        None => fail("guard-refusal", format!("{path} declares no fn bounded")),
    });

    properties.push(match functions.iter().find(|f| f.sig.ident == "hidden") {
        Some(function) if !is_public(function) => pass("private-symbol", "fn hidden is not pub and is otherwise fuzzable-shaped"),
        Some(_) => fail("private-symbol", "hidden is public, so its skip would not come from visibility"),
        None => fail("private-symbol", format!("{path} declares no fn hidden")),
    });

    properties.push(match functions.iter().find(|f| f.sig.ident == "callback") {
        Some(function) if is_public(function) && has_bare_fn_parameter(function) => {
            pass("unrepresentable-symbol", "pub fn callback takes a bare fn(..) parameter")
        }
        Some(_) => fail("unrepresentable-symbol", "callback exists but has no unrepresentable parameter"),
        None => fail("unrepresentable-symbol", format!("{path} declares no fn callback")),
    });

    let handle_blocked = file.items.iter().any(|item| match item {
        Item::Struct(item) => {
            item.ident == "Handle"
                && matches!(&item.fields, Fields::Named(named) if named.named.iter().any(|f| !matches!(f.vis, Visibility::Public(_))))
        }
        _ => false,
    });
    let handle_read = has_public_method(file, "Handle", "read");
    properties.push(if handle_blocked && handle_read {
        pass("unconstructible-receiver", "struct Handle has a private field and pub fn read(&self)")
    } else {
        fail("unconstructible-receiver", format!("Handle private field: {handle_blocked}; pub fn Handle::read: {handle_read}"))
    });

    let counter_buildable = file.items.iter().any(|item| match item {
        Item::Struct(item) => {
            item.ident == "Counter"
                && matches!(&item.vis, Visibility::Public(_))
                && matches!(&item.fields, Fields::Named(named) if named.named.iter().all(|f| matches!(f.vis, Visibility::Public(_))))
        }
        _ => false,
    });
    let counter_bump = has_public_method(file, "Counter", "bump");
    properties.push(if counter_buildable && counter_bump {
        pass("method-receiver", "struct Counter is fully public and has pub fn bump")
    } else {
        fail("method-receiver", format!("Counter fully public: {counter_buildable}; pub fn Counter::bump: {counter_bump}"))
    });

    let distinct_callees = functions.iter().find(|f| f.sig.ident == "branch").map(|function| distinct_call_names(&function.block)).unwrap_or_default();
    properties.push(if distinct_callees.len() >= 2 {
        pass("coverage-digest-live", format!("branch dispatches to {} distinct functions, so two inputs execute different sets", distinct_callees.len()))
    } else {
        fail("coverage-digest-live", "branch does not call two distinct functions from its two arms")
    });

    CheckReport { version: 1, properties }
}

fn is_public(function: &syn::ItemFn) -> bool {
    matches!(function.vis, Visibility::Public(_))
}

fn returns_result(function: &syn::ItemFn) -> bool {
    match &function.sig.output {
        syn::ReturnType::Type(_, ty) => matches!(&**ty, Type::Path(path) if path.path.segments.last().is_some_and(|s| s.ident == "Result")),
        _ => false,
    }
}

fn has_bare_fn_parameter(function: &syn::ItemFn) -> bool {
    function.sig.inputs.iter().any(|input| match input {
        syn::FnArg::Typed(argument) => matches!(&*argument.ty, Type::BareFn(_)),
        _ => false,
    })
}

fn has_public_method(file: &File, type_name: &str, method: &str) -> bool {
    file.items.iter().any(|item| match item {
        Item::Impl(impl_block) => {
            let self_name = match &*impl_block.self_ty {
                Type::Path(path) => path.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default(),
                _ => String::new(),
            };
            self_name == type_name
                && impl_block.items.iter().any(|member| match member {
                    ImplItem::Fn(function) => function.sig.ident == method && matches!(function.vis, Visibility::Public(_)),
                    _ => false,
                })
        }
        _ => false,
    })
}

/// Whether the body contains `return Err(...)` - the guard the author wrote.
fn contains_return_err(block: &syn::Block) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr(&mut self, expr: &'ast Expr) {
            if let Expr::Return(ret) = expr {
                if let Some(inner) = &ret.expr {
                    if let Expr::Call(call) = &**inner {
                        if let Expr::Path(path) = &*call.func {
                            if path.path.segments.last().is_some_and(|s| s.ident == "Err") {
                                self.found = true;
                            }
                        }
                    }
                }
            }
            syn::visit::visit_expr(self, expr);
        }
    }
    let mut finder = Finder { found: false };
    finder.visit_block(block);
    finder.found
}

/// Whether the body indexes a collection - the unguarded dereference past the end.
fn contains_index(block: &syn::Block) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr(&mut self, expr: &'ast Expr) {
            if matches!(expr, Expr::Index(_)) {
                self.found = true;
            }
            syn::visit::visit_expr(self, expr);
        }
    }
    let mut finder = Finder { found: false };
    finder.visit_block(block);
    finder.found
}

/// The distinct callee names the body calls, for the branch-shape check.
fn distinct_call_names(block: &syn::Block) -> Vec<String> {
    struct Finder {
        names: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr(&mut self, expr: &'ast Expr) {
            if let Expr::Call(call) = expr {
                if let Expr::Path(path) = &*call.func {
                    let name = path.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                    if !name.is_empty() && !self.names.contains(&name) {
                        self.names.push(name);
                    }
                }
            }
            syn::visit::visit_expr(self, expr);
        }
    }
    let mut finder = Finder { names: Vec::new() };
    finder.visit_block(block);
    finder.names
}
