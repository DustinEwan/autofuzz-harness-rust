//! Discovery: parse Rust sources with `syn`, never compile.
//!
//! The scan walks the request root for `Cargo.toml` files, reads each package's lib target as
//! a module tree, and reports every function it finds: public free functions, inherent
//! methods, and `Self`-less associated functions with constructible parameters become targets,
//! and everything else is reported in `skipped` with a reason. A symbol is never dropped
//! silently.
//!
//! The same parse also produces the coverage universe: every function in every parsed file,
//! public and private, with its byte range. The coverage denominator is "functions declared in
//! a file discovery parsed", so the private functions have to be in it.

use std::collections::HashMap;
use std::ops::Range;
use std::path::{Path, PathBuf};

use afz_protocol::{
    Blocker, Discovery, DiscoverReq, Effects, Materialization, Origin, Parameter, SkipReason, SkippedTarget,
    TargetClass, TargetDescriptor,
};
use quote::ToTokens;
use sha2::{Digest as _, Sha256};
use syn::visit::Visit;
use syn::spanned::Spanned;
use syn::{File, ImplItem, Item, ItemFn, ItemImpl, Type, Visibility};

use crate::lower::{self, BlockedWhy, Build, Ctx, FieldDef, PassMode, TypeDef, TypeKind, VariantDef, Wrap};

/// Directories no scan wants: build caches, VCS state, scan output, dependency trees.
const SKIPPED_DIRS: &[&str] = &["target", ".git", ".autofuzz", "node_modules"];
const MAX_DEPTH: u32 = 8;

/// One lib package found under the scan root.
#[derive(Debug, Clone)]
pub struct Package {
    /// The crate name with `-` replaced by `_`, the path segment a call starts with.
    pub name: String,
    /// The name as its own `Cargo.toml` spells it, the key the driver's dependency table needs.
    pub manifest_name: String,
    pub root: PathBuf,
    pub lib_rs: PathBuf,
}

/// One function in the coverage universe, keyed by its demangled name.
#[derive(Debug, Clone)]
pub struct UniFn {
    pub file: String,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone)]
pub struct ParamSpec {
    pub build: Build,
    pub mode: PassMode,
    pub wrap: Wrap,
    pub receiver: ReceiverKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverKind {
    None,
    Ref,
    RefMut,
    Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetShape {
    Plain,
    Result,
    Option,
}

/// One fuzzable call, with everything the driver generator and the invoke path need.
#[derive(Debug, Clone)]
pub struct Tgt {
    pub id: String,
    pub name: String,
    /// The full Rust path the driver calls: `afz_engine::git::parse` or
    /// `afz_engine::corpus::Corpus::insert`.
    pub call_path: String,
    pub params: Vec<ParamSpec>,
    pub ret: RetShape,
    pub unsafe_call: bool,
    pub descriptor: TargetDescriptor,
}

/// Everything one `discover` learned, kept for `prepare`, `invoke`, `reproducer`, and
/// `coverageMap`.
pub struct Inventory {
    pub root: PathBuf,
    pub discovery: Discovery,
    pub targets: Vec<Tgt>,
    pub universe: HashMap<String, UniFn>,
    /// Path dependencies the generated driver needs: one per discovered package.
    pub packages: Vec<Package>,
}

/// Run discovery for one request.
pub fn discover(req: &DiscoverReq) -> Result<Inventory, String> {
    let root = std::fs::canonicalize(&req.root).map_err(|e| format!("{}: {e}", req.root))?;
    let packages = find_packages(&root);
    let mut inventory =
        Inventory { root, discovery: Discovery::default(), targets: Vec::new(), universe: HashMap::new(), packages };
    if inventory.packages.is_empty() {
        return Ok(inventory);
    }

    let mut files: Vec<ParsedFile> = Vec::new();
    for package in &inventory.packages {
        parse_crate(package, &mut files);
    }

    // The type index spans every parsed package: a path dependency's types are outside it and
    // stay blocked, which is the whole point of parsing only the scan's own tree.
    let mut types: HashMap<String, TypeDef> = HashMap::new();
    for file in &files {
        index_types(file, &mut types);
    }

    for file in &files {
        collect_universe_items(&file.file.items, file, &file.mod_path, &mut inventory.universe);
        let excluded = match_excludes(req, &file.rel);
        let included = match_includes(req, &file.rel);
        collect_items(&file.file.items, file, &file.mod_path, file.reachable, excluded, included, &types, &mut inventory);
    }

    inventory.discovery.targets.sort_by(|a, b| a.id.cmp(&b.id));
    inventory.discovery.skipped.sort_by(|a, b| a.name.cmp(&b.name).then(a.target_id.cmp(&b.target_id)));
    inventory.targets.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(inventory)
}

fn find_packages(root: &Path) -> Vec<Package> {
    let mut manifests = Vec::new();
    collect_manifests(root, 0, &mut manifests);
    manifests.sort();
    let mut found = Vec::new();
    for manifest in manifests {
        let Ok(text) = std::fs::read_to_string(&manifest) else { continue };
        let Some((name, lib)) = package_lib_target(&text) else { continue };
        let dir = manifest.parent().map(Path::to_path_buf).unwrap_or_default();
        let lib_rs = match lib {
            Some(rel) => dir.join(rel),
            None => dir.join("src").join("lib.rs"),
        };
        if !lib_rs.is_file() {
            // A package with no lib target contributes nothing: `[[bin]]` items are not
            // reachable from outside their crate.
            continue;
        }
        found.push(Package { name: name.replace('-', "_"), manifest_name: name, root: dir, lib_rs });
    }
    found
}

fn collect_manifests(dir: &Path, depth: u32, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if !SKIPPED_DIRS.contains(&name.as_str()) && !name.starts_with('.') {
                collect_manifests(&path, depth + 1, out);
            }
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
}

/// A line-based reader for the two facts discovery needs from a manifest: the package name
/// and the lib path. A full TOML crate is not worth a dependency for two keys.
fn package_lib_target(text: &str) -> Option<(String, Option<String>)> {
    let mut section = String::new();
    let mut name = None;
    let mut lib_path = None;
    let mut has_package = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('[') {
            section = rest.trim_end_matches(']').trim().to_string();
            if section == "package" {
                has_package = true;
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let value = value.split('#').next().unwrap_or("").trim().trim_matches('"').to_string();
        match section.as_str() {
            "package" if key.trim() == "name" && !value.is_empty() => name = Some(value),
            "lib" if key.trim() == "path" && !value.is_empty() => lib_path = Some(value),
            _ => {}
        }
    }
    if !has_package {
        return None;
    }
    Some((name?, lib_path))
}

/// One parsed source file with the module path its items live under.
struct ParsedFile {
    #[allow(dead_code)]
    path: PathBuf,
    /// Root-relative path with `/` separators, the form `origin.file` and coverage urls use.
    rel: String,
    /// `afz_engine::report` for `src/report.rs` of the `afz_engine` crate.
    mod_path: String,
    /// False when any module on the way here was private: its `pub` items are still not
    /// reachable from outside the crate.
    reachable: bool,
    file: File,
    text: String,
}

fn parse_crate(package: &Package, out: &mut Vec<ParsedFile>) {
    parse_file_into(package, package.lib_rs.clone(), package.name.clone(), true, out);
}

fn parse_file_into(package: &Package, path: PathBuf, mod_path: String, reachable: bool, out: &mut Vec<ParsedFile>) {
    let Ok(text) = std::fs::read_to_string(&path) else { return };
    let Ok(file) = syn::parse_file(&text) else { return };
    let rel = relative(&package.root, &path);
    let items = file.items.clone();
    out.push(ParsedFile { path: path.clone(), rel, mod_path: mod_path.clone(), reachable, file, text });
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    for item in &items {
        let Item::Mod(module) = item else { continue };
        if has_cfg(module, &["test", "bench"]) {
            continue;
        }
        if module.content.is_some() {
            // Inline modules are walked where functions are collected; they are not files.
            continue;
        }
        let child_mod = format!("{mod_path}::{}", module.ident);
        let child_reachable = reachable && matches!(module.vis, Visibility::Public(_));
        let name = module.ident.to_string();
        let candidates = match attr_path(&module.attrs) {
            Some(explicit) => vec![dir.join(explicit)],
            None => vec![dir.join(format!("{name}.rs")), dir.join(&name).join("mod.rs")],
        };
        for candidate in candidates {
            if candidate.is_file() {
                parse_file_into(package, candidate, child_mod, child_reachable, out);
                break;
            }
        }
    }
}

fn has_cfg(module: &syn::ItemMod, kinds: &[&str]) -> bool {
    module.attrs.iter().any(|attr| {
        let Ok(meta) = attr.meta.require_list() else { return false };
        if !meta.path.is_ident("cfg") {
            return false;
        }
        let text = meta.tokens.to_string();
        kinds.iter().any(|kind| text.split(|c: char| !c.is_alphanumeric() && c != '_').any(|word| word == *kind))
    })
}

fn attr_path(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if let Ok(meta) = attr.meta.require_name_value() {
            if meta.path.is_ident("path") {
                if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(value), .. }) = &meta.value {
                    return Some(value.value());
                }
            }
        }
    }
    None
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/")
}

fn index_types(file: &ParsedFile, types: &mut HashMap<String, TypeDef>) {
    for item in &file.file.items {
        match item {
            Item::Struct(item) => {
                if !item.generics.params.is_empty() {
                    continue;
                }
                let key = format!("{}::{}", file.mod_path, item.ident);
                match &item.fields {
                    syn::Fields::Named(named) => {
                        let fields = named
                            .named
                            .iter()
                            .map(|field| FieldDef {
                                name: field.ident.clone().map(|i| i.to_string()).unwrap_or_default(),
                                ty: field.ty.clone(),
                                public: matches!(field.vis, Visibility::Public(_)),
                            })
                            .collect();
                        types.insert(key, TypeDef { kind: TypeKind::Struct { fields } });
                    }
                    // A tuple struct has no field names to read from a JSON object and a unit
                    // struct no field to read: both carry a non-existent private field so
                    // lowering reports them as unconstructible rather than mis-building them.
                    syn::Fields::Unnamed(_) | syn::Fields::Unit => {
                        types.insert(
                            key,
                            TypeDef {
                                kind: TypeKind::Struct {
                                    fields: vec![FieldDef { name: String::new(), ty: syn::parse_quote!(()), public: false }],
                                },
                            },
                        );
                    }
                }
            }
            Item::Enum(item) => {
                if !item.generics.params.is_empty() {
                    continue;
                }
                let mut variants = Vec::new();
                for variant in &item.variants {
                    let name = variant.ident.to_string();
                    match &variant.fields {
                        syn::Fields::Unit => variants.push(VariantDef::Unit(name)),
                        syn::Fields::Unnamed(unnamed) => {
                            variants.push(VariantDef::Tuple(name, unnamed.unnamed.iter().map(|f| f.ty.clone()).collect()));
                        }
                        syn::Fields::Named(named) => variants.push(VariantDef::Struct(
                            name,
                            named
                                .named
                                .iter()
                                .map(|field| FieldDef {
                                    name: field.ident.clone().map(|i| i.to_string()).unwrap_or_default(),
                                    ty: field.ty.clone(),
                                    public: matches!(field.vis, Visibility::Public(_)),
                                })
                                .collect(),
                        )),
                    }
                }
                types.insert(format!("{}::{}", file.mod_path, item.ident), TypeDef { kind: TypeKind::Enum { variants } });
            }
            _ => {}
        }
    }
}

/// Record every function in these items, public and private: the coverage denominator.
/// Inline modules recurse; `#[cfg(test)]` modules do not, because they are not compiled.
fn collect_universe_items(items: &[Item], file: &ParsedFile, mod_path: &str, universe: &mut HashMap<String, UniFn>) {
    let line_starts = line_starts(&file.text);
    collect_universe_walk(items, file, mod_path, universe, &line_starts);
}

fn collect_universe_walk(
    items: &[Item],
    file: &ParsedFile,
    mod_path: &str,
    universe: &mut HashMap<String, UniFn>,
    line_starts: &[usize],
) {
    for item in items {
        match item {
            Item::Fn(item) => {
                let key = format!("{mod_path}::{}", item.sig.ident);
                record(universe, file, line_starts, key.clone(), item.span().byte_range(), item.span().start());
                collect_nested_fns(&item.block, file, line_starts, &format!("{key}::"), universe);
            }
            Item::Impl(item) => {
                let Some(type_name) = impl_type_name(item) else { continue };
                for member in &item.items {
                    if let ImplItem::Fn(method) = member {
                        let key = format!("{mod_path}::{type_name}::{}", method.sig.ident);
                        record(universe, file, line_starts, key.clone(), method.span().byte_range(), method.span().start());
                        collect_nested_fns(&method.block, file, line_starts, &format!("{key}::"), universe);
                    }
                }
            }
            Item::Mod(module) => {
                if has_cfg(module, &["test", "bench"]) {
                    continue;
                }
                if let Some((_, inner)) = &module.content {
                    collect_universe_walk(inner, file, &format!("{mod_path}::{}", module.ident), universe, line_starts);
                }
            }
            _ => {}
        }
    }
}

/// A nested fn's symbol is `<outer>::<inner>`; the demangled key carries the chain, so
/// record each nested fn under `prefix` + name where prefix ends with `::`.
fn collect_nested_fns(block: &syn::Block, file: &ParsedFile, line_starts: &[usize], prefix: &str, universe: &mut HashMap<String, UniFn>) {
    struct Finder<'a> {
        file: &'a ParsedFile,
        line_starts: &'a [usize],
        prefix: String,
        universe: &'a mut HashMap<String, UniFn>,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_item_fn(&mut self, node: &'ast ItemFn) {
            let key = format!("{}{}", self.prefix, node.sig.ident);
            record(self.universe, self.file, self.line_starts, key.clone(), node.span().byte_range(), node.span().start());
            let deeper = format!("{key}::");
            let outer = std::mem::replace(&mut self.prefix, deeper);
            syn::visit::visit_item_fn(self, node);
            self.prefix = outer;
        }
    }
    let mut finder = Finder { file, line_starts, prefix: prefix.to_string(), universe };
    finder.visit_block(block);
}

fn record(
    universe: &mut HashMap<String, UniFn>,
    file: &ParsedFile,
    line_starts: &[usize],
    key: String,
    range: Range<usize>,
    span_start: proc_macro2::LineColumn,
) {
    let (start, end) = if range.end > range.start {
        (range.start as u64, range.end as u64)
    } else if !file.text.is_empty() {
        // A `0..0` span (possible for macro-expanded items): convert the span start through
        // the line-start table so the entry still locates a byte range.
        let line = (span_start.line.saturating_sub(1)).min(line_starts.len().saturating_sub(1));
        let start = line_starts.get(line).copied().unwrap_or(0);
        (start as u64, file.text.len() as u64)
    } else {
        return;
    };
    universe.insert(key, UniFn { file: file.rel.clone(), start, end });
}

fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (index, byte) in text.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(index + 1);
        }
    }
    starts
}

fn impl_type_name(item: &ItemImpl) -> Option<String> {
    let Type::Path(path) = &*item.self_ty else { return None };
    let last = path.path.segments.last()?;
    Some(last.ident.to_string())
}

/// Walk the items of one file (recursing into inline modules) and report every function.
fn collect_items(
    items: &[Item],
    file: &ParsedFile,
    mod_path: &str,
    reachable: bool,
    excluded: bool,
    included: bool,
    types: &HashMap<String, TypeDef>,
    inventory: &mut Inventory,
) {
    for item in items {
        match item {
            Item::Fn(item) => {
                let name = item.sig.ident.to_string();
                analyze(
                    file,
                    mod_path,
                    None,
                    &format!("{mod_path}::{name}"),
                    &name,
                    &item.sig,
                    &item.block,
                    &item.vis,
                    ReceiverKind::None,
                    item.sig.unsafety.is_some(),
                    excluded,
                    included,
                    reachable,
                    types,
                    inventory,
                );
            }
            Item::Impl(item) => collect_impl(item, file, mod_path, reachable, excluded, included, types, inventory),
            Item::Mod(module) => {
                if has_cfg(module, &["test", "bench"]) {
                    continue;
                }
                if let Some((_, inner)) = &module.content {
                    collect_items(
                        inner,
                        file,
                        &format!("{mod_path}::{}", module.ident),
                        reachable && matches!(module.vis, Visibility::Public(_)),
                        excluded,
                        included,
                        types,
                        inventory,
                    );
                }
            }
            _ => {}
        }
    }
}

fn collect_impl(
    item: &ItemImpl,
    file: &ParsedFile,
    mod_path: &str,
    reachable: bool,
    excluded: bool,
    included: bool,
    types: &HashMap<String, TypeDef>,
    inventory: &mut Inventory,
) {
    if item.trait_.is_some() {
        return;
    }
    let generic_impl = item.generics.params.iter().any(|p| !matches!(p, syn::GenericParam::Lifetime(_)));
    let Some(type_name) = impl_type_name(item) else { return };
    for member in &item.items {
        let ImplItem::Fn(method) = member else { continue };
        let name = format!("{type_name}::{}", method.sig.ident);
        if !matches!(method.vis, Visibility::Public(_)) {
            inventory.discovery.skipped.push(skip(
                target_id(mod_path, &name, &signature_text(&method.sig)),
                &name,
                SkipReason::NotPublic,
                None,
                None,
                Some(format!("{} is not pub", method.sig.ident)),
            ));
            continue;
        }
        if generic_impl {
            inventory.discovery.skipped.push(skip(
                target_id(mod_path, &name, &signature_text(&method.sig)),
                &name,
                SkipReason::UnsupportedSignature,
                None,
                None,
                Some("generic impl: the driver cannot pick an instantiation".into()),
            ));
            continue;
        }
        let receiver = match method.sig.receiver() {
            None => ReceiverKind::None,
            Some(receiver) => match (&receiver.reference, &receiver.mutability) {
                (None, _) => ReceiverKind::Value,
                (Some(_), Some(_)) => ReceiverKind::RefMut,
                (Some(_), None) => ReceiverKind::Ref,
            },
        };
        analyze(
            file,
            mod_path,
            Some(&type_name),
            &format!("{mod_path}::{type_name}::{}", method.sig.ident),
            &name,
            &method.sig,
            &method.block,
            &method.vis,
            receiver,
            method.sig.unsafety.is_some(),
            excluded,
            included,
            reachable,
            types,
            inventory,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze(
    file: &ParsedFile,
    mod_path: &str,
    type_context: Option<&str>,
    call_path: &str,
    name: &str,
    sig: &syn::Signature,
    block: &syn::Block,
    vis: &Visibility,
    receiver: ReceiverKind,
    unsafe_call: bool,
    excluded: bool,
    included: bool,
    reachable: bool,
    types: &HashMap<String, TypeDef>,
    inventory: &mut Inventory,
) {
    let id = target_id(mod_path, name, &signature_text(sig));

    // 1. visibility.
    if !matches!(vis, Visibility::Public(_)) {
        inventory.discovery.skipped.push(skip(id, name, SkipReason::NotPublic, None, None, Some(format!("{name} is not pub"))));
        return;
    }
    if !reachable {
        inventory.discovery.skipped.push(skip(
            id,
            name,
            SkipReason::NotPublic,
            None,
            None,
            Some(format!("{name} is pub but declared in a private module")),
        ));
        return;
    }
    // 2. include/exclude.
    if excluded || !included {
        inventory.discovery.skipped.push(skip(id, name, SkipReason::Excluded, None, None, Some(file.rel.clone())));
        return;
    }
    // 3. uncallable constructs.
    if let Some(detail) = lower::signature_blocker(sig) {
        inventory.discovery.skipped.push(skip(id, name, SkipReason::UnsupportedSignature, None, None, Some(detail)));
        return;
    }

    // 4. parameter lowering; the receiver is parameter zero.
    let mut ctx = Ctx::new(types, mod_path);
    let mut params: Vec<ParamSpec> = Vec::new();
    let mut descriptor_params: Vec<Parameter> = Vec::new();
    let mut blocker: Option<Blocker> = None;
    let mut sig_detail: Option<String> = None;
    for (index, input) in sig.inputs.iter().enumerate() {
        match input {
            syn::FnArg::Receiver(rcv) => {
                if rcv.colon_token.is_some() {
                    inventory.discovery.skipped.push(skip(
                        id,
                        name,
                        SkipReason::UnsupportedSignature,
                        None,
                        None,
                        Some("an annotated self receiver (arbitrary_self_types) is not callable".into()),
                    ));
                    return;
                }
                let self_written = type_context.unwrap_or("()");
                let self_ty: Type = match syn::parse_str(self_written) {
                    Ok(ty) => ty,
                    Err(_) => syn::parse_quote!(()),
                };
                match lower::lower(&mut ctx, &self_ty) {
                    Ok(lowered) => {
                        params.push(ParamSpec { build: lowered.build, mode: PassMode::Value, wrap: Wrap::None, receiver });
                        descriptor_params.push(Parameter { name: "self".into(), ty: lowered.ty, required: true });
                    }
                    Err(blocked) => {
                        blocker = Some(Blocker { type_: blocked.type_name, module: Some(file.rel.clone()), path: "receiver".into() });
                    }
                }
            }
            syn::FnArg::Typed(argument) => {
                let param_name = match &*argument.pat {
                    syn::Pat::Ident(ident) => ident.ident.to_string(),
                    _ => format!("arg{index}"),
                };
                match lower::lower(&mut ctx, &argument.ty) {
                    Ok(lowered) => {
                        let (mode, wrap) = lower::call_shape(&argument.ty);
                        params.push(ParamSpec { build: lowered.build, mode, wrap, receiver: ReceiverKind::None });
                        descriptor_params.push(Parameter { name: param_name, ty: lowered.ty, required: true });
                    }
                    Err(blocked) => {
                        if blocked.why == BlockedWhy::Signature {
                            sig_detail = Some(format!("{} cannot be built", blocked.type_name));
                            break;
                        }
                        blocker.get_or_insert(Blocker {
                            type_: blocked.type_name,
                            module: Some(file.rel.clone()),
                            path: format!("arg{index}"),
                        });
                    }
                }
            }
        }
    }
    if let Some(detail) = sig_detail {
        inventory.discovery.skipped.push(skip(id, name, SkipReason::UnsupportedSignature, None, None, Some(detail)));
        return;
    }
    if let Some(blocked_by) = blocker {
        inventory.discovery.skipped.push(skip(
            id,
            name,
            SkipReason::UnconstructibleParameter,
            Some(blocked_by),
            Some(Materialization::Opaque),
            Some("a parameter or receiver cannot be built from generated JSON".into()),
        ));
        return;
    }

    let ret = match &sig.output {
        syn::ReturnType::Default => RetShape::Plain,
        syn::ReturnType::Type(_, ty) => match lower::written_path(ty).rsplit("::").next().unwrap_or("") {
            "Result" => RetShape::Result,
            "Option" => RetShape::Option,
            _ => RetShape::Plain,
        },
    };
    // A return type lowers best-effort: an unlowerable return never blocks a target, it just
    // leaves `returns` empty.
    let returns = match &sig.output {
        syn::ReturnType::Default => None,
        syn::ReturnType::Type(_, ty) => lower::lower(&mut ctx, ty).ok().map(|lowered| lowered.ty),
    };

    let line = sig.ident.span().start().line as u32;
    let descriptor = TargetDescriptor {
        id: id.clone(),
        target_class: TargetClass::DesignTime,
        origin: Origin {
            file: Some(file.rel.clone()),
            line: Some(line),
            module: Some(mod_path.to_string()),
            http: None,
        },
        name: name.to_string(),
        parameters: descriptor_params,
        returns,
        // Any Rust function can panic: `throws` records the possibility, the guard sites
        // record the refusals the author wrote.
        effects: Effects { async_: false, throws: true, streams: false, callbacks: false, mutates_state: false },
        guard_sites: guard_sites(block),
        materialization: Materialization::Constructible,
    };
    inventory.targets.push(Tgt {
        id,
        name: name.to_string(),
        call_path: call_path.to_string(),
        params,
        ret,
        unsafe_call,
        descriptor: descriptor.clone(),
    });
    inventory.discovery.targets.push(descriptor);
}

/// Lines inside the body that hold a refusal or a deliberate stop the author wrote.
fn guard_sites(block: &syn::Block) -> Vec<u32> {
    struct Guard {
        lines: Vec<u32>,
    }
    impl<'ast> Visit<'ast> for Guard {
        fn visit_expr(&mut self, expr: &'ast syn::Expr) {
            match expr {
                syn::Expr::Macro(mac) => {
                    if let Some(last) = mac.mac.path.segments.last() {
                        if matches!(last.ident.to_string().as_str(), "panic" | "unreachable" | "todo" | "unimplemented") {
                            self.lines.push(mac.span().start().line as u32);
                        }
                    }
                }
                syn::Expr::MethodCall(call) => {
                    if call.method == "expect" {
                        self.lines.push(call.method.span().start().line as u32);
                    }
                }
                syn::Expr::Return(ret) => {
                    if let Some(inner) = &ret.expr {
                        let name = match &**inner {
                            syn::Expr::Call(call) => match &*call.func {
                                syn::Expr::Path(path) => path.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default(),
                                _ => String::new(),
                            },
                            syn::Expr::Path(path) => path.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default(),
                            _ => String::new(),
                        };
                        if name == "Err" || name == "None" {
                            self.lines.push(ret.return_token.span().start().line as u32);
                        }
                    }
                }
                _ => {}
            }
            syn::visit::visit_expr(self, expr);
        }
    }
    let mut guard = Guard { lines: Vec::new() };
    guard.visit_block(block);
    guard.lines.sort_unstable();
    guard.lines.dedup();
    guard.lines.truncate(64);
    guard.lines
}

fn signature_text(sig: &syn::Signature) -> String {
    sig.to_token_stream().to_string()
}

/// The target id: a hash of the module path, the symbol, and the signature, so the same
/// function of the same tree gets the same id across runs and a resumed scan recognises its
/// findings.
pub fn target_id(module_path: &str, name: &str, signature: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(module_path.as_bytes());
    digest.update([0]);
    digest.update(name.as_bytes());
    digest.update([0]);
    digest.update(signature.as_bytes());
    let bytes = digest.finalize();
    let mut hex = String::with_capacity(12);
    for byte in &bytes[..6] {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("afz:t:{hex}")
}

fn skip(
    target_id: String,
    name: &str,
    reason: SkipReason,
    blocked_by: Option<Blocker>,
    materialization: Option<Materialization>,
    detail: Option<String>,
) -> SkippedTarget {
    SkippedTarget { target_id, name: name.to_string(), reason, blocked_by, unlocks_targets: None, materialization, detail }
}

fn match_excludes(req: &DiscoverReq, rel: &str) -> bool {
    req.exclude.as_ref().is_some_and(|patterns| patterns.iter().any(|glob| matches_pattern(glob, rel)))
}

fn match_includes(req: &DiscoverReq, rel: &str) -> bool {
    req.include.as_ref().is_none_or(|patterns| patterns.iter().any(|glob| matches_pattern(glob, rel)))
}

/// Match a path against a glob, segment by segment: `*` matches within one path segment and
/// `**` matches any number of segments. A pattern with no separator names a file at any
/// depth, which is how `*.rs` is written.
pub fn matches_pattern(pattern: &str, path: &str) -> bool {
    let pattern = pattern.replace('\\', "/");
    let path = path.replace('\\', "/");
    let pat = glob_segments(&pattern);
    let way = glob_segments(&path);
    let way: &[&str] = match (pattern.contains('/'), way.split_last()) {
        (true, _) => &way,
        (false, Some((last, _))) => std::slice::from_ref(last),
        (false, None) => &[],
    };
    matches_segments(&pat, way)
}

fn glob_segments(text: &str) -> Vec<&str> {
    text.split('/').filter(|part| !part.is_empty() && *part != ".").collect()
}

fn matches_segments(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.first().copied() {
        None => path.is_empty(),
        Some("**") => matches_segments(&pattern[1..], path) || (!path.is_empty() && matches_segments(pattern, &path[1..])),
        Some(head) => !path.is_empty() && matches_segment(head, path[0]) && matches_segments(&pattern[1..], &path[1..]),
    }
}

fn matches_segment(pattern: &str, text: &str) -> bool {
    let mut rest = text;
    for (index, part) in pattern.split('*').enumerate() {
        if index == 0 {
            if !rest.starts_with(part) {
                return false;
            }
            rest = &rest[part.len()..];
            continue;
        }
        let Some(at) = rest.find(part) else { return false };
        rest = &rest[at + part.len()..];
    }
    rest.is_empty() || pattern.ends_with('*')
}
