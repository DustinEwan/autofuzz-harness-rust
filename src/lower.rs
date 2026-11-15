//! Type lowering: `syn::Type` to the wire `TypeNode`, plus the `Build` tree the driver
//! generator walks.
//!
//! One recursive function produces both halves, so the declared parameter type and the
//! generated construction code cannot drift: `TypeNode` is what the generator side of the
//! engine sees, `Build` is what `src/calls.rs` of the generated driver compiles. A project
//! type never needs a serde derive, because a struct argument is built field by field with a
//! struct literal, not deserialized.
//!
//! A type that cannot be built is `Blocked`, and the reason decides which skip reason
//! discovery reports: `Signature` (the construct itself is uncallable: `dyn Trait`, a bare
//! `fn(..)`, `[T; N]`) becomes `unsupported-signature`, and `Unconstructible` (a type whose
//! shape the driver cannot fill: a private field, a pointer, a dependency's type) becomes
//! `unconstructible-parameter` with the blocking type's name.

use std::collections::HashMap;

use afz_protocol::types::{CollectionKind, CompositeKind, Field, LengthBounds, NumberBounds, ScalarKind, TypeNode};
use quote::ToTokens;
use syn::visit::Visit;
use syn::{Type, GenericParam};

/// Why a parameter graph cannot be built, mapped onto the two skip reasons by discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedWhy {
    /// The construct is not callable at all: `async`, `dyn Trait`, `impl Trait`, a bare
    /// `fn(..)`, a closure, a non-lifetime generic parameter, `[T; N]`.
    Signature,
    /// The construct is callable but no value of it can be built from generated JSON: a
    /// pointer, `PhantomData`, a non-`pub` field, a type outside the parsed set, a recursive
    /// type, a map with a non-string key.
    Unconstructible,
}

#[derive(Debug, Clone)]
pub struct Blocked {
    pub type_name: String,
    pub why: BlockedWhy,
}

impl Blocked {
    pub fn signature(type_name: impl Into<String>) -> Self {
        Blocked { type_name: type_name.into(), why: BlockedWhy::Signature }
    }
    pub fn unconstructible(type_name: impl Into<String>) -> Self {
        Blocked { type_name: type_name.into(), why: BlockedWhy::Unconstructible }
    }
}

#[derive(Debug, Clone)]
pub struct Lowered {
    pub ty: TypeNode,
    pub build: Build,
}

/// How the built value reaches the call: by value, by reference, or mutably. Wrappers that
/// need construction (`Box`, `Arc`, `Rc`, `Cow`) are [`Wrap`], not a pass mode: the driver
/// binds `let a0: T = …;` with the wrapper built, and passes it by one of these three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassMode {
    Value,
    Ref,
    RefMut,
}

/// One variant of a project enum, in the wire shape the driver reads: a unit variant is a
/// string literal naming it, a tuple variant is a tuple, a struct variant is an object.
#[derive(Debug, Clone)]
pub enum VariantShape {
    Unit,
    Tuple(Vec<Build>),
    Struct(Vec<(String, Build)>),
}

#[derive(Debug, Clone)]
pub struct Variant {
    pub name: String,
    pub shape: VariantShape,
}

/// The recipe for one value, recursive, walked by the driver generator and by the
/// reproducer renderer.
#[derive(Debug, Clone)]
pub enum Build {
    Bool,
    Int(&'static str),
    Float(&'static str),
    Char,
    Str,
    PathBuf,
    JsonValue,
    Vec { inner: Box<Build> },
    Set { inner: Box<Build>, ordered: bool },
    Map { value: Box<Build>, ordered: bool },
    Tuple { items: Vec<Build> },
    Option { inner: Box<Build> },
    Struct { path: String, fields: Vec<(String, Build)> },
    Enum { path: String, variants: Vec<Variant> },
}

impl Build {
    /// Whether the generated driver may serialize a value of this build with
    /// `serde_json::to_value`: wire types yes, project structs and enums no. Their
    /// `Serialize` derive cannot be assumed from the field list alone, and a missing derive
    /// is a trait bound that fails the whole driver build, so the value is dropped instead.
    pub fn serializable(&self) -> bool {
        match self {
            Build::Bool | Build::Int(_) | Build::Float(_) | Build::Char | Build::Str | Build::PathBuf | Build::JsonValue => true,
            Build::Vec { inner } | Build::Set { inner, .. } | Build::Option { inner } => inner.serializable(),
            Build::Map { value, .. } => value.serializable(),
            Build::Tuple { items } => items.iter().all(Build::serializable),
            Build::Struct { .. } | Build::Enum { .. } => false,
        }
    }

    /// The Rust type the generated `let` binding carries. `PathBuf` is built even for a
    /// `&Path` parameter, because `&PathBuf` coerces to `&Path` at the call.
    pub fn rust_ty(&self) -> String {
        match self {
            Build::Bool => "bool".into(),
            Build::Int(t) | Build::Float(t) => (*t).to_string(),
            Build::Char => "char".into(),
            Build::Str => "::std::string::String".into(),
            Build::PathBuf => "::std::path::PathBuf".into(),
            Build::JsonValue => "::serde_json::Value".into(),
            Build::Vec { inner } => format!("::std::vec::Vec<{}>", inner.rust_ty()),
            Build::Set { inner, ordered } => {
                let set = if *ordered { "::std::collections::BTreeSet" } else { "::std::collections::HashSet" };
                format!("{set}<{}>", inner.rust_ty())
            }
            Build::Map { value, ordered } => {
                let map = if *ordered { "::std::collections::BTreeMap" } else { "::std::collections::HashMap" };
                format!("{map}<::std::string::String, {}>", value.rust_ty())
            }
            Build::Tuple { items } => {
                let parts: Vec<String> = items.iter().map(Build::rust_ty).collect();
                format!("({})", parts.join(", "))
            }
            Build::Option { inner } => format!("::std::option::Option<{}>", inner.rust_ty()),
            Build::Struct { path, .. } | Build::Enum { path, .. } => path.clone(),
        }
    }
}

/// A parsed project type, keyed by its full path (`afz_engine::report::RenderOptions`).
#[derive(Debug, Clone)]
pub struct TypeDef {
    pub kind: TypeKind,
}

#[derive(Debug, Clone)]
pub enum TypeKind {
    /// Every field carries its visibility; a non-`pub` field blocks construction.
    Struct { fields: Vec<FieldDef> },
    Enum { variants: Vec<VariantDef> },
}

#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub ty: Type,
    pub public: bool,
}

#[derive(Debug, Clone)]
pub enum VariantDef {
    Unit(String),
    Tuple(String, Vec<Type>),
    Struct(String, Vec<FieldDef>),
}


/// The lowering context: the parsed type index and the module the query comes from, so a
/// bare `RenderOptions` resolves against the file's own module and its ancestors.
pub struct Ctx<'a> {
    pub types: &'a HashMap<String, TypeDef>,
    /// The module path of the file being lowered, e.g. `afz_engine::git`.
    pub mod_path: String,
    /// The full paths currently being lowered, for the recursion guard.
    stack: Vec<String>,
}

impl<'a> Ctx<'a> {
    pub fn new(types: &'a HashMap<String, TypeDef>, mod_path: impl Into<String>) -> Ctx<'a> {
        Ctx { types, mod_path: mod_path.into(), stack: Vec::new() }
    }

    /// Resolve a written path to a parsed type: the file's own module first, then each
    /// ancestor module, then the path as written (a crate-root item).
    fn resolve(&self, written: &str) -> Option<(&'a String, &'a TypeDef)> {
        let mut prefix: &str = &self.mod_path;
        loop {
            let candidate = format!("{prefix}::{written}");
            if let Some(entry) = self.types.get_key_value(&candidate) {
                return Some(entry);
            }
            match prefix.rfind("::") {
                Some(cut) => prefix = &prefix[..cut],
                None => break,
            }
        }
        self.types.get_key_value(written)
    }
}

/// Last-segment name of a type path, ignoring generic arguments: `Vec<u8>` -> `Vec`.
fn head_name(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else { return None };
    let last = path.path.segments.last()?;
    Some(last.ident.to_string())
}

/// The angle-bracketed type arguments of a path type: `Vec<u8>` -> `[u8]`. Lifetimes are
/// dropped, because a lifetime never decides constructibility.
fn type_args(ty: &Type) -> Vec<Type> {
    let Type::Path(path) = ty else { return Vec::new() };
    let Some(last) = path.path.segments.last() else { return Vec::new() };
    match &last.arguments {
        syn::PathArguments::AngleBracketed(inner) => inner
            .args
            .iter()
            .filter_map(|arg| match arg {
                syn::GenericArgument::Type(t) => Some(t.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn is_integer(name: &str) -> Option<&'static str> {
    Some(match name {
        "i8" => "i8",
        "i16" => "i16",
        "i32" => "i32",
        "i64" => "i64",
        "isize" => "isize",
        "u8" => "u8",
        "u16" => "u16",
        "u32" => "u32",
        "u64" => "u64",
        "usize" => "usize",
        _ => return None,
    })
}

/// A signature contains a construct the driver cannot call at all: `async`, `dyn Trait`,
/// `impl Trait`, a bare `fn(..)`, a closure, an `[T; N]`, or a non-lifetime generic
/// parameter. The returned sentence names the construct for the skip's `detail`.
pub fn signature_blocker(sig: &syn::Signature) -> Option<String> {
    if sig.asyncness.is_some() {
        return Some("async fn: the driver has no executor".into());
    }
    if sig.variadic.is_some() {
        return Some("variadic parameters cannot be built".into());
    }
    if sig.generics.params.iter().any(|p| !matches!(p, GenericParam::Lifetime(_))) {
        return Some("generic parameters cannot be instantiated".into());
    }
    let mut finder = Constructs::default();
    for input in &sig.inputs {
        finder.visit_fn_arg(input);
    }
    finder.found
}

/// The pass mode a written parameter type implies for its lowered inner value.
pub fn pass_mode(ty: &Type) -> PassMode {
    match ty {
        Type::Reference(reference) => {
            if reference.mutability.is_some() {
                PassMode::RefMut
            } else {
                PassMode::Ref
            }
        }
        _ => PassMode::Value,
    }
}

/// A transparent wrapper the driver must build around the lowered value: lowering sees
/// through `Box`/`Arc`/`Rc`/`Cow` to the inner type, so the call site reconstructs the
/// wrapper. `Cowed` carries the written parameter type because `Cow<'static, str>` is built
/// from a `String` and no lowered type says that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wrap {
    None,
    Boxed,
    BoxedSlice,
    Arced,
    Rced,
    Cowed(String),
}

/// The pass mode and the wrapper construction one written parameter type asks for.
pub fn call_shape(ty: &Type) -> (PassMode, Wrap) {
    let mode = pass_mode(ty);
    let inner = match ty {
        Type::Reference(reference) => &reference.elem,
        other => other,
    };
    let wrap = match head_name(inner).as_deref() {
        Some("Box") => {
            if matches!(type_args(inner).first(), Some(Type::Slice(_))) {
                Wrap::BoxedSlice
            } else {
                Wrap::Boxed
            }
        }
        Some("Arc") => Wrap::Arced,
        Some("Rc") => Wrap::Rced,
        Some("Cow") => Wrap::Cowed(ty.to_token_stream().to_string().replace("'_", "'static")),
        _ => Wrap::None,
    };
    (mode, wrap)
}

#[derive(Default)]
struct Constructs {
    found: Option<String>,
}

impl<'ast> Visit<'ast> for Constructs {
    fn visit_type(&mut self, ty: &'ast Type) {
        if self.found.is_none() {
            match ty {
                Type::TraitObject(_) => self.found = Some("a dyn Trait parameter cannot be called through".into()),
                Type::ImplTrait(_) => self.found = Some("an impl Trait parameter cannot be instantiated".into()),
                Type::BareFn(_) => self.found = Some("a fn(..) parameter cannot be built".into()),
                Type::Array(_) => self.found = Some("[T; N] cannot be sized from a generated length".into()),
                Type::Infer(_) => self.found = Some("an inferred parameter type cannot be lowered".into()),
                _ => {}
            }
        }
        if self.found.is_none() {
            syn::visit::visit_type(self, ty);
        }
    }
}

/// Lower one type. The `Ok` half carries both the wire node and the build recipe; the `Err`
/// half names the type that stops a parameter.
pub fn lower(ctx: &mut Ctx, ty: &Type) -> Result<Lowered, Blocked> {
    match ty {
        Type::Reference(reference) => lower(ctx, &reference.elem),
        Type::Group(group) => lower(ctx, &group.elem),
        Type::Paren(paren) => lower(ctx, &paren.elem),
        Type::Slice(slice) => {
            let inner = lower(ctx, &slice.elem)?;
            Ok(array_of(inner))
        }
        Type::Tuple(tuple) => {
            if tuple.elems.is_empty() {
                // `()` is a real return type but never a meaningful parameter; describe it
                // as an empty tuple so `report` still compiles.
                return Ok(Lowered {
                    ty: TypeNode::Tuple { items: Vec::new() },
                    build: Build::Tuple { items: Vec::new() },
                });
            }
            let mut items = Vec::new();
            let mut tys = Vec::new();
            for element in &tuple.elems {
                let lowered = lower(ctx, element)?;
                items.push(lowered.build);
                tys.push(lowered.ty);
            }
            Ok(Lowered { ty: TypeNode::Tuple { items: tys }, build: Build::Tuple { items } })
        }
        Type::Ptr(_) => Err(Blocked::unconstructible(head_name(ty).unwrap_or_else(|| "*mut T".into()))),
        Type::TraitObject(_) => Err(Blocked::signature("dyn Trait")),
        Type::ImplTrait(_) => Err(Blocked::signature("impl Trait")),
        Type::BareFn(_) => Err(Blocked::signature("fn(..)")),
        Type::Array(_) => Err(Blocked::signature("[T; N]")),
        _ => lower_path(ctx, ty),
    }
}

fn array_of(inner: Lowered) -> Lowered {
    Lowered {
        ty: TypeNode::Collection {
            collection: CollectionKind::Array,
            element: Box::new(inner.ty),
            key: None,
            length: Some(LengthBounds { min: None, max: Some(64) }),
        },
        build: Build::Vec { inner: Box::new(inner.build) },
    }
}

fn lower_path(ctx: &mut Ctx, ty: &Type) -> Result<Lowered, Blocked> {
    let name = head_name(ty).unwrap_or_default();
    let written = written_path(ty);
    let args = type_args(ty);

    match name.as_str() {
        "bool" => return Ok(Lowered { ty: TypeNode::boolean(), build: Build::Bool }),
        "char" => {
            return Ok(Lowered {
                ty: TypeNode::Scalar {
                    scalar: ScalarKind::String,
                    bounds: None,
                    length: Some(LengthBounds { min: Some(1), max: Some(1) }),
                },
                build: Build::Char,
            })
        }
        "f32" | "f64" => {
            let t = if name == "f32" { "f32" } else { "f64" };
            return Ok(Lowered {
                ty: TypeNode::Scalar {
                    scalar: ScalarKind::Number,
                    bounds: Some(NumberBounds { int: false, finite_only: false, min: None, max: None }),
                    length: None,
                },
                build: Build::Float(t),
            });
        }
        "String" | "str" | "OsString" | "OsStr" => return Ok(string_like(Build::Str)),
        "PathBuf" | "Path" => return Ok(string_like(Build::PathBuf)),
        _ => {}
    }
    if let Some(t) = is_integer(&name) {
        let (min, max) = int_bounds(t);
        return Ok(Lowered {
            ty: TypeNode::Scalar {
                scalar: ScalarKind::BigInt,
                bounds: Some(NumberBounds { int: true, finite_only: true, min: Some(min), max: Some(max) }),
                length: None,
            },
            build: Build::Int(t),
        });
    }

    // Transparent wrappers: the value is built as the inner type and wrapped at the call.
    if matches!(name.as_str(), "Box" | "Arc" | "Rc" | "Cow") {
        if let Some(inner) = args.first() {
            return lower(ctx, inner);
        }
    }

    match name.as_str() {
        "Vec" | "VecDeque" => {
            let Some(inner) = args.first() else { return Err(Blocked::unconstructible(format!("{name}<?>"))) };
            return Ok(array_of(lower(ctx, inner)?));
        }
        "HashSet" | "BTreeSet" => {
            let Some(inner) = args.first() else { return Err(Blocked::unconstructible(format!("{name}<?>"))) };
            let lowered = lower(ctx, inner)?;
            let ordered = name == "BTreeSet";
            return Ok(Lowered {
                ty: TypeNode::Collection {
                    collection: CollectionKind::Set,
                    element: Box::new(lowered.ty),
                    key: None,
                    length: Some(LengthBounds { min: None, max: Some(64) }),
                },
                build: Build::Set { inner: Box::new(lowered.build), ordered },
            });
        }
        "HashMap" | "BTreeMap" => {
            let ordered = name == "BTreeMap";
            if args.len() != 2 {
                return Err(Blocked::unconstructible(format!("{name}<?, ?>")));
            }
            let key = lower(ctx, &args[0])?;
            if !matches!(key.build, Build::Str) {
                return Err(Blocked::unconstructible(format!("{name} with a non-string key: serde_json map keys are strings")));
            }
            let value = lower(ctx, &args[1])?;
            return Ok(Lowered {
                ty: TypeNode::Collection {
                    collection: CollectionKind::Map,
                    element: Box::new(value.ty),
                    key: Some(Box::new(TypeNode::Scalar { scalar: ScalarKind::String, bounds: None, length: None })),
                    length: Some(LengthBounds { min: None, max: Some(64) }),
                },
                build: Build::Map { value: Box::new(value.build), ordered },
            });
        }
        "Option" => {
            let Some(inner) = args.first() else { return Err(Blocked::unconstructible("Option<?>")) };
            let lowered = lower(ctx, inner)?;
            return Ok(Lowered {
                ty: TypeNode::Composite {
                    composite: CompositeKind::Union,
                    members: vec![lowered.ty, TypeNode::null()],
                    discriminant: None,
                },
                build: Build::Option { inner: Box::new(lowered.build) },
            });
        }
        "PhantomData" => return Err(Blocked::unconstructible("PhantomData")),
        _ => {}
    }

    if written == "serde_json::Value" || written == "serde_json::raw::RawValue" {
        let members = vec![
            TypeNode::Scalar { scalar: ScalarKind::Boolean, bounds: None, length: None },
            TypeNode::Scalar { scalar: ScalarKind::Number, bounds: Some(NumberBounds::default()), length: None },
            TypeNode::Scalar { scalar: ScalarKind::String, bounds: None, length: None },
            TypeNode::null(),
            TypeNode::Collection {
                collection: CollectionKind::Array,
                element: Box::new(TypeNode::Scalar {
                    scalar: ScalarKind::BigInt,
                    bounds: Some(NumberBounds { int: true, finite_only: true, min: None, max: None }),
                    length: None,
                }),
                key: None,
                length: Some(LengthBounds { min: None, max: Some(64) }),
            },
        ];
        return Ok(Lowered {
            ty: TypeNode::Composite { composite: CompositeKind::Union, members, discriminant: None },
            build: Build::JsonValue,
        });
    }

    // A project-local type: resolved through the parsed index, bounded for recursion.
    if let Some((full, def)) = ctx.resolve(&written) {
        let full = full.clone();
        if ctx.stack.contains(&full) {
            return Err(Blocked::unconstructible(format!("recursive type {full}")));
        }
        if !args.is_empty() {
            // A generic project type: the driver cannot pick an instantiation.
            return Err(Blocked::unconstructible(full));
        }
        ctx.stack.push(full.clone());
        let result = match &def.kind {
            TypeKind::Struct { fields } => {
                let mut builds = Vec::new();
                let mut nodes = Vec::new();
                let mut blocked = None;
                for field in fields {
                    if !field.public {
                        blocked = Some(Blocked::unconstructible(full.clone()));
                        break;
                    }
                    match lower(ctx, &field.ty) {
                        Ok(lowered) => {
                            builds.push((field.name.clone(), lowered.build));
                            nodes.push(Field { name: field.name.clone(), ty: lowered.ty, required: true });
                        }
                        Err(b) => {
                            blocked = Some(b);
                            break;
                        }
                    }
                }
                match blocked {
                    Some(b) => Err(b),
                    None => Ok(Lowered {
                        ty: TypeNode::Object { name: Some(full.clone()), fields: nodes, id: None },
                        build: Build::Struct { path: full, fields: builds },
                    }),
                }
            }
            TypeKind::Enum { variants } => {
                let mut out = Vec::new();
                let mut members = Vec::new();
                let mut blocked: Option<Blocked> = None;
                for variant in variants {
                    if blocked.is_some() {
                        break;
                    }
                    match variant {
                        VariantDef::Unit(name) => {
                            out.push(Variant { name: name.clone(), shape: VariantShape::Unit });
                            members.push(TypeNode::Literal { values: vec![serde_json::json!(name)] });
                        }
                        VariantDef::Tuple(name, types) => {
                            let mut builds = Vec::new();
                            let mut tys = Vec::new();
                            for element in types {
                                match lower(ctx, element) {
                                    Ok(lowered) => {
                                        builds.push(lowered.build);
                                        tys.push(lowered.ty);
                                    }
                                    Err(b) => {
                                        blocked = Some(b);
                                        break;
                                    }
                                }
                            }
                            out.push(Variant { name: name.clone(), shape: VariantShape::Tuple(builds) });
                            members.push(TypeNode::Tuple { items: tys });
                        }
                        VariantDef::Struct(name, fields) => {
                            let mut builds = Vec::new();
                            let mut nodes = Vec::new();
                            for field in fields {
                                if !field.public {
                                    blocked = Some(Blocked::unconstructible(full.clone()));
                                    break;
                                }
                                match lower(ctx, &field.ty) {
                                    Ok(lowered) => {
                                        builds.push((field.name.clone(), lowered.build));
                                        nodes.push(Field { name: field.name.clone(), ty: lowered.ty, required: true });
                                    }
                                    Err(b) => {
                                        blocked = Some(b);
                                        break;
                                    }
                                }
                            }
                            out.push(Variant { name: name.clone(), shape: VariantShape::Struct(builds) });
                            members.push(TypeNode::Object { name: None, fields: nodes, id: None });
                        }
                    }
                }
                match blocked {
                    Some(b) => Err(b),
                    None => Ok(Lowered {
                        ty: TypeNode::Composite { composite: CompositeKind::Union, members, discriminant: None },
                        build: Build::Enum { path: full, variants: out },
                    }),
                }
            }
        };
        ctx.stack.pop();
        return result;
    }

    // Nothing matched: the type is outside the parsed set (a dependency's type, `Result`, a
    // generic parameter). Its own name is the blocker's name.
    Err(Blocked::unconstructible(written))
}

fn string_like(build: Build) -> Lowered {
    Lowered {
        ty: TypeNode::Scalar {
            scalar: ScalarKind::String,
            bounds: None,
            length: Some(LengthBounds { min: None, max: Some(4096) }),
        },
        build,
    }
}

fn int_bounds(t: &str) -> (f64, f64) {
    match t {
        "i8" => (i8::MIN as f64, i8::MAX as f64),
        "i16" => (i16::MIN as f64, i16::MAX as f64),
        "i32" => (i32::MIN as f64, i32::MAX as f64),
        "i64" => (i64::MIN as f64, i64::MAX as f64),
        "isize" => (isize::MIN as f64, isize::MAX as f64),
        "u8" => (0.0, u8::MAX as f64),
        "u16" => (0.0, u16::MAX as f64),
        "u32" => (0.0, u32::MAX as f64),
        "u64" => (0.0, u64::MAX as f64),
        "usize" => (0.0, usize::MAX as f64),
        _ => (0.0, 0.0),
    }
}

/// The written spelling of a type path as the source wrote it, with `crate::` and `self::`
/// stripped and lifetimes dropped: this is the lookup key into the parsed type index.
pub fn written_path(ty: &Type) -> String {
    let Type::Path(path) = ty else { return String::new() };
    if path.qself.is_some() {
        return String::new();
    }
    let mut out = String::new();
    for segment in &path.path.segments {
        if !out.is_empty() {
            out.push_str("::");
        }
        out.push_str(&segment.ident.to_string());
    }
    if let Some(rest) = out.strip_prefix("crate::") {
        out = rest.to_string();
    }
    if let Some(rest) = out.strip_prefix("self::") {
        out = rest.to_string();
    }
    out
}
