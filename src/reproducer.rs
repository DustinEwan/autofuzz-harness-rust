//! Reproducer: render a standalone `.rs` script that replays one call.
//!
//! The suite stores the bytes verbatim and checks only that the script is non-empty and names
//! the fixture file the fault came from; running it is the reader's act, so the script is
//! written to be pasted into a binary crate with a path dependency on the crate under test.
//! The literals are Rust, not JSON: the point of a `.rs` reproducer is that a Rust reader can
//! see the call the generator made.

use afz_protocol::ValueTree;

use crate::discover::Tgt;
use crate::driver::{self, PassModeSnapshot};
use crate::lower::{Build, VariantShape};

/// The complete script for one call. An `Err` here means a value no longer materializes, and
/// the harness answers the `reproducer` request with a plugin error rather than a broken
/// script.
pub fn script(tgt: &Tgt, values: &[ValueTree]) -> Result<String, String> {
    let mut out = String::new();
    out.push_str(&format!("//! autofuzz reproducer for `{}`\n", tgt.name));
    if let Some(file) = &tgt.descriptor.origin.file {
        out.push_str(&format!("//! Fault source: {file}:{}\n", tgt.descriptor.origin.line.unwrap_or(0)));
    }
    if let Some(module) = &tgt.descriptor.origin.module {
        out.push_str(&format!("//! Module: {module}\n"));
    }
    out.push_str(
        "//!\n\
         //! Replay: create a binary crate whose `Cargo.toml` carries a path dependency on\n\
         //! the crate under test, paste this file into its `src/main.rs`, and `cargo run`.\n\n",
    );
    out.push_str("fn main() {\n");
    for (index, (param, tree)) in tgt.params.iter().zip(values).enumerate() {
        let literal = literal(&param.build, tree)?;
        let ty = driver::binding_type(&param.wrap, &param.build);
        out.push_str(&format!("    let mut a{index}: {ty} = {literal};\n"));
    }
    let snapshot: Vec<PassModeSnapshot> = tgt.params.iter().map(|p| PassModeSnapshot { mode: p.mode, receiver: p.receiver }).collect();
    let args: Vec<String> = snapshot.iter().enumerate().map(|(index, pass)| driver::pass_expression(pass, index)).collect();
    let call = format!("{}({})", tgt.call_path, args.join(", "));
    let call = if tgt.unsafe_call { format!("unsafe {{ {call} }}") } else { call };
    out.push_str(&format!("    let _result = {call};\n    // `_result` is the value the finding was classified on.\n}}\n"));
    Ok(out)
}

/// A Rust literal for one value, checked against the `Build` tree so the script says exactly
/// what the generator drew.
fn literal(build: &Build, tree: &ValueTree) -> Result<String, String> {
    let node = &tree.node;
    Ok(match build {
        Build::Bool => match node {
            afz_protocol::ValueNode::Boolean { value } => value.to_string(),
            _ => return Err("expected a boolean".into()),
        },
        Build::Int(t) => {
            let number = number_of(node)?;
            if t.starts_with('u') {
                format!("{}{t}", number as u64)
            } else {
                format!("{}{t}", number as i64)
            }
        }
        Build::Float(t) => {
            let number = number_of(node)?;
            if number.is_nan() {
                format!("f64::NAN as {t}")
            } else if number == f64::INFINITY {
                format!("f64::INFINITY as {t}")
            } else if number == f64::NEG_INFINITY {
                format!("f64::NEG_INFINITY as {t}")
            } else {
                format!("{number:?}{t}")
            }
        }
        Build::Char => match node {
            afz_protocol::ValueNode::String { value } => match value.chars().next() {
                Some(c) if value.chars().count() == 1 => format!("'{}'", c.escape_debug()),
                _ => return Err("expected exactly one character".into()),
            },
            _ => return Err("expected a string".into()),
        },
        Build::Str => match node {
            afz_protocol::ValueNode::String { value } => format!("{}.to_string()", serde_json::to_string(value).unwrap()),
            _ => return Err("expected a string".into()),
        },
        Build::PathBuf => match node {
            afz_protocol::ValueNode::String { value } => {
                format!("::std::path::PathBuf::from({})", serde_json::to_string(value).unwrap())
            }
            _ => return Err("expected a string".into()),
        },
        Build::JsonValue => format!("::serde_json::json!({})", driver::json_passthrough(node)?.to_string()),
        Build::Vec { inner } => {
            let items: Vec<&ValueTree> = match node {
                afz_protocol::ValueNode::Array { items } | afz_protocol::ValueNode::Stream { items, .. } => items.iter().collect(),
                afz_protocol::ValueNode::Buffer { bytes } => {
                    let parts: Vec<String> = bytes.iter().map(|byte| format!("{byte}u8")).collect();
                    return Ok(format!("vec![{}]", parts.join(", ")));
                }
                _ => return Err("expected an array".into()),
            };
            let parts: Vec<String> = items.iter().map(|item| literal(inner, item)).collect::<Result<_, _>>()?;
            format!("vec![{}]", parts.join(", "))
        }
        Build::Set { inner, ordered } => {
            let set = if *ordered { "::std::collections::BTreeSet" } else { "::std::collections::HashSet" };
            let items: &[ValueTree] = match node {
                afz_protocol::ValueNode::Set { items } | afz_protocol::ValueNode::Array { items } => items,
                _ => return Err("expected a set".into()),
            };
            let parts: Vec<String> = items.iter().map(|item| literal(inner, item)).collect::<Result<_, _>>()?;
            format!("{set}::from([{}])", parts.join(", "))
        }
        Build::Map { value, ordered } => {
            let map = if *ordered { "::std::collections::BTreeMap" } else { "::std::collections::HashMap" };
            let entries: &[(ValueTree, ValueTree)] = match node {
                afz_protocol::ValueNode::Map { entries } => entries,
                _ => return Err("expected a map".into()),
            };
            let parts: Vec<String> = entries
                .iter()
                .map(|(key, value_tree)| match &key.node {
                    afz_protocol::ValueNode::String { value: key_text } => Ok(format!(
                        "({}.to_string(), {})",
                        serde_json::to_string(key_text).unwrap(),
                        literal(value, value_tree)?
                    )),
                    _ => Err("expected a string map key".to_string()),
                })
                .collect::<Result<_, _>>()?;
            format!("{map}::from([{}])", parts.join(", "))
        }
        Build::Tuple { items } => {
            let given: &[ValueTree] = match node {
                afz_protocol::ValueNode::Tuple { items } | afz_protocol::ValueNode::Array { items } => items,
                _ => return Err("expected a tuple".into()),
            };
            if given.len() != items.len() {
                return Err("tuple length mismatch".into());
            }
            let parts: Vec<String> = items.iter().zip(given).map(|(build, tree)| literal(build, tree)).collect::<Result<_, _>>()?;
            format!("({},)", parts.join(", "))
        }
        Build::Option { inner } => {
            if matches!(node, afz_protocol::ValueNode::Null | afz_protocol::ValueNode::Undefined) {
                "::std::option::Option::None".to_string()
            } else {
                format!("::std::option::Option::Some({})", literal(inner, tree)?)
            }
        }
        Build::Struct { path, fields } => {
            let given: &[(String, ValueTree)] = match node {
                afz_protocol::ValueNode::Object { fields } => fields,
                _ => return Err("expected an object".into()),
            };
            let parts: Vec<String> = fields
                .iter()
                .map(|(name, field_build)| -> Result<String, String> {
                    let (_, tree) = given.iter().find(|(given, _)| given == name).ok_or_else(|| format!("missing field {name}"))?;
                    Ok(format!("{name}: {}", literal(field_build, tree)?))
                })
                .collect::<Result<_, _>>()?;
            format!("{path} {{ {}, }}", parts.join(", "))
        }
        Build::Enum { path, variants } => match node {
            afz_protocol::ValueNode::String { value } => {
                if variants.iter().any(|v| v.name == *value && matches!(v.shape, VariantShape::Unit)) {
                    format!("{path}::{value}")
                } else {
                    return Err(format!("{value} is not a unit variant"));
                }
            }
            afz_protocol::ValueNode::Tuple { items } | afz_protocol::ValueNode::Array { items } => {
                let mut out = None;
                for variant in variants {
                    if let VariantShape::Tuple(builds) = &variant.shape {
                        if builds.len() != items.len() {
                            continue;
                        }
                        let attempt: Vec<String> =
                            builds.iter().zip(items).map(|(build, tree)| literal(build, tree)).collect::<Result<_, _>>()?;
                        out = Some(format!("{path}::{}({})", variant.name, attempt.join(", ")));
                        break;
                    }
                }
                out.ok_or("no tuple variant matches")?
            }
            afz_protocol::ValueNode::Object { fields } => {
                let mut out = None;
                for variant in variants {
                    if let VariantShape::Struct(builds) = &variant.shape {
                        let mut parts = Vec::new();
                        let mut ok = true;
                        for (name, field_build) in builds {
                            match fields.iter().find(|(given, _)| given == name) {
                                Some((_, tree)) => match literal(field_build, tree) {
                                    Ok(part) => parts.push(format!("{name}: {part}")),
                                    Err(_) => {
                                        ok = false;
                                        break;
                                    }
                                },
                                None => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok {
                            out = Some(format!("{path}::{} {{ {}, }}", variant.name, parts.join(", ")));
                            break;
                        }
                    }
                }
                out.ok_or("no struct variant matches")?
            }
            _ => return Err("expected an enum value".into()),
        },
    })
}

fn number_of(node: &afz_protocol::ValueNode) -> Result<f64, String> {
    match node {
        afz_protocol::ValueNode::Number { value } => Ok(value.as_f64()),
        afz_protocol::ValueNode::BigInt { value } => value.parse::<f64>().map_err(|_| format!("{value} is not a number")),
        _ => Err("expected a number".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::{ReceiverKind, Tgt};
    use crate::lower::PassMode;
    use afz_protocol::{Effects, Materialization, Origin, TargetClass, TargetDescriptor, ValueNode, ValueTree};

    fn target(call_path: &str, params: Vec<(Build, PassMode, ReceiverKind)>, ret: crate::discover::RetShape) -> Tgt {
        Tgt {
            id: "afz:t:test".into(),
            name: call_path.rsplit("::").next().unwrap().into(),
            call_path: call_path.into(),
            params: params
                .into_iter()
                .map(|(build, mode, receiver)| crate::discover::ParamSpec { build, mode, wrap: crate::lower::Wrap::None, receiver })
                .collect(),
            ret,
            unsafe_call: false,
            descriptor: TargetDescriptor {
                id: "afz:t:test".into(),
                target_class: TargetClass::DesignTime,
                origin: Origin { file: Some("src/lib.rs".into()), line: Some(7), module: Some("probe".into()), http: None },
                name: "probe".into(),
                parameters: Vec::new(),
                returns: None,
                effects: Effects::default(),
                guard_sites: Vec::new(),
                materialization: Materialization::Constructible,
            },
        }
    }

    #[test]
    fn script_names_the_source_file_and_renders_the_call() {
        let tgt = target("probe::bounded", vec![(Build::Int("i64"), PassMode::Value, ReceiverKind::None)], crate::discover::RetShape::Result);
        let script = script(&tgt, &[ValueTree::new(ValueNode::Number { value: afz_protocol::NumberValue::Finite(500.0) })]).unwrap();
        assert!(script.contains("src/lib.rs"), "the script must name the file the fault came from");
        assert!(script.contains("let mut a0: i64 = 500i64;"), "{script}");
        assert!(script.contains("let _result = probe::bounded(a0);"), "{script}");
    }

    #[test]
    fn struct_and_enum_values_render_as_rust_literals() {
        let build = Build::Struct {
            path: "probe::Options".into(),
            fields: vec![("limit".into(), Build::Int("u64")), ("name".into(), Build::Str)],
        };
        let tree = ValueTree::new(ValueNode::Object {
            fields: vec![
                ("limit".into(), ValueTree::new(ValueNode::number(3.0))),
                ("name".into(), ValueTree::string("hi")),
            ],
        });
        assert_eq!(literal(&build, &tree).unwrap(), "probe::Options { limit: 3u64, name: \"hi\".to_string(), }");
    }
}
