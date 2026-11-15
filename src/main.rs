//! The Rust harness plugin: a JSON-RPC server on stdio that fuzzes Rust libraries through a
//! generated cargo driver.
//!
//! It is a harness plugin like `js-ts` and `wasm` are, and it speaks the same eight methods,
//! which is the point: the engine drives a Rust target with the same scheduler, corpus, and
//! oracles it uses for a package on disk, and nothing in the engine learns that the target is
//! compiled. Discovery parses sources with `syn` and never executes them, so the handshake
//! says `discoverRequiresExecution: false`; the compilation happens in `prepare`, where the
//! generated driver crate is built once per scan and the repair loop turns a target the
//! compiler refuses into a skip.
//!
//! Every invocation runs in a fresh driver child in its own process group: the deadline cuts
//! by killing the group, a panic is caught and reported with its source location as the fault
//! frame, and the target's own stdout writes land in a pipe the protocol never reads.

mod coverage;
mod discover;
mod driver;
mod lower;
mod reproducer;

use std::io;
use std::path::PathBuf;

use afz_protocol::rpc::{self, parse_request, read_line, write_line, Method, Request, Response};
use afz_protocol::{
    Capability, CoverageEntry, CoverageMap, DiscoverReq, Discovery, FailedOutcome, FaultFrame, FaultSignature, Handshake,
    InvokeReq, MaterializedCall, OkOutcome, Outcome, PrepareReq, PrepareResp, ReadyResp, RejectedOutcome, ReproducerReq,
    ReproducerResp, SkipReason, TargetClass, ValueNode, ValueTree, PROTOCOL_VERSION,
};
use serde::de::DeserializeOwned;

use crate::coverage::Coverage;
use crate::discover::{Inventory, Tgt};

/// A request the plugin cannot answer at all: an unknown target, or a method this harness
/// does not implement.
const INVALID_REQUEST: i64 = -32600;
/// Parameters the plugin cannot read.
const INVALID_PARAMS: i64 = -32602;

fn main() {
    let mut stdin = rpc::buffered(io::stdin());
    let mut stdout = rpc::buffered_writer(io::stdout());
    let mut harness = Harness::new();
    let mut buf = String::new();
    loop {
        let line = match read_line(&mut stdin, &mut buf) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(_) => break,
        };
        let response = match parse_request(&line) {
            Ok(request) => harness.respond(&request),
            Err(_) => Response::err(0, rpc::PARSE_ERROR, "the plugin received a line that is not JSON"),
        };
        if write_line(&mut stdout, &response).is_err() {
            break;
        }
    }
}

/// The plugin's state across one scan: one discovery, one built driver, one coverage tool.
struct Harness {
    inventory: Option<Inventory>,
    driver: Option<driver::Driver>,
    coverage: Option<Coverage>,
}

impl Harness {
    fn new() -> Harness {
        Harness { inventory: None, driver: None, coverage: Coverage::detect() }
    }

    fn respond(&mut self, request: &Request) -> Response {
        let id = request.id;
        let outcome = match Method::from_wire(&request.method) {
            None => Err((rpc::METHOD_NOT_FOUND, format!("the rust harness does not answer {}", request.method))),
            Some(method) => match method {
                Method::Handshake => Ok(serde_json::to_value(self.handshake()).expect("a handshake serializes")),
                Method::Discover => params(request).and_then(|req| self.discover(req)).and_then(json),
                Method::Prepare => params(request).and_then(|req| self.prepare(req)).and_then(json),
                Method::Invoke => params(request).and_then(|req| self.invoke(req)).and_then(json),
                Method::Reproducer => params(request).and_then(|req| self.reproducer(req)).and_then(json),
                Method::CoverageMap => Ok(serde_json::to_value(self.coverage_map()).expect("a coverage map serializes")),
                Method::Ready => Ok(serde_json::to_value(ReadyResp { ready: true, detail: None }).expect("ready serializes")),
                Method::Minimize => Err((rpc::METHOD_NOT_FOUND, "the rust harness does not declare `minimize`".into())),
            },
        };
        match outcome {
            Ok(result) => Response::ok(id, result),
            Err((code, message)) => Response::err(id, code, message),
        }
    }

    /// What the engine can ask of this plugin. `coverage` rides only when the toolchain's
    /// `llvm-profdata` exists, because the digest is read through it.
    fn handshake(&self) -> Handshake {
        let mut capabilities = vec![Capability::Reproducer, Capability::Stateful];
        if self.coverage.is_some() {
            capabilities.insert(0, Capability::Coverage);
        }
        Handshake {
            protocol_version: PROTOCOL_VERSION.to_string(),
            name: "rust".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            target_class: TargetClass::DesignTime,
            capabilities,
            languages: vec!["rust".to_string()],
            // Discovery parses sources; it never runs target code.
            discover_requires_execution: false,
        }
    }

    fn discover(&mut self, req: DiscoverReq) -> Result<Discovery, (i64, String)> {
        let inventory = discover::discover(&req).map_err(|e| (rpc::PLUGIN_ERROR, e))?;
        let discovery = inventory.discovery.clone();
        self.inventory = Some(inventory);
        // The previous scan's driver, if any, was rendered for a different tree.
        self.driver = None;
        Ok(discovery)
    }

    /// Build the driver on the first call that needs it: `prepare` is where the engine asks
    /// whether a call can be made at all, and building is the honest way to answer.
    fn ensure_driver(&mut self) -> Result<(), (i64, String)> {
        if self.driver.is_some() {
            return Ok(());
        }
        let inventory = self.inventory.as_ref().ok_or((INVALID_REQUEST, "discover has not run".to_string()))?;
        let built = driver::build(inventory).map_err(|e| (rpc::PLUGIN_ERROR, e))?;
        self.driver = Some(built);
        Ok(())
    }

    fn target(&self, target_id: &str) -> Result<&Tgt, (i64, String)> {
        let inventory = self.inventory.as_ref().ok_or((INVALID_REQUEST, "discover has not run".to_string()))?;
        inventory
            .targets
            .iter()
            .find(|tgt| tgt.id == target_id)
            .ok_or((INVALID_REQUEST, format!("no target with id {target_id}")))
    }

    fn prepare(&mut self, req: PrepareReq) -> Result<PrepareResp, (i64, String)> {
        let tgt = self.target(&req.target_id)?.clone();
        match self.materialize(&tgt, &req.values)? {
            Ok(()) => Ok(PrepareResp::Ok {
                materialized: MaterializedCall { handle: req.target_id, summary: driver::summarize(&tgt, &req.values) },
            }),
            Err(reason) => Ok(PrepareResp::Skip { reason }),
        }
    }

    /// Check the request's values against the parameter graph and the repair loop's verdict.
    /// `Ok(Err(skip))` is a protocol answer, not a plugin failure.
    fn materialize(&mut self, tgt: &Tgt, values: &[ValueTree]) -> Result<Result<(), SkipReason>, (i64, String)> {
        self.ensure_driver()?;
        if self.driver.as_ref().is_some_and(|driver| driver.dropped.iter().any(|d| d == &tgt.id)) {
            return Ok(Err(SkipReason::UnconstructibleParameter));
        }
        if values.len() != tgt.params.len() {
            return Ok(Err(SkipReason::UnsupportedSignature));
        }
        for (param, value) in tgt.params.iter().zip(values) {
            if driver::value_for(&param.build, value).is_err() {
                return Ok(Err(SkipReason::UnconstructibleParameter));
            }
        }
        Ok(Ok(()))
    }

    fn invoke(&mut self, req: InvokeReq) -> Result<Outcome, (i64, String)> {
        let tgt = self.target(&req.target_id)?.clone();
        self.ensure_driver()?;
        let driver = self.driver.as_ref().expect("ensure_driver built it");
        let root = self.inventory.as_ref().expect("ensure_driver needed it").root.clone();
        if driver.dropped.iter().any(|d| d == &tgt.id) {
            return Ok(afz_protocol::Outcome::Rejected(RejectedOutcome {
                duration_ms: 0.0,
                coverage: None,
                via: "unmaterializable".into(),
                detail: format!("{}: the generated driver does not compile this call", tgt.name),
            }));
        }
        let mut args = Vec::new();
        for (param, value) in tgt.params.iter().zip(&req.values) {
            match driver::value_for(&param.build, value) {
                Ok(argument) => args.push(argument),
                Err(detail) => {
                    return Ok(afz_protocol::Outcome::Rejected(RejectedOutcome {
                        duration_ms: 0.0,
                        coverage: None,
                        via: "unmaterializable".into(),
                        detail: format!("{} cannot be built for {}: {detail}", prepared_shape(value), tgt.name),
                    }))
                }
            }
        }

        let profraw: Option<PathBuf> = self.coverage.as_ref().map(|_| driver.profiles.join(format!("{}.profraw", req.invocation_id)));
        let (run, duration) = driver::run(driver, &tgt, args, std::time::Duration::from_millis(req.deadline_ms), profraw.as_deref());
        let duration_ms = duration.as_secs_f64() * 1000.0;
        let edges = self.coverage_hits(profraw.as_deref(), req.collect_coverage);
        let coverage = req.collect_coverage.then_some(edges);

        Ok(match run {
            driver::Run::Answered(answer) => {
                let status = answer.get("status").and_then(|s| s.as_str()).unwrap_or("");
                match status {
                    "returned" => afz_protocol::Outcome::Ok(OkOutcome {
                        duration_ms,
                        memory_bytes: None,
                        coverage,
                        value: answer.get("value").filter(|v| !v.is_null()).map(value_tree),
                    }),
                    "returned-err" => afz_protocol::Outcome::Rejected(RejectedOutcome {
                        duration_ms,
                        coverage,
                        via: "guard-site".into(),
                        detail: answer.get("display").and_then(|d| d.as_str()).unwrap_or("Err").to_string(),
                    }),
                    "returned-none" => afz_protocol::Outcome::Rejected(RejectedOutcome {
                        duration_ms,
                        coverage,
                        via: "guard-site".into(),
                        detail: "returned None".into(),
                    }),
                    "panicked" => {
                        // The compiler saw the crate through the driver's absolute path
                        // dependency; the report speaks scan-root-relative paths, the same
                        // spelling discovery puts in `origin.file`.
                        let written = answer.get("file").and_then(|f| f.as_str()).unwrap_or("");
                        let file = std::path::Path::new(written).strip_prefix(&root).map(|rel| rel.display().to_string()).unwrap_or_else(|_| written.to_string());
                        let line = answer.get("line").and_then(|l| l.as_u64()).unwrap_or(0) as u32;
                        let frames = if file.is_empty() {
                            Vec::new()
                        } else {
                            vec![FaultFrame { file, line, column: None, fn_name: Some(tgt.name.clone()) }]
                        };
                        afz_protocol::Outcome::Failed(FailedOutcome {
                            duration_ms,
                            coverage,
                            via: "panic".into(),
                            fault: FaultSignature {
                                class: "Panic".into(),
                                message: answer.get("message").and_then(|m| m.as_str()).unwrap_or("panic").to_string(),
                                frames,
                            },
                        })
                    }
                    _ => afz_protocol::Outcome::Failed(FailedOutcome {
                        duration_ms,
                        coverage,
                        via: "driver-error".into(),
                        fault: FaultSignature {
                            class: "DriverError".into(),
                            message: answer.get("message").and_then(|m| m.as_str()).unwrap_or("the driver refused the call").to_string(),
                            frames: Vec::new(),
                        },
                    }),
                }
            }
            driver::Run::Deadline => afz_protocol::Outcome::Failed(FailedOutcome {
                duration_ms,
                coverage,
                via: "deadline-cut".into(),
                fault: FaultSignature {
                    class: "DeadlineCut".into(),
                    message: format!("{} overran its {} ms deadline and the driver process group was killed", tgt.name, req.deadline_ms),
                    frames: Vec::new(),
                },
            }),
            driver::Run::Silent(detail) => afz_protocol::Outcome::Failed(FailedOutcome {
                duration_ms,
                coverage,
                via: "driver-died".into(),
                fault: FaultSignature { class: "DriverDied".into(), message: detail, frames: Vec::new() },
            }),
        })
    }

    /// The universe keys the raw profile attributes to this call, as edge ids; `None` when
    /// coverage was not collected or the profile cannot be read.
    fn coverage_hits(&mut self, profraw: Option<&std::path::Path>, collect: bool) -> Vec<u32> {
        let Some(path) = profraw.filter(|_| collect) else {
            return Vec::new();
        };
        let result = match self.coverage.as_ref() {
            Some(coverage) if path.exists() => coverage.hits(path),
            _ => Err("no coverage tool or no profile".into()),
        };
        let _ = std::fs::remove_file(path);
        let Ok(names) = result else { return Vec::new() };
        let Some(inventory) = self.inventory.as_ref() else { return Vec::new() };
        let mut edges: Vec<u32> = Vec::new();
        for name in names {
            let key = if inventory.universe.contains_key(&name) {
                Some(name)
            } else {
                let cut = name.split('<').next().unwrap_or(&name).to_string();
                inventory.universe.contains_key(&cut).then_some(cut)
            };
            if let Some(key) = key {
                let edge = coverage::edge_id(&key);
                if !edges.contains(&edge) {
                    edges.push(edge);
                }
            }
        }
        edges.sort_unstable();
        edges
    }

    fn reproducer(&self, req: ReproducerReq) -> Result<ReproducerResp, (i64, String)> {
        let tgt = self.target(&req.target_id)?;
        let script = reproducer::script(tgt, &req.values).map_err(|e| (rpc::PLUGIN_ERROR, e))?;
        Ok(ReproducerResp { extension: "rs".into(), script })
    }

    /// The map from edge ids to source ranges: every function in the universe, public or
    /// private, because any of them can appear in an invocation's digest.
    fn coverage_map(&self) -> CoverageMap {
        let Some(inventory) = self.inventory.as_ref() else { return CoverageMap::default() };
        let mut entries: Vec<CoverageEntry> = inventory
            .universe
            .iter()
            .map(|(key, entry)| CoverageEntry {
                edge: coverage::edge_id(key),
                url: entry.file.clone(),
                start: entry.start,
                end: entry.end,
            })
            .collect();
        entries.sort_by(|a, b| a.url.cmp(&b.url).then(a.start.cmp(&b.start)));
        CoverageMap { entries }
    }
}

fn params<T: DeserializeOwned>(request: &Request) -> Result<T, (i64, String)> {
    let value = request.params.clone().unwrap_or(serde_json::Value::Null);
    serde_json::from_value(value).map_err(|e| (INVALID_PARAMS, format!("{}: {e}", request.method)))
}

fn json(value: impl serde::Serialize) -> Result<serde_json::Value, (i64, String)> {
    serde_json::to_value(value).map_err(|e| (rpc::PLUGIN_ERROR, e.to_string()))
}

/// A returned JSON value as a `ValueTree`, so the engine's corpus can keep it.
fn value_tree(value: &serde_json::Value) -> ValueTree {
    ValueTree::new(match value {
        serde_json::Value::Null => ValueNode::Null,
        serde_json::Value::Bool(v) => ValueNode::Boolean { value: *v },
        serde_json::Value::Number(n) => ValueNode::number(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => ValueNode::string(s.clone()),
        serde_json::Value::Array(items) => ValueNode::Array { items: items.iter().map(value_tree).collect() },
        serde_json::Value::Object(fields) => {
            ValueNode::Object { fields: fields.iter().map(|(name, v)| (name.clone(), value_tree(v))).collect() }
        }
    })
}

/// A short name for the node kind in an `unmaterializable` rejection detail.
fn prepared_shape(value: &ValueTree) -> &'static str {
    match &value.node {
        ValueNode::Null => "null",
        ValueNode::Undefined => "undefined",
        ValueNode::Boolean { .. } => "a boolean",
        ValueNode::Number { .. } => "a number",
        ValueNode::BigInt { .. } => "a big integer",
        ValueNode::String { .. } => "a string",
        ValueNode::Literal { .. } => "a literal",
        ValueNode::Array { .. } => "an array",
        ValueNode::Set { .. } => "a set",
        ValueNode::Map { .. } => "a map",
        ValueNode::Object { .. } => "an object",
        ValueNode::Tuple { .. } => "a tuple",
        ValueNode::Buffer { .. } => "a buffer",
        ValueNode::Function { .. } => "a function stub",
        ValueNode::Stream { .. } => "a stream",
        ValueNode::Opaque { .. } => "an opaque value",
    }
}

