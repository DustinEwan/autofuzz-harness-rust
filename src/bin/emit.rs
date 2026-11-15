//! Render the conformance fixture project for the Rust harness.
//!
//! `afz validate-harness` and `afz install-harness` validate a plugin against the template
//! (`crates/afz-conformance/template/v1.json` in the engine repository): twelve semantic
//! properties stated as wire-level expectations. This emitter renders a real crate - a
//! `Cargo.toml` and a `src/lib.rs` with one symbol per property - writes the `autofuzz.json`
//! that points the plugin at it, and writes `afz-conformance-manifest.json` naming the symbol
//! and inputs behind each property. The suite, not this file, decides pass/fail.
//!
//! Rust realizes every property, unlike a bare wasm module: visibility, signature blockers,
//! unconstructible receivers, method receivers, and a refusal channel all exist in the
//! language, and the driver child keeps the protocol channel clean while target code shouts
//! at its own stdout.
//!
//! Usage:
//!   target/release/afz-rust-emit --out /tmp/conformance-rust

use std::path::{Path, PathBuf};

/// The fixture crate's manifest: a plain lib crate with no dependencies, so the driver build
/// needs nothing beyond the toolchain.
const CARGO_TOML: &str = "[package]\nname = \"conformance-rust\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n";

/// The fixture. Each block is commented with the template property it realizes; the suite
/// drives these symbols by discovery name.
const LIB_RS: &str = r#"//! Conformance fixture for the rust harness: one symbol per template property.

pub fn crash(index: u64) -> u64 {
    // crash-unguarded: indexing past the end panics inside this file, so the fault frame
    // names a file inside the rendered root.
    let values = vec![1u64, 2, 3];
    values[index as usize]
}

pub fn bounded(amount: i64) -> Result<i64, String> {
    // guard-refusal: the author wrote the refusal, and an `Err` return is the language's
    // ordinary rejection channel.
    if amount > 100 {
        return Err(format!("{amount} exceeds the limit of 100"));
    }
    Ok(amount)
}

fn hidden(value: u64) -> u64 {
    // private-symbol: otherwise fuzzable-shaped, so the skip can only come from visibility.
    value + 1
}

pub fn callback(transform: fn(u64) -> u64, value: u64) -> u64 {
    // unrepresentable-symbol: a bare function pointer the generator cannot drive.
    transform(value)
}

pub struct Handle {
    // unconstructible-receiver: the private field stops the driver from building `self`.
    descriptor: u64,
}

impl Handle {
    pub fn read(&self) -> u64 {
        self.descriptor
    }
}

pub struct Counter {
    pub value: u64,
}

impl Counter {
    // method-receiver: every pub field is buildable, so the driver constructs the receiver.
    pub fn bump(&mut self, by: u64) -> u64 {
        self.value += by;
        self.value
    }
}

fn branch_left(value: u64) -> u64 {
    value + 1
}

fn branch_right(value: u64) -> u64 {
    value * 2
}

pub fn branch(value: u64) -> u64 {
    // coverage-digest-live: the two inputs execute different private functions, so the two
    // digests differ even though the entry function is the same.
    if value < 10 {
        branch_left(value)
    } else {
        branch_right(value)
    }
}

pub fn noise(value: u64) -> u64 {
    // stdout-purity: the call runs in its own child process, so this cannot reach the
    // plugin's protocol channel.
    println!("noise from the fixture: {value}");
    value
}

pub fn sleeper(value: u64) -> u64 {
    // deadline-sleep: ten seconds, far past any deadline the suite passes.
    std::thread::sleep(std::time::Duration::from_secs(10));
    value
}

pub struct Reading {
    pub code: u64,
}

pub fn reading(value: u64) -> Reading {
    // opaque-return: `Reading` is a project type without `Serialize`, so the driver drops
    // the value instead of serializing it: the call must still answer ok, with no value.
    Reading { code: value }
}

pub struct Silent;

pub fn broken(value: u64) -> Result<u64, Silent> {
    // unbuildable-symbol: discovery accepts this signature - constructible parameter,
    // serializable Ok - but the driver formats the error with `{:?}` and `Silent`
    // implements neither `Debug` nor `Display`. Only this call fails to compile, so the
    // repair loop drops it alone and its siblings survive.
    if value > 100 {
        return Err(Silent);
    }
    Ok(value)
}
"#;

fn autofuzz_json() -> String {
    serde_json::json!({
        "project": "conformance-rust",
        "harness": {
            // No `command`: the plugin the suite launches is the one `afz-harness.json`
            // names, and the crate is everything under `AFZ_ROOT`, which the driver points
            // at this rendered project.
            "name": "rust",
            "include": ["**/*.rs"],
        },
        "budget": { "invocations": 2000, "wallClockMs": 60000, "workers": 0, "maxCorpus": 256, "strategy": "guided" },
        "output": { "dir": ".autofuzz", "renderers": ["json"] },
    })
    .to_string()
}

fn number(n: i64) -> serde_json::Value {
    serde_json::json!({ "node": "number", "value": n, "provenance": "user" })
}

fn receiver(value: i64) -> serde_json::Value {
    serde_json::json!({
        "node": "object",
        "fields": [["value", number(value)]],
        "provenance": "user",
    })
}

fn manifest(check: &Path, lib: &Path) -> String {
    serde_json::json!({
        "templateVersion": 1,
        "properties": {
            "crash-unguarded": { "symbol": "crash", "input": [number(7)] },
            "guard-refusal": { "symbol": "bounded", "input": [number(500)] },
            "private-symbol": { "symbol": "hidden" },
            "unrepresentable-symbol": { "symbol": "callback" },
            "unconstructible-receiver": { "symbol": "Handle::read", "blockedByType": "conformance_rust::Handle" },
            "method-receiver": { "symbol": "Counter::bump", "input": [receiver(0), number(3)] },
            // 0 takes `branch_left` and 20 takes `branch_right`: two invocations that answer
            // the same digest mean a dead or never-reset counter.
            "coverage-digest-live": { "symbol": "branch", "inputs": [[number(0)], [number(20)]] },
            "stdout-purity": { "symbol": "noise" },
            "reproducer-script": { "symbol": "crash", "input": [number(7)] },
            "deadline-sleep": { "symbol": "sleeper", "input": [number(1)] },
            "opaque-return": { "symbol": "reading", "input": [number(3)] },
            "unbuildable-symbol": { "symbol": "broken", "input": [number(0)] },
        },
        // The project judges its own fixture: the check binary reads `src/lib.rs` with `syn`
        // and compiles it with `rustc`, with no protocol and no plugin in the path.
        "validator": [check.display().to_string(), lib.display().to_string()],
    })
    .to_string()
}

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut out: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        if arg == "--out" {
            out = Some(PathBuf::from(args.next().ok_or("usage: afz-rust-emit --out DIR")?));
        }
    }
    let out = out.ok_or("usage: afz-rust-emit --out DIR")?;
    let src = out.join("src");
    std::fs::create_dir_all(&src).map_err(|e| format!("cannot create {}: {e}", src.display()))?;
    let lib = src.join("lib.rs");
    std::fs::write(out.join("Cargo.toml"), CARGO_TOML).map_err(|e| format!("cannot write Cargo.toml: {e}"))?;
    std::fs::write(&lib, LIB_RS).map_err(|e| format!("cannot write {}: {e}", lib.display()))?;
    std::fs::write(out.join("autofuzz.json"), autofuzz_json() + "\n").map_err(|e| e.to_string())?;
    // The fixture validator sits beside this binary in the build directory the install built.
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let check = exe.parent().ok_or("the emitter is not running from a directory")?.join("afz-rust-check");
    std::fs::write(out.join("afz-conformance-manifest.json"), manifest(&check, &lib) + "\n").map_err(|e| e.to_string())?;
    println!("{}", out.display());
    Ok(())
}
