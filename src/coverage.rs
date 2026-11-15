//! Coverage: find the toolchain's `llvm-profdata`, read one call's raw profile, and attribute
//! the executed functions to the discovery universe.
//!
//! The driver child is built with `-Cinstrument-coverage` and dumps the instrumentation
//! runtime's buffer to a file at exit. Parsing that binary buffer by hand would tie the
//! harness to one LLVM raw-profile revision - the format carries no version-compatibility
//! guarantee - so the harness reads it with the `llvm-profdata` from the same toolchain that
//! compiled the driver, the same pairing `cargo-llvm-cov` uses. When the component is absent
//! the handshake drops `coverage` and every other method still works.
//!
//! A hit is a function whose first counter - the function-entry counter - is non-zero. The
//! name `llvm-profdata` prints is the mangled symbol; `rustc-demangle` turns it into the
//! `module::path::name` spelling the universe is keyed by, so private functions that ran
//! inside a call are attributed too.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest as _, Sha256};

/// The edge id a universe key gets, in the outcome digest and in `coverageMap` alike.
pub fn edge_id(key: &str) -> u32 {
    let digest = Sha256::digest(key.as_bytes());
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

/// The toolchain's `llvm-profdata`, resolved the same way `cargo-llvm-cov` resolves it.
pub struct Coverage {
    pub profdata: PathBuf,
}

/// The demangled spelling of a symbol, normalized to the universe's key spelling:
/// `afz_engine::git::parse`. `rustc-demangle` renders the crate disambiguator
/// (`probe[6502329edc43e610]::helper`) and generic instantiations (`foo::bar<i32>`); the
/// disambiguator is stripped here, and the caller tries the generic cut as a fallback.
pub fn demangle(symbol: &str) -> String {
    let demangled = rustc_demangle::try_demangle(symbol)
        .map(|d| d.to_string())
        .unwrap_or_else(|_| symbol.to_string());
    strip_disambiguators(&demangled)
}

/// Remove `[hex]` crate-disambiguator groups: `probe[6502329edc43e610]::helper` ->
/// `probe::helper`.
pub fn strip_disambiguators(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut depth = 0usize;
    for c in name.chars() {
        match c {
            '[' => depth += 1,
            ']' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

impl Coverage {
    /// Find `llvm-profdata`: the explicit override, then the sysroot's `llvm-tools`
    /// component, then `PATH`. `None` means the scan runs without coverage.
    pub fn detect() -> Option<Coverage> {
        if let Some(explicit) = std::env::var_os("AFZ_LLVM_PROFDATA") {
            let path = PathBuf::from(explicit);
            if path.is_file() {
                return Some(Coverage { profdata: path });
            }
            return None;
        }
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
        if let Some(profdata) = sysroot_profdata(&rustc) {
            return Some(Coverage { profdata });
        }
        which("llvm-profdata").map(|profdata| Coverage { profdata })
    }

    /// The demangled names of the functions the call executed, from one raw profile.
    pub fn hits(&self, profraw: &Path) -> Result<Vec<String>, String> {
        let output = Command::new(&self.profdata)
            .arg("show")
            .arg("-all-functions")
            .arg("-text")
            .arg(profraw)
            .output()
            .map_err(|e| format!("{} did not start: {e}", self.profdata.display()))?;
        if !output.status.success() {
            return Err(format!(
                "llvm-profdata failed: {}",
                String::from_utf8_lossy(&output.stderr).lines().next().unwrap_or("")
            ));
        }
        Ok(parse_show(&String::from_utf8_lossy(&output.stdout)))
    }
}

/// Parse `llvm-profdata show -text -all-functions` on a profraw: per function, a name line,
/// then `# Func Hash:` and a bare hash, `# Num Counters:` and a bare count, then
/// `# Counter Values:` and the counters; the first counter is the entry count.
fn parse_show(text: &str) -> Vec<String> {
    #[derive(PartialEq)]
    enum Field {
        Name,
        Hash,
        Count,
        Values,
    }
    let mut hits = Vec::new();
    let mut current: Option<String> = None;
    let mut field = Field::Name;
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            // A blank line ends one function's block; the next bare line is a name again.
            field = Field::Name;
            continue;
        }
        match line {
            "# Func Hash:" => field = Field::Hash,
            "# Num Counters:" => field = Field::Count,
            "# Counter Values:" => field = Field::Values,
            _ if line.starts_with('#') => {}
            _ => match field {
                Field::Name => {
                    current = Some(line.to_string());
                    // The hash and counter-count lines follow the name; stay in `Name` only
                    // until the first labelled section re-sets the field.
                }
                Field::Hash | Field::Count => {}
                Field::Values => {
                    // Only the entry counter decides a hit: region counters describe
                    // branches, and a function that ran has a non-zero entry count.
                    if line.parse::<u64>().is_ok_and(|count| count > 0) {
                        if let Some(name) = current.take() {
                            hits.push(demangle(&name));
                        }
                    }
                    // The remaining counters of this function are bare lines too, but a
                    // second one never re-fires: `current` is taken after the first.
                    field = Field::Hash;
                }
            },
        }
    }
    hits
}

fn sysroot_profdata(rustc: &str) -> Option<PathBuf> {
    let output = Command::new(rustc).arg("--print").arg("sysroot").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let sysroot = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let rustlib = sysroot.join("lib").join("rustlib");
    let entries = std::fs::read_dir(&rustlib).ok()?;
    for entry in entries.flatten() {
        let candidate = entry.path().join("bin").join("llvm-profdata");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).find_map(|dir| {
        let candidate = dir.join(name);
        candidate.is_file().then_some(candidate)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_output_yields_only_functions_with_a_nonzero_entry_counter() {
        let text = "\
_RNvCs8FFjms3Z1Gm_5probe6helper
# Func Hash:
10107070405104815653
# Num Counters:
2
# Counter Values:
3
0

_RNvCs8FFjms3Z1Gm_5probe6unused
# Func Hash:
16864665497575098779
# Num Counters:
1
# Counter Values:
0

";
        let hits = parse_show(text);
        assert_eq!(hits, vec!["probe::helper".to_string()], "only the function that ran is a hit");
    }

    #[test]
    fn edge_ids_are_stable_and_distinct() {
        assert_eq!(edge_id("afz_engine::git::parse"), edge_id("afz_engine::git::parse"));
        assert_ne!(edge_id("afz_engine::git::parse"), edge_id("afz_engine::corpus::insert"));
    }
}
