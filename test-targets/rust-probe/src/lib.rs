//! A small Rust library the README's scan example points at: a few real functions, one of
//! which panics on an input the generator can reach.

/// Splits `text` on `separator` and returns the pieces with their original spacing gone.
pub fn split_words(text: String, separator: char) -> Vec<String> {
    text.split(separator).map(|piece| piece.trim().to_string()).filter(|piece| !piece.is_empty()).collect()
}

/// Joins the pieces back with `separator`, refusing any piece that already contains it.
pub fn join_words(pieces: Vec<String>, separator: String) -> Result<String, String> {
    for piece in &pieces {
        if piece.contains(separator.as_str()) {
            return Err(format!("{piece:?} already contains {separator:?}"));
        }
    }
    Ok(pieces.join(&separator))
}

/// The value at `index`, rotated left by `shift` bits.
pub fn rotate(values: Vec<u64>, index: usize, shift: u32) -> Option<u64> {
    values.get(index).map(|value| value.rotate_left(shift % 64))
}

/// Decodes a `key=value` line. A line that starts with `!` is a comment in this format, and
/// the panic on it is the bug the scan is meant to find.
pub fn decode(line: String) -> (String, String) {
    if line.starts_with('!') {
        panic!("decode: comment line reached the decoder: {line}");
    }
    match line.split_once('=') {
        Some((key, value)) => (key.trim().to_string(), value.trim().to_string()),
        None => (line.trim().to_string(), String::new()),
    }
}

/// The running total of `steps`, refusing a total that would leave the range the caller
/// declared.
pub fn total(steps: Vec<i64>, limit: i64) -> Result<i64, String> {
    let sum: i64 = steps.iter().sum();
    if sum > limit {
        return Err(format!("total {sum} exceeds the limit {limit}"));
    }
    Ok(sum)
}
