//! Canonical JSON byte-identical to niyantrak's `card.card_bytes()`:
//! `json.dumps(card, sort_keys=True, separators=(",", ":"))` with Python's defaults (ensure_ascii: every character
//! outside 0x20..0x7e as a lower-case \uXXXX escape, surrogate pairs above the BMP; floats as Python repr).
//! The control plane verifies the signature over exactly these bytes.

use serde_json::Value;

fn string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ' '..='~' => out.push(ch),
            _ => {
                let mut buf = [0u16; 2];
                for unit in ch.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

/// Python float repr: shortest round-trip digits, always with a '.' or exponent; 1e16 and up use exponent form.
pub fn py_float(f: f64) -> String {
    if f.is_nan() {
        return "NaN".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    let a = f.abs();
    if a != 0.0 && !(1e-4..1e16).contains(&a) {
        // Rust `{:e}` is shortest round-trip too: 1e16 -> "1e16"; Python -> "1e+16"
        let s = format!("{f:e}");
        let (m, e) = s.split_once('e').unwrap();
        let exp: i32 = e.parse().unwrap();
        return format!("{m}e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs());
    }
    let s = format!("{f}");
    if s.contains('.') {
        s
    } else {
        format!("{s}.0")
    }
}

fn value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string())
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string())
            } else {
                out.push_str(&py_float(n.as_f64().unwrap_or(0.0)))
            }
        }
        Value::String(s) => string(out, s),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                value(out, x);
            }
            out.push(']');
        }
        Value::Object(m) => {
            // Python sorts str keys by code point; Rust String order is UTF-8 byte order, which is the same
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(out, k);
                out.push(':');
                value(out, &m[*k]);
            }
            out.push('}');
        }
    }
}

pub fn to_bytes(v: &Value) -> Vec<u8> {
    let mut s = String::new();
    value(&mut s, v);
    s.into_bytes()
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_python_dumps() {
        let v = json!({"b": 1, "a": [true, null, 15.6, 16.0, -0.5], "é": "naïve 😀 \"q\"\n", "c": {"z": 1, "y": "x"}});
        let s = String::from_utf8(to_bytes(&v)).unwrap();
        assert_eq!(
            s,
            "{\"a\":[true,null,15.6,16.0,-0.5],\"b\":1,\"c\":{\"y\":\"x\",\"z\":1},\"\\u00e9\":\"na\\u00efve \\ud83d\\ude00 \\\"q\\\"\\n\"}"
        );
    }

    #[test]
    fn python_float_forms() {
        assert_eq!(py_float(31.3), "31.3");
        assert_eq!(py_float(0.0), "0.0");
        assert_eq!(py_float(1e16), "1e+16");
        assert_eq!(py_float(1.5e-5), "1.5e-05");
        assert_eq!(py_float(123456789.0), "123456789.0");
    }

    #[test]
    fn sha256_is_hex() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    /// Cross-check with the real Python json.dumps when python3 is on PATH (skips otherwise).
    #[test]
    fn cross_check_with_python_if_available() {
        let v = json!({"node_id": "nyk-0123456789ab", "memory_gb": 62.7, "os": {"id": "ubuntu", "version": "24.04"},
                       "role": null, "gpu": [{"name": "Example GPU", "vram_mb": 16384}], "hostname": "dév"});
        let ours = to_bytes(&v);
        let py = std::process::Command::new("python3")
            .args(["-c", "import json,sys; d=json.load(sys.stdin.buffer); sys.stdout.write(json.dumps(d, sort_keys=True, separators=(',', ':')))"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn();
        let Ok(mut child) = py else { return };
        use std::io::Write;
        child.stdin.take().unwrap().write_all(serde_json::to_string(&v).unwrap().as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        if out.status.success() {
            assert_eq!(String::from_utf8(ours).unwrap(), String::from_utf8(out.stdout).unwrap());
        }
    }
}
