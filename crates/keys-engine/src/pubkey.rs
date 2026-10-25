//! Public key lines: parsing, SHA256 fingerprints (as `ssh-keygen -lf` prints them) and the key comment pattern.
//! Only public material is handled here; private keys are never read by this crate.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubKey {
    pub kind: String,
    pub blob: String,
    pub comment: String,
}

fn is_key_type(t: &str) -> bool {
    t.starts_with("ssh-") || t.starts_with("ecdsa-sha2-") || t.starts_with("sk-")
}

impl PubKey {
    /// Parse a `.pub` file line or an authorized_keys line (options before the key type are skipped).
    pub fn parse(line: &str) -> Option<PubKey> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        let i = toks.iter().position(|t| is_key_type(t))?;
        let blob = toks.get(i + 1)?;
        STANDARD.decode(blob).ok()?;
        Some(PubKey { kind: toks[i].to_string(), blob: blob.to_string(), comment: toks[i + 2..].join(" ") })
    }

    pub fn fingerprint(&self) -> String {
        let raw = STANDARD.decode(&self.blob).unwrap_or_default();
        format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(raw)))
    }

    /// `type blob comment` — the line appended to authorized_keys.
    pub fn line(&self) -> String {
        if self.comment.is_empty() {
            format!("{} {}", self.kind, self.blob)
        } else {
            format!("{} {} {}", self.kind, self.blob, self.comment)
        }
    }
}

/// A comment that follows `<source>-<target>-<user>-<YYYYMMDD>` for the given target node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternComment {
    pub source: String,
    pub target: String,
    pub user: String,
    pub date: String,
}

/// Split a comment against the pattern. Node names contain '-', so the target is matched against the nodes the
/// connection list knows; an unknown target or a missing date means "off-pattern".
pub fn parse_comment<'a, I: IntoIterator<Item = &'a String>>(comment: &str, nodes: I) -> Option<PatternComment> {
    let (rest, date) = comment.rsplit_once('-')?;
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut best: Option<PatternComment> = None;
    for node in nodes {
        let needle = format!("-{node}-");
        if let Some(pos) = rest.find(&needle) {
            let source = &rest[..pos];
            let user = &rest[pos + needle.len()..];
            if source.is_empty() || user.is_empty() || user.chars().any(char::is_whitespace) {
                continue;
            }
            let cand = PatternComment { source: source.into(), target: node.clone(), user: user.into(), date: date.into() };
            // prefer the longest matching node name
            if best.as_ref().is_none_or(|b| b.target.len() < cand.target.len()) {
                best = Some(cand);
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    // a syntactically valid ed25519 public key blob (32 zero bytes of key material) — public data only
    pub const BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn parses_pub_and_authorized_keys_lines() {
        let k = PubKey::parse(&format!("ssh-ed25519 {BLOB} ws-01-gpu-01-alice-20260425")).unwrap();
        assert_eq!(k.kind, "ssh-ed25519");
        assert_eq!(k.comment, "ws-01-gpu-01-alice-20260425");
        let o = PubKey::parse(&format!("from=\"10.0.0.1\",no-pty ssh-ed25519 {BLOB} c d")).unwrap();
        assert_eq!(o.blob, BLOB);
        assert_eq!(o.comment, "c d");
        assert!(PubKey::parse("# comment").is_none());
        assert!(PubKey::parse("ssh-ed25519 !!!notbase64").is_none());
        assert!(PubKey::parse("").is_none());
    }

    #[test]
    fn fingerprint_matches_ssh_keygen_format() {
        let k = PubKey::parse(&format!("ssh-ed25519 {BLOB}")).unwrap();
        let fp = k.fingerprint();
        assert!(fp.starts_with("SHA256:") && fp.len() == 7 + 43, "{fp}");
        assert!(!fp.ends_with('='));
    }

    #[test]
    fn comment_pattern() {
        let nodes: Vec<String> = ["ws-01", "gpu-01", "edge-01"].iter().map(|s| s.to_string()).collect();
        let p = parse_comment("ws-01-gpu-01-root-20260512", &nodes).unwrap();
        assert_eq!((p.source.as_str(), p.target.as_str(), p.user.as_str(), p.date.as_str()),
                   ("ws-01", "gpu-01", "root", "20260512"));
        assert!(parse_comment("ws-01-to-laptop-20260428", &nodes).is_none()); // off-pattern (known 2026-10-20)
        assert!(parse_comment("alice@ws-01", &nodes).is_none());
        assert!(parse_comment("ws-01-gpu-01-alice", &nodes).is_none());
    }
}
