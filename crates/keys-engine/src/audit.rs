//! Audit trail: one JSONL line per rotation step (public fingerprints only, never key material) and a matching
//! 6W event (`niyantrak.6w/1`: who, whom, what, where, why, which + when) that `niyantrak telemetry ingest` or the
//! sink `POST /v1/events` accepts.

use crate::identity::Identity;
use crate::timeutil;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

pub const SCHEMA_6W: &str = "niyantrak.6w/1";
const OUTCOMES: &[&str] = &["allowed", "masked", "local", "blocked", "needs_approval", "approved", "rejected", "error"];

/// One line of `ssh-rotation.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditLine {
    pub ts: String,
    pub connection: String,
    pub source: String,
    pub user: String,
    pub target: String,
    pub target_user: String,
    pub step: String,
    pub step_no: u8,
    /// ok | skip | fail | warn | planned
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_fp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_fp: Option<String>,
    pub detail: String,
    pub who: String,
    pub who_id: String,
    pub dry_run: bool,
}

/// A 6W event. Field names and limits follow niyantrak/telemetry/schema.py; `validate()` mirrors its structural
/// rules (allow-listed fields, short one-line labels or paths, `which` also as `<machine>:~/path`, no long digit
/// runs, no e-mail addresses) so a bad event fails here first. The core's identifier recognizers stay authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SixW {
    pub schema: String,
    pub ts: String,
    pub who: String,
    pub who_id: String,
    pub what: String,
    #[serde(rename = "where")]
    pub where_: String,
    pub why: String,
    /// The project / repository / workspace the action touched (`acme/payments-api`, `ws-01:~/projects/app`).
    /// A key rotation is not tied to one, so the engine leaves it out (null in the store).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub which: Option<String>,
    pub outcome: String,
    pub agent: String,
    pub route: String,
    pub machine: String,
    pub rule_ids: Vec<String>,
}

fn word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}
/// LABEL_RX: `^[\w][\w .:/()+#&,'·-]*$`
fn label_form(v: &str) -> bool {
    v.chars().next().is_some_and(word) && v.chars().all(|c| word(c) || " .:/()+#&,'·-".contains(c))
}
/// The core's path characters (`_PATH_CHARS`): label characters plus `@ = ~` and the backslash.
fn path_chars(v: &str) -> bool {
    v.chars().all(|c| word(c) || " .:/\\()+#&,'·@=~-".contains(c))
}
/// PATH_RX: POSIX absolute (`/var/log`), Windows drive (`C:\Users`, `D:/data`) or UNC (`\\server\share`).
fn path_form(v: &str) -> bool {
    let c: Vec<char> = v.chars().take(3).collect();
    let start = c.first() == Some(&'/')
        || (c.len() == 3 && c[0].is_ascii_alphabetic() && c[1] == ':' && (c[2] == '\\' || c[2] == '/'))
        || (c.len() == 3 && c[0] == '\\' && c[1] == '\\' && word(c[2]));
    start && path_chars(v)
}
/// WORKSPACE_RX (`which` only): `<machine>:<path>`, the path may start with `~` (`ws-01:~/projects/app`).
fn workspace_form(v: &str) -> bool {
    let Some((machine, path)) = v.split_once(':') else { return false };
    let path = path.strip_prefix('~').unwrap_or(path);
    let n = machine.chars().count();
    (1..=63).contains(&n)
        && machine.chars().next().is_some_and(word)
        && machine.chars().all(|c| word(c) || c == '.' || c == '-')
        && path.starts_with('/')
        && path_chars(path)
}
/// An e-mail address anywhere in the value (`local@domain.tld`), as the core's recognizer would find it.
fn has_email(v: &str) -> bool {
    v.split(|c: char| !(word(c) || ".+-@".contains(c))).any(|tok| {
        tok.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.split_once('.').is_some_and(|(a, b)| !a.is_empty() && !b.is_empty())
        })
    })
}

pub(crate) fn label_ok(field: &str, v: &str) -> Result<(), String> {
    let v = v.trim();
    let (limit, words) = if field == "why" { (96, 12) } else { (64, 8) };
    if v.is_empty() {
        return Err(format!("{field}: required"));
    }
    if v.chars().count() > limit || v.split_whitespace().count() > words || v.contains('\n') || v.contains('\r') {
        return Err(format!("{field}: free text is not allowed"));
    }
    if !(label_form(v) || path_form(v) || (field == "which" && workspace_form(v))) {
        return Err(format!("{field}: unexpected characters"));
    }
    let digits: String = v.chars().filter(|c| *c != ' ' && *c != '-').collect();
    let mut run = 0;
    for c in digits.chars() {
        run = if c.is_ascii_digit() { run + 1 } else { 0 };
        if run >= 9 {
            return Err(format!("{field}: looks like an identifier value"));
        }
    }
    if has_email(v) {
        return Err(format!("{field}: contains personal data"));
    }
    Ok(())
}

impl SixW {
    pub fn validate(&self) -> Result<(), String> {
        for (f, v) in [("who", &self.who), ("what", &self.what), ("where", &self.where_), ("why", &self.why),
                       ("agent", &self.agent), ("route", &self.route), ("machine", &self.machine)] {
            label_ok(f, v)?;
        }
        if let Some(w) = &self.which {
            label_ok("which", w)?;
        }
        if !OUTCOMES.contains(&self.outcome.as_str()) {
            return Err("outcome: not a 6W outcome".into());
        }
        if self.rule_ids.len() > 16
            || !self.rule_ids.iter().all(|r| {
                !r.is_empty() && r.len() <= 64 && r.chars().all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
            })
        {
            return Err("rule_ids: short codes only".into());
        }
        Ok(())
    }
}

pub fn step_outcome(result: &str) -> &'static str {
    match result {
        "ok" => "allowed",
        "planned" => "needs_approval",
        "skip" => "blocked",
        _ => "error",
    }
}

/// Labels short enough for 6W (a `who` that is not a valid label falls back to "operator account").
pub fn sixw_for(line: &AuditLine, agent: Option<&str>) -> SixW {
    let who = if label_ok("who", &line.who).is_ok() { line.who.clone() } else { "operator account".into() };
    let why = match (line.step.as_str(), line.result.as_str()) {
        ("due", "skip") => "SSH-ROT key younger than max age".to_string(),
        ("due", _) => "SSH-ROT key at or past max age".to_string(),
        ("preflight", "skip") => "SSH-ROT target unreachable, retry next run".to_string(),
        (_, "fail") => "SSH-ROT step failed, old key kept".to_string(),
        (_, "warn") => "SSH-ROT step needs operator attention".to_string(),
        (_, "planned") => "SSH-ROT dry run, nothing changed".to_string(),
        _ => "SSH-ROT one key per connection".to_string(),
    };
    let route = if label_ok("route", &line.connection).is_ok() { line.connection.clone() } else { "ssh connection".into() };
    SixW {
        schema: SCHEMA_6W.into(),
        ts: line.ts.clone(),
        who,
        who_id: line.who_id.clone(),
        what: format!("ssh key rotation {}", line.step),
        where_: if label_ok("where", &line.target).is_ok() { line.target.clone() } else { "ssh target".into() },
        why,
        which: None,
        outcome: step_outcome(&line.result).into(),
        agent: agent.filter(|a| label_ok("agent", a).is_ok()).unwrap_or("niyantrak-keys").to_string(),
        route,
        machine: if label_ok("machine", &line.source).is_ok() { line.source.clone() } else { "this device".into() },
        rule_ids: vec![format!("SSH-ROT-STEP-{}", line.step_no)],
    }
}

/// Collects step lines in memory and appends them to the JSONL files (when paths are set).
#[derive(Debug, Default)]
pub struct Audit {
    pub jsonl: Option<PathBuf>,
    pub sixw: Option<PathBuf>,
    pub agent: Option<String>,
    pub lines: Vec<AuditLine>,
    pub events: Vec<SixW>,
    pub write_errors: Vec<String>,
}

impl Audit {
    pub fn memory() -> Self {
        Self::default()
    }
    pub fn files(jsonl: PathBuf, sixw: PathBuf) -> Self {
        Audit { jsonl: Some(jsonl), sixw: Some(sixw), ..Default::default() }
    }

    fn append(path: &PathBuf, line: &str) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut o = OpenOptions::new();
        o.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(path)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")
    }

    pub fn record(&mut self, line: AuditLine) {
        let ev = sixw_for(&line, self.agent.as_deref());
        if let Err(e) = ev.validate() {
            self.write_errors.push(format!("6W event not written: {e}"));
        } else {
            if let Some(p) = &self.sixw {
                if let Err(e) = Self::append(p, &serde_json::to_string(&ev).unwrap_or_default()) {
                    self.write_errors.push(format!("{}: {e}", p.display()));
                }
            }
            self.events.push(ev);
        }
        if let Some(p) = &self.jsonl {
            if let Err(e) = Self::append(p, &serde_json::to_string(&line).unwrap_or_default()) {
                self.write_errors.push(format!("{}: {e}", p.display()));
            }
        }
        self.lines.push(line);
    }
}

pub fn now_iso() -> String {
    timeutil::iso(timeutil::now())
}

/// Convenience for building lines.
pub fn actor_fields(id: &Identity) -> (String, String) {
    (id.name.clone(), id.stable_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(step: &str, result: &str) -> AuditLine {
        AuditLine {
            ts: "2026-10-23T03:30:00Z".into(),
            connection: "ws-01-edge-01-alice".into(),
            source: "ws-01".into(),
            user: "alice".into(),
            target: "edge-01".into(),
            target_user: "alice".into(),
            step: step.into(),
            step_no: 5,
            result: result.into(),
            old_fp: Some("SHA256:abc".into()),
            new_fp: Some("SHA256:def".into()),
            detail: "verified with only the new key".into(),
            who: "alice".into(),
            who_id: "local:uid:1000@0123456789ab".into(),
            dry_run: false,
        }
    }

    #[test]
    fn sixw_is_valid_and_carries_no_fingerprints() {
        let ev = sixw_for(&line("verify", "ok"), None);
        ev.validate().unwrap();
        let j = serde_json::to_string(&ev).unwrap();
        assert!(!j.contains("SHA256"), "{j}");
        assert!(j.contains("\"where\":\"edge-01\"") && j.contains("SSH-ROT-STEP-5"));
        assert_eq!(sixw_for(&line("verify", "fail"), None).outcome, "error");
        assert_eq!(sixw_for(&line("preflight", "skip"), None).outcome, "blocked");
    }

    #[test]
    fn events_use_the_6w_schema_and_leave_which_out_when_unknown() {
        assert_eq!(SCHEMA_6W, "niyantrak.6w/1");
        let ev = sixw_for(&line("verify", "ok"), None);
        assert_eq!(ev.schema, "niyantrak.6w/1");
        // a key rotation is not tied to a project / repository / workspace: `which` stays absent (null)
        assert_eq!(ev.which, None);
        let j = serde_json::to_string(&ev).unwrap();
        assert!(j.contains("\"schema\":\"niyantrak.6w/1\"") && !j.contains("\"which\""), "{j}");
    }

    #[test]
    fn which_is_serialized_and_validated_when_set() {
        for good in ["acme/payments-api", "group/sub/repo", "ws-01:~/projects/app", "edge-01:/srv/app", "payments",
                     "/var/lib/app", "C:\\Users\\Public", "D:/data", "\\\\fileserver\\share"] {
            let mut ev = sixw_for(&line("verify", "ok"), None);
            ev.which = Some(good.into());
            ev.validate().unwrap_or_else(|e| panic!("{good}: {e}"));
            assert!(serde_json::to_string(&ev).unwrap().contains("\"which\":"), "{good}");
        }
        for bad in ["", "ws-01:~/x;rm", "line\nbreak", "one two three four five six seven eight nine",
                    "build 1234567890", "ws-01:~/9876-54321-0", "-flag", "a|b", "x`y", "$HOME/app",
                    "ws-01:~/alice@example.com", &"a".repeat(65)] {
            let mut ev = sixw_for(&line("verify", "ok"), None);
            ev.which = Some(bad.into());
            let e = ev.validate().expect_err(bad);
            assert!(e.starts_with("which:"), "{bad}: {e}");
            assert!(!e.contains(bad) || bad.is_empty(), "errors name the field, never the value: {e}");
        }
    }

    #[test]
    fn workspace_form_is_only_for_which() {
        assert!(label_ok("which", "ws-01:~/projects/app").is_ok());
        assert!(label_ok("where", "ws-01:~/projects/app").is_err());
        // paths are labels for every field, as in the core
        assert!(label_ok("where", "/var/log").is_ok());
        assert!(label_ok("where", "C:\\Users\\Public").is_ok());
    }

    #[test]
    fn label_rules() {
        assert!(label_ok("what", "ssh key rotation verify").is_ok());
        assert!(label_ok("what", "one two three four five six seven eight nine").is_err());
        assert!(label_ok("what", "a;b").is_err());
        assert!(label_ok("what", "call 9876543210").is_err());
        assert!(label_ok("what", "line\nbreak").is_err());
        assert!(label_ok("what", "-starts-with-dash").is_err());
    }

    #[test]
    fn writes_both_files() {
        let t = tempfile::tempdir().unwrap();
        let mut a = Audit::files(t.path().join("s/a.jsonl"), t.path().join("s/a.6w.jsonl"));
        a.record(line("stage", "ok"));
        a.record(line("install", "ok"));
        let j = fs::read_to_string(t.path().join("s/a.jsonl")).unwrap();
        assert_eq!(j.lines().count(), 2);
        assert!(j.contains("SHA256:def") && !j.contains("PRIVATE"));
        assert_eq!(fs::read_to_string(t.path().join("s/a.6w.jsonl")).unwrap().lines().count(), 2);
        assert!(a.write_errors.is_empty());
    }
}
