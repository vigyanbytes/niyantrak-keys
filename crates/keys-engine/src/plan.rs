//! `plan()` — read-only. For every connection: key age, due date, overdue, reachability with the current key, and
//! drift on the target: each authorized_keys line is declared / declared-mismatch / undeclared / off-pattern, so
//! nothing on a target is trusted without an entry. Nothing is written, created or removed.

use crate::layout::{self, current_key, Layout};
use crate::model::{Policy, RotationConfig};
use crate::pubkey::{parse_comment, PubKey};
use crate::timeutil::{self, DAY};
use crate::transport::Transport;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionStatus {
    pub id: String,
    pub source: String,
    pub user: String,
    pub target: String,
    pub target_user: String,
    /// this device and this OS user own the key (only owned connections are rotated here)
    pub owned: bool,
    pub key_path: Option<String>,
    pub legacy: bool,
    pub fingerprint: Option<String>,
    pub comment: Option<String>,
    pub comment_on_pattern: bool,
    pub rotated_at: Option<String>,
    pub age_days: Option<i64>,
    pub due_at: Option<String>,
    pub due: bool,
    pub overdue: bool,
    pub reachable: Option<bool>,
    pub endpoint: Option<String>,
    pub detail: Option<String>,
    pub retired_copies: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DriftLine {
    pub target: String,
    pub target_user: String,
    pub endpoint: String,
    pub fingerprint: String,
    pub comment: String,
    /// declared | declared-mismatch | undeclared | off-pattern
    pub class: String,
    pub connection: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub total: usize,
    pub owned: usize,
    pub due: usize,
    pub overdue: usize,
    pub unreachable: usize,
    pub undeclared: usize,
    pub off_pattern: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub generated_at: String,
    pub node: String,
    pub user: String,
    pub policy: Policy,
    pub connections: Vec<ConnectionStatus>,
    pub drift: Vec<DriftLine>,
    pub summary: Summary,
}

pub struct PlanOptions {
    /// this device's node name and OS user (connections with this source + user are owned here)
    pub node: String,
    pub user: String,
    /// log in with the current key to test reachability and read authorized_keys (read-only)
    pub probe: bool,
    pub now: i64,
}

pub fn plan(cfg: &RotationConfig, l: &Layout, t: &mut dyn Transport, o: &PlanOptions) -> Plan {
    let p = &cfg.policy;
    let max = p.max_age_days as i64;
    let nodes = cfg.known_nodes();
    let mut out = vec![];
    let mut reads: BTreeMap<String, (String, String, Vec<String>)> = BTreeMap::new();
    let mut summary = Summary { total: cfg.connections.len(), ..Default::default() };

    for c in &cfg.connections {
        let owned = c.source == o.node && c.user == o.user;
        let mut s = ConnectionStatus {
            id: c.id(),
            source: c.source.clone(),
            user: c.user.clone(),
            target: c.target.clone(),
            target_user: c.target_user.clone(),
            owned,
            key_path: None,
            legacy: false,
            fingerprint: None,
            comment: None,
            comment_on_pattern: false,
            rotated_at: None,
            age_days: None,
            due_at: None,
            due: false,
            overdue: false,
            reachable: None,
            endpoint: None,
            detail: None,
            retired_copies: 0,
        };
        if !owned {
            s.detail = Some(format!("key lives on {} (user {}); rotated there", c.source, c.user));
            out.push(s);
            continue;
        }
        summary.owned += 1;
        s.retired_copies = layout::retired_files(l, c).iter().filter(|(p, _)| !p.to_string_lossy().ends_with(".pub")).count();
        match current_key(l, c) {
            Err(e) => {
                s.detail = Some(e);
                s.due = true;
            }
            Ok(k) => {
                s.key_path = Some(k.path.display().to_string());
                s.legacy = k.legacy;
                s.fingerprint = Some(k.pubkey.fingerprint());
                s.comment_on_pattern = parse_comment(&k.pubkey.comment, &nodes)
                    .is_some_and(|pc| pc.source == c.source && pc.target == c.target && pc.user == c.user);
                s.comment = Some(k.pubkey.comment.clone());
                if let Some(since) = k.since {
                    s.rotated_at = Some(timeutil::iso(since));
                    let age = (o.now - since).max(0) / DAY;
                    s.age_days = Some(age);
                    s.due_at = Some(timeutil::iso(since + max * DAY));
                    s.due = age >= max;
                    s.overdue = age >= max + p.overdue_alert_days as i64;
                } else {
                    s.due = true;
                }
                if k.legacy {
                    s.due = true; // first rotation = migration to the per-connection key
                    s.detail = Some(format!("uses legacy key {}; next rotation migrates it", k.path.display()));
                }
                if o.probe {
                    match t.resolve(c) {
                        Err(e) => {
                            s.reachable = Some(false);
                            s.detail = Some(format!("cannot resolve: {e}"));
                        }
                        Ok(ep) => {
                            s.endpoint = Some(ep.label());
                            match t.login(&ep, &k.path) {
                                Ok(()) => {
                                    s.reachable = Some(true);
                                    if let std::collections::btree_map::Entry::Vacant(e) = reads.entry(ep.label()) {
                                        match t.authorized_keys(&ep, &k.path) {
                                            Ok(lines) => {
                                                e.insert((c.target.clone(), c.target_user.clone(), lines));
                                            }
                                            Err(e) => s.detail = Some(format!("authorized_keys not readable: {e}")),
                                        }
                                    }
                                }
                                Err(e) => {
                                    s.reachable = Some(false);
                                    s.detail = Some(e.0);
                                }
                            }
                        }
                    }
                }
            }
        }
        summary.due += s.due as usize;
        summary.overdue += s.overdue as usize;
        summary.unreachable += (s.reachable == Some(false)) as usize;
        out.push(s);
    }

    // drift on every target account we could read
    let mut drift = vec![];
    for (endpoint, (target, target_user, lines)) in reads {
        for line in lines {
            let Some(k) = PubKey::parse(&line) else { continue };
            let mine = out.iter().find(|s| {
                s.owned && s.target == target && s.target_user == target_user && s.fingerprint.as_deref() == Some(&k.fingerprint())
            });
            let pc = parse_comment(&k.comment, &nodes);
            let declared_by_comment = pc.as_ref().and_then(|pc| {
                cfg.connections.iter().find(|c| {
                    c.source == pc.source && c.user == pc.user && c.target == pc.target && c.target == target && c.target_user == target_user
                })
            });
            let (class, connection) = match (mine, declared_by_comment) {
                (Some(m), Some(d)) if m.id == d.id() => ("declared", Some(m.id.clone())),
                (Some(m), _) => ("declared-mismatch", Some(m.id.clone())),
                (None, Some(d)) => ("declared", Some(d.id())),
                (None, None) if pc.is_some() => ("undeclared", None),
                (None, None) => ("off-pattern", None),
            };
            match class {
                "undeclared" => summary.undeclared += 1,
                "off-pattern" => summary.off_pattern += 1,
                _ => {}
            }
            drift.push(DriftLine {
                target: target.clone(),
                target_user: target_user.clone(),
                endpoint: endpoint.clone(),
                fingerprint: k.fingerprint(),
                comment: k.comment.clone(),
                class: class.into(),
                connection,
            });
        }
    }

    Plan { generated_at: timeutil::iso(o.now), node: o.node.clone(), user: o.user.clone(), policy: p.clone(), connections: out, drift, summary }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::read_pub;
    use crate::transport::FakeTransport;
    use std::fs;

    const NOW: i64 = 1_792_726_200;

    #[test]
    fn plan_reports_age_due_reachability_and_drift_without_changing_anything() {
        let t = tempfile::tempdir().unwrap();
        let l = Layout::for_home(t.path());
        fs::create_dir_all(&l.ssh_dir).unwrap();
        let cfg = RotationConfig::from_json(r#"{"connections":[
            {"source":"ws-01","user":"alice","target":"gpu-01","target_user":"alice"},
            {"source":"ws-01","user":"alice","target":"edge-01","target_user":"alice","legacy_key":"~/.ssh/id_ed25519"},
            {"source":"ws-01","user":"alice","target":"laptop-01","target_user":"alice"},
            {"source":"gpu-01","user":"root","target":"ws-01","target_user":"root"}]}"#).unwrap();
        let mut f = FakeTransport::new();
        let c0 = &cfg.connections[0];
        f.keygen(&l.key(c0), &c0.comment("20260425")).unwrap();
        fs::write(l.rotated_at(c0), timeutil::iso(NOW - 181 * DAY)).unwrap();
        f.keygen(&l.ssh_dir.join("id_ed25519"), "ws-01-gpu-01-alice-20260425").unwrap();
        let c2 = &cfg.connections[2];
        f.keygen(&l.key(c2), &c2.comment("20261001")).unwrap();
        fs::write(l.rotated_at(c2), timeutil::iso(NOW - 22 * DAY)).unwrap();
        f.unreachable.push("laptop-01".into());
        // gpu-01: our key, an undeclared on-pattern key, an off-pattern key
        f.add_line("alice@gpu-01", &read_pub(&l.key(c0)).unwrap().line());
        f.add_line("alice@gpu-01", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA laptop-02-gpu-01-bob-20260301");
        f.add_line("alice@gpu-01", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice@old-laptop");
        // edge-01: the shared legacy key whose comment names gpu-01
        f.add_line("alice@edge-01", &read_pub(&l.ssh_dir.join("id_ed25519")).unwrap().line());
        f.reset();
        let before: Vec<_> = fs::read_dir(&l.ssh_dir).unwrap().flatten().map(|e| e.file_name()).collect();

        let p = plan(&cfg, &l, &mut f, &PlanOptions { node: "ws-01".into(), user: "alice".into(), probe: true, now: NOW });

        let s = |id: &str| p.connections.iter().find(|c| c.id == id).unwrap().clone();
        let a = s("ws-01-gpu-01-alice");
        assert_eq!((a.age_days, a.due, a.overdue, a.reachable), (Some(181), true, true, Some(true)));
        assert!(a.comment_on_pattern);
        let h = s("ws-01-edge-01-alice");
        assert!(h.legacy && h.due && !h.comment_on_pattern);
        let lap = s("ws-01-laptop-01-alice");
        assert_eq!((lap.due, lap.reachable), (false, Some(false)));
        assert_eq!(lap.due_at.as_deref(), Some(timeutil::iso(NOW - 22 * DAY + 90 * DAY).as_str()));
        let r = s("gpu-01-ws-01-root");
        assert!(!r.owned && r.reachable.is_none());
        assert_eq!(p.summary.owned, 3);
        assert_eq!((p.summary.due, p.summary.overdue, p.summary.unreachable), (2, 1, 1));

        let classes: Vec<(String, String)> = p.drift.iter().map(|d| (d.target.clone(), d.class.clone())).collect();
        assert!(classes.contains(&("gpu-01".into(), "declared".into())));
        assert!(classes.contains(&("gpu-01".into(), "undeclared".into())));
        assert!(classes.contains(&("gpu-01".into(), "off-pattern".into())));
        assert!(classes.contains(&("edge-01".into(), "declared-mismatch".into())));
        assert_eq!((p.summary.undeclared, p.summary.off_pattern), (1, 1));

        // read-only: no install/remove/keygen, no file created
        assert!(f.calls.iter().all(|c| c.starts_with("resolve") || c.starts_with("login") || c.starts_with("read")), "{:?}", f.calls);
        let after: Vec<_> = fs::read_dir(&l.ssh_dir).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(before.len(), after.len());
    }

    #[test]
    fn plan_without_probe_makes_no_calls() {
        let t = tempfile::tempdir().unwrap();
        let l = Layout::for_home(t.path());
        let cfg = RotationConfig::from_json(r#"{"connections":[{"source":"n","user":"u","target":"t","target_user":"u"}]}"#).unwrap();
        let mut f = FakeTransport::new();
        let p = plan(&cfg, &l, &mut f, &PlanOptions { node: "n".into(), user: "u".into(), probe: false, now: NOW });
        assert!(f.calls.is_empty());
        assert!(p.connections[0].detail.as_deref().unwrap().contains("no key"));
        assert!(p.connections[0].due);
    }
}
