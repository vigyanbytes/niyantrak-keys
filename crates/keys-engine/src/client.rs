//! The desktop app's facade. Every Tauri command is a thin wrapper around one of these functions, so the app's
//! behaviour is tested here (with temp homes and the fake transport) without WebKit.

use crate::audit::Audit;
use crate::enrol::{self, Enrolment, Signer, SshKeySigner, Status};
use crate::features::{self, Features};
use crate::identity::{self, Identity};
use crate::layout::Layout;
use crate::plan::{plan, Plan, PlanOptions};
use crate::rotate::{RotationReport, Rotator, StepEvent};
use crate::transport::{SystemTransport, Transport};
use crate::{timeutil, RotationConfig};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ClientCtx {
    pub layout: Layout,
    pub node: String,
    pub user: String,
    pub known_hosts: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Overview {
    pub person: Identity,
    pub process_user: String,
    pub node: String,
    pub features: Features,
    pub enrolment: Option<Enrolment>,
    pub connections_file: String,
    pub connections: Option<usize>,
    pub connections_error: Option<String>,
    pub audit_log: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrolPreview {
    pub card: Value,
    pub card_sha256: String,
    pub node_id: String,
    pub host_key: String,
    pub host_key_fingerprint: Option<String>,
    /// false when this process cannot read the private host key (the usual case for a desktop app)
    pub can_sign: bool,
    /// what to run elevated when `can_sign` is false (the token is typed at the prompt, never on the command line)
    pub elevated_command: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct DueSummary {
    pub owned: usize,
    pub due: usize,
    pub overdue: usize,
}

impl ClientCtx {
    pub fn detect() -> Result<ClientCtx, String> {
        let layout = Layout::current_user().ok_or("no home directory")?;
        layout.migrate_legacy(); // Windows: one-time copy from %APPDATA%\niyantrak; no-op elsewhere / afterwards
        Ok(ClientCtx { layout, node: identity::node_name(), user: identity::effective_user(), known_hosts: None })
    }

    pub fn connections(&self) -> Result<RotationConfig, String> {
        let p = self.layout.connections_file();
        let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        RotationConfig::from_json(&text).map_err(|e| e.0)
    }

    /// Cached control-plane flags, else defaults.
    pub fn features(&self) -> Features {
        fs::read_to_string(self.layout.features_file())
            .ok()
            .and_then(|t| Features::from_json(&t, "cache").ok())
            .unwrap_or_default()
    }

    pub fn overview(&self) -> Overview {
        let (connections, connections_error) = match self.connections() {
            Ok(c) => (Some(c.connections.len()), None),
            Err(e) => (None, Some(e)),
        };
        Overview {
            person: identity::current(),
            process_user: self.user.clone(),
            node: self.node.clone(),
            features: self.features(),
            enrolment: Enrolment::load(&self.layout.enrolment_file()),
            connections_file: self.layout.connections_file().display().to_string(),
            connections,
            connections_error,
            audit_log: self.layout.audit_log().display().to_string(),
        }
    }

    fn transport(&self) -> SystemTransport {
        SystemTransport { known_hosts: self.known_hosts.clone(), ..Default::default() }
    }

    pub fn plan_with(&self, t: &mut dyn Transport, probe: bool, now: i64) -> Result<Plan, String> {
        let cfg = self.connections()?;
        Ok(plan(&cfg, &self.layout, t, &PlanOptions { node: self.node.clone(), user: self.user.clone(), probe, now }))
    }

    pub fn plan(&self, probe: bool) -> Result<Plan, String> {
        self.plan_with(&mut self.transport(), probe, timeutil::now())
    }

    pub fn due_summary_at(&self, now: i64) -> DueSummary {
        match self.plan_with(&mut crate::transport::FakeTransport::new(), false, now) {
            Ok(p) => DueSummary { owned: p.summary.owned, due: p.summary.due, overdue: p.summary.overdue },
            Err(_) => DueSummary::default(),
        }
    }

    /// Text for the desktop notification, or None when nothing is due (or the keys module is off).
    pub fn due_notification(&self, now: i64) -> Option<(String, String)> {
        if !self.features().enabled(features::KEYS) {
            return None;
        }
        let s = self.due_summary_at(now);
        if s.due == 0 {
            return None;
        }
        let title = if s.overdue > 0 { "SSH keys overdue for rotation" } else { "SSH keys due for rotation" };
        let body = format!(
            "{} of {} connection{} on this device {} due{}. Open Niyantrak → Keys to rotate.",
            s.due,
            s.owned,
            if s.owned == 1 { "" } else { "s" },
            if s.due == 1 { "is" } else { "are" },
            if s.overdue > 0 { format!(" ({} overdue)", s.overdue) } else { String::new() }
        );
        Some((title.into(), body))
    }

    pub fn rotate_with(
        &self,
        t: &mut dyn Transport,
        id: &str,
        apply: bool,
        force: bool,
        now: i64,
        progress: &mut dyn FnMut(&StepEvent),
    ) -> Result<RotationReport, String> {
        if !self.features().enabled(features::KEYS) {
            return Err("the keys module is disabled by the control plane".into());
        }
        let cfg = self.connections()?;
        let c = cfg.find(id).ok_or(format!("no connection {id}"))?.clone();
        if c.source != self.node || c.user != self.user {
            return Err(format!("{id} belongs to {} user {}; it is rotated there", c.source, c.user));
        }
        let owned = cfg.connections.iter().filter(|o| o.source == self.node && o.user == self.user).cloned().collect();
        let mut audit = Audit::files(self.layout.audit_log(), self.layout.sixw_log());
        audit.agent = identity::agent().or_else(|| Some("Niyantrak app".into()));
        let r = Rotator { layout: &self.layout, policy: &cfg.policy, transport: t, audit: &mut audit, actor: identity::current(), now, apply, force, owned }
            .rotate(&c, progress);
        Ok(r)
    }

    pub fn rotate(&self, id: &str, apply: bool, progress: &mut dyn FnMut(&StepEvent)) -> Result<RotationReport, String> {
        self.rotate_with(&mut self.transport(), id, apply, false, timeutil::now(), progress)
    }

    pub fn enrol_preview_with(&self, signer: &SshKeySigner, role: Option<&str>) -> EnrolPreview {
        let card = enrol::collect_card(role);
        let pub_line = signer.public_key().ok();
        let can_sign = fs::File::open(&signer.key).is_ok();
        let exe = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join(if cfg!(windows) { "niyantrak-keys.exe" } else { "niyantrak-keys" })));
        let cli = exe.filter(|p| p.exists()).map(|p| p.display().to_string()).unwrap_or_else(|| "niyantrak-keys".into());
        let elevated_command = if cfg!(windows) {
            format!("Start-Process -Verb RunAs -FilePath '{cli}' -ArgumentList 'enrol'   # paste the invite at the prompt")
        } else {
            format!("sudo {cli} enrol   # paste the invite at the prompt")
        };
        EnrolPreview {
            card_sha256: enrol::card_sha256(&card),
            node_id: card["node_id"].as_str().unwrap_or_default().to_string(),
            card,
            host_key: signer.key.display().to_string(),
            host_key_fingerprint: pub_line.as_deref().and_then(enrol::host_key_fingerprint),
            can_sign,
            elevated_command,
        }
    }

    pub fn enrol_preview(&self) -> EnrolPreview {
        self.enrol_preview_with(&SshKeySigner::new(enrol::default_host_key()), None)
    }

    pub fn enrol_submit_with(&self, invite_text: &str, signer: &SshKeySigner) -> Result<Enrolment, String> {
        let invite = enrol::parse_invite(invite_text).map_err(|e| e.0)?;
        let card = enrol::collect_card(None);
        let rec = enrol::join(&invite, &card, signer, Duration::from_secs(30)).map_err(|e| e.0)?;
        rec.save(&self.layout.enrolment_file()).map_err(|e| e.to_string())?;
        Ok(rec)
    }

    pub fn enrol_submit(&self, invite_text: &str) -> Result<Enrolment, String> {
        self.enrol_submit_with(invite_text, &SshKeySigner::new(enrol::default_host_key()))
    }

    /// Ask the control plane for the node state; when approved, also pull the client config (features +
    /// ssh_rotation) if the control plane offers it.
    pub fn enrol_refresh(&self) -> Result<Enrolment, String> {
        let path = self.layout.enrolment_file();
        let mut rec = Enrolment::load(&path).ok_or("not enrolled yet")?;
        match enrol::status(&rec, Duration::from_secs(15)).map_err(|e| e.0)? {
            Status::State(s) => rec.state = s,
            Status::Unsupported => {}
        }
        rec.checked_at = Some(timeutil::iso(timeutil::now()));
        rec.save(&path).map_err(|e| e.to_string())?;
        if rec.state == "approved" {
            if let Ok(Some(body)) = enrol::fetch_client_config(&rec, Duration::from_secs(15)) {
                self.store_client_config(&body)?;
            }
        }
        Ok(rec)
    }

    /// Cache a control-plane config reply: `features` -> features.json, `ssh_rotation` -> connections.json.
    /// Both are validated before anything is written.
    pub fn store_client_config(&self, body: &str) -> Result<(), String> {
        let v: Value = serde_json::from_str(body).map_err(|e| format!("client config is not JSON: {e}"))?;
        let feats = match v.get("features") {
            Some(f) => Some(Features::from_json(&f.to_string(), "control-plane")?),
            None => None,
        };
        let rot = match v.get("ssh_rotation") {
            Some(r) => {
                let wrapped = serde_json::json!({ "ssh_rotation": r }).to_string();
                RotationConfig::from_json(&wrapped).map_err(|e| e.0)?;
                Some(wrapped)
            }
            None => None,
        };
        fs::create_dir_all(&self.layout.config_dir).map_err(|e| e.to_string())?;
        if let Some(f) = feats {
            fs::write(self.layout.features_file(), serde_json::to_string_pretty(&f).unwrap()).map_err(|e| e.to_string())?;
        }
        if let Some(r) = rot {
            fs::write(self.layout.connections_file(), r).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::read_pub;
    use crate::rotate::Outcome;
    use crate::timeutil::DAY;
    use crate::transport::FakeTransport;

    const NOW: i64 = 1_792_726_200;

    fn ctx() -> (tempfile::TempDir, ClientCtx) {
        let t = tempfile::tempdir().unwrap();
        let c = ClientCtx { layout: Layout::for_home(t.path()), node: "ws-01".into(), user: "alice".into(), known_hosts: None };
        fs::create_dir_all(&c.layout.config_dir).unwrap();
        fs::create_dir_all(&c.layout.ssh_dir).unwrap();
        fs::write(
            c.layout.connections_file(),
            r#"{"ssh_rotation":{"connections":[
                {"source":"ws-01","user":"alice","target":"edge-01","target_user":"alice"},
                {"source":"gpu-01","user":"root","target":"ws-01","target_user":"root"}]}}"#,
        )
        .unwrap();
        (t, c)
    }

    #[test]
    fn overview_without_enrolment() {
        let (_t, c) = ctx();
        let o = c.overview();
        assert_eq!(o.connections, Some(2));
        assert!(o.enrolment.is_none());
        assert!(o.features.enabled("keys") && !o.features.enabled("homecloud-import"));
        assert_eq!(o.features.source, "defaults");
    }

    #[test]
    fn due_notification_counts_owned_connections() {
        let (_t, c) = ctx();
        let conn = c.connections().unwrap().connections[0].clone();
        let mut f = FakeTransport::new();
        f.keygen(&c.layout.key(&conn), "x").unwrap();
        fs::write(c.layout.rotated_at(&conn), timeutil::iso(NOW - 10 * DAY)).unwrap();
        assert!(c.due_notification(NOW).is_none());
        fs::write(c.layout.rotated_at(&conn), timeutil::iso(NOW - 120 * DAY)).unwrap();
        let (title, body) = c.due_notification(NOW).unwrap();
        assert_eq!(title, "SSH keys overdue for rotation");
        assert!(body.starts_with("1 of 1 connection on this device is due (1 overdue)"), "{body}");
        // module switched off by the control plane: no notification
        fs::write(c.layout.features_file(), r#"{"modules":{"keys":{"enabled":false}}}"#).unwrap();
        assert!(c.due_notification(NOW).is_none());
    }

    #[test]
    fn rotate_through_the_facade_streams_steps_and_writes_audit() {
        let (_t, c) = ctx();
        let conn = c.connections().unwrap().connections[0].clone();
        let mut f = FakeTransport::new();
        f.keygen(&c.layout.key(&conn), &conn.comment("20260101")).unwrap();
        f.add_line("alice@edge-01", &read_pub(&c.layout.key(&conn)).unwrap().line());
        fs::write(c.layout.rotated_at(&conn), timeutil::iso(NOW - 100 * DAY)).unwrap();
        f.reset();
        let mut seen = vec![];
        let r = c.rotate_with(&mut f, &conn.id(), true, false, NOW, &mut |e| seen.push(e.no)).unwrap();
        assert_eq!(r.outcome, Outcome::Rotated);
        assert_eq!(seen, vec![1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(fs::read_to_string(c.layout.audit_log()).unwrap().lines().count(), 7);
        // the agent label is the AI agent when one acts (CLAUDECODE=1 / NIYANTRAK_AGENT), else the app itself
        let agent = identity::agent().unwrap_or_else(|| "Niyantrak app".into());
        assert!(fs::read_to_string(c.layout.sixw_log()).unwrap().contains(&format!("\"agent\":\"{agent}\"")));
    }

    #[test]
    fn rotate_refuses_foreign_and_disabled() {
        let (_t, c) = ctx();
        let mut f = FakeTransport::new();
        let e = c.rotate_with(&mut f, "gpu-01-ws-01-root", true, false, NOW, &mut |_| {}).unwrap_err();
        assert!(e.contains("rotated there"));
        fs::write(c.layout.features_file(), r#"{"modules":{"keys":{"enabled":false}}}"#).unwrap();
        let e = c.rotate_with(&mut f, "ws-01-edge-01-alice", true, false, NOW, &mut |_| {}).unwrap_err();
        assert!(e.contains("disabled"));
    }

    #[test]
    fn control_plane_config_is_validated_before_it_is_cached() {
        let (_t, c) = ctx();
        let before = fs::read_to_string(c.layout.connections_file()).unwrap();
        let bad = r#"{"features":{"modules":{"homecloud-import":{"enabled":true}}},
                      "ssh_rotation":{"connections":[{"source":"a","user":"u","target":"b","target_user":"u","ssh_options":["ProxyCommand=evil"]}]}}"#;
        assert!(c.store_client_config(bad).is_err());
        assert_eq!(fs::read_to_string(c.layout.connections_file()).unwrap(), before, "nothing written on a bad reply");
        assert!(!c.layout.features_file().exists());
        let good = r#"{"features":{"modules":{"homecloud-import":{"enabled":true}}},
                       "ssh_rotation":{"connections":[{"source":"ws-01","user":"alice","target":"gpu-01","target_user":"alice"}]}}"#;
        c.store_client_config(good).unwrap();
        assert!(c.features().enabled("homecloud-import"));
        assert_eq!(c.connections().unwrap().connections[0].target, "gpu-01");
    }

    #[test]
    fn enrol_preview_reports_whether_it_can_sign() {
        let (t, c) = ctx();
        let key = t.path().join("hostkey");
        assert!(std::process::Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "h", "-f"]).arg(&key).status().unwrap().success());
        let p = c.enrol_preview_with(&SshKeySigner::new(&key), Some("client"));
        assert!(p.can_sign && p.host_key_fingerprint.unwrap().starts_with("SHA256:"));
        assert_eq!(p.card_sha256, enrol::card_sha256(&p.card));
        let p = c.enrol_preview_with(&SshKeySigner::new(t.path().join("missing")), None);
        assert!(!p.can_sign && p.elevated_command.contains("enrol"));
    }
}
