//! The connection model: the `ssh_rotation` block of the control plane / `connections.json`.
//!
//! One connection = source node + source user -> target node + target user. Each gets its own key:
//!   key file  `~/.ssh/<source>-<target>-<user>`        (no date)
//!   comment   `<source>-<target>-<user>-<YYYYMMDD>`    (the date lives here)
//! Two connections that would share a key file are refused: a key opens exactly one door.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ConfigError {}

fn d_max() -> u32 { 90 }
fn d_overdue() -> u32 { 14 }
fn d_keep() -> u32 { 30 }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default = "d_max")]
    pub max_age_days: u32,
    #[serde(default = "d_overdue")]
    pub overdue_alert_days: u32,
    #[serde(default = "d_keep")]
    pub retired_keep_days: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { max_age_days: d_max(), overdue_alert_days: d_overdue(), retired_keep_days: d_keep() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TargetOs {
    #[default]
    Linux,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub source: String,
    pub user: String,
    pub target: String,
    pub target_user: String,
    /// Stable id; defaults to the key name `<source>-<target>-<user>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Address to connect to; when absent it is resolved with `ssh -G <target>` (read-only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub target_os: TargetOs,
    /// Remote authorized_keys file. Linux default `~/.ssh/authorized_keys`; Windows default
    /// `administrators` (C:\ProgramData\ssh\administrators_authorized_keys); `user` = the user's own file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_keys: Option<String>,
    /// The key this connection uses before its first rotation (e.g. `~/.ssh/id_ed25519`). The first rotation
    /// is the migration to the per-connection key; the legacy file itself is never moved or deleted here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_key: Option<String>,
    /// Extra `-o` options for every ssh call (e.g. `ProxyJump=bastion`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_options: Vec<String>,
}

impl Connection {
    pub fn key_name(&self) -> String {
        format!("{}-{}-{}", self.source, self.target, self.user)
    }
    pub fn id(&self) -> String {
        self.id.clone().unwrap_or_else(|| self.key_name())
    }
    pub fn comment(&self, ymd: &str) -> String {
        format!("{}-{}", self.key_name(), ymd)
    }
    pub fn authorized_keys_path(&self) -> String {
        match (self.target_os, self.authorized_keys.as_deref()) {
            (_, Some(p)) if p != "administrators" && p != "user" => p.to_string(),
            (TargetOs::Windows, Some("user")) => "$env:USERPROFILE\\.ssh\\authorized_keys".into(),
            (TargetOs::Windows, _) => "$env:ProgramData\\ssh\\administrators_authorized_keys".into(),
            (TargetOs::Linux, _) => "~/.ssh/authorized_keys".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RotationConfig {
    #[serde(flatten)]
    pub policy: Policy,
    #[serde(default)]
    pub connections: Vec<Connection>,
}

/// ssh options a connection may add. Anything that runs a command (ProxyCommand, LocalCommand, ...) is refused:
/// the connection list can come from the control plane, and it must never be able to run code on this device.
pub const SSH_OPTIONS_ALLOWED: &[&str] =
    &["ProxyJump", "HostKeyAlias", "ConnectTimeout", "ServerAliveInterval", "ServerAliveCountMax", "AddressFamily"];

/// A node or user name that is safe inside a file name, a key comment and an ssh argument.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('-')
        && !s.starts_with('.')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

impl RotationConfig {
    /// Accepts `{"ssh_rotation": {...}}` (nodes.json / control-plane reply) or the block itself.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|e| ConfigError(format!("connections file is not JSON: {e}")))?;
        let block = match v.get("ssh_rotation") {
            Some(b) => b.clone(),
            None if v.get("connections").is_some() => v,
            None => return Err(ConfigError("no ssh_rotation block (expected {\"ssh_rotation\": {...}})".into())),
        };
        let cfg: RotationConfig =
            serde_json::from_value(block).map_err(|e| ConfigError(format!("ssh_rotation block is invalid: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let p = &self.policy;
        if p.max_age_days == 0 || p.max_age_days > 3650 {
            return Err(ConfigError("max_age_days must be 1..3650".into()));
        }
        let mut keys = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for c in &self.connections {
            for (field, val) in [("source", &c.source), ("user", &c.user), ("target", &c.target), ("target_user", &c.target_user)] {
                if !valid_name(val) {
                    return Err(ConfigError(format!(
                        "connection {}: {field} '{val}' must be letters, digits, '-', '_' or '.' (it becomes part of a file name)",
                        c.id()
                    )));
                }
            }
            if let Some(h) = &c.hostname {
                if h.is_empty() || h.starts_with('-') || h.chars().any(|ch| ch.is_whitespace()) {
                    return Err(ConfigError(format!("connection {}: hostname is not a host name", c.id())));
                }
            }
            for o in &c.ssh_options {
                let name = o.split('=').next().unwrap_or("");
                if !o.contains('=') || o.contains('\n') || !SSH_OPTIONS_ALLOWED.iter().any(|a| a.eq_ignore_ascii_case(name)) {
                    return Err(ConfigError(format!(
                        "connection {}: ssh_options allows only {} as Name=value (no commands)",
                        c.id(),
                        SSH_OPTIONS_ALLOWED.join(", ")
                    )));
                }
            }
            if !keys.insert(c.key_name()) {
                return Err(ConfigError(format!(
                    "two connections would share the key file {} — one key per connection",
                    c.key_name()
                )));
            }
            if !ids.insert(c.id()) {
                return Err(ConfigError(format!("connection id {} is used twice", c.id())));
            }
        }
        Ok(())
    }

    pub fn find(&self, id: &str) -> Option<&Connection> {
        self.connections.iter().find(|c| c.id() == id)
    }

    pub fn known_nodes(&self) -> BTreeSet<String> {
        self.connections.iter().flat_map(|c| [c.source.clone(), c.target.clone()]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESIGN: &str = r#"{"version":1,"nodes":[],"ssh_rotation": {
      "max_age_days": 90, "overdue_alert_days": 14, "retired_keep_days": 30,
      "connections": [
        {"source": "ws-01", "user": "alice", "target": "gpu-01",     "target_user": "alice"},
        {"source": "ws-01", "user": "alice", "target": "edge-01", "target_user": "alice"},
        {"source": "ws-01", "user": "alice", "target": "laptop-01",    "target_user": "alice", "target_os": "windows"},
        {"source": "ws-01", "user": "root",   "target": "gpu-01",     "target_user": "root"},
        {"source": "gpu-01",   "user": "root",   "target": "ws-01",   "target_user": "root"}
      ]}}"#;

    #[test]
    fn loads_the_design_block() {
        let c = RotationConfig::from_json(DESIGN).unwrap();
        assert_eq!(c.policy, Policy::default());
        assert_eq!(c.connections.len(), 5);
        let h = &c.connections[1];
        assert_eq!(h.key_name(), "ws-01-edge-01-alice");
        assert_eq!(h.comment("20261020"), "ws-01-edge-01-alice-20261020");
        assert_eq!(h.authorized_keys_path(), "~/.ssh/authorized_keys");
        assert_eq!(
            c.connections[2].authorized_keys_path(),
            "$env:ProgramData\\ssh\\administrators_authorized_keys"
        );
        assert!(c.find("gpu-01-ws-01-root").is_some());
    }

    #[test]
    fn accepts_the_bare_block_and_defaults() {
        let c = RotationConfig::from_json(r#"{"connections":[{"source":"a","user":"u","target":"b","target_user":"u"}]}"#).unwrap();
        assert_eq!(c.policy.max_age_days, 90);
        assert_eq!(c.policy.retired_keep_days, 30);
    }

    #[test]
    fn refuses_shared_keys() {
        let e = RotationConfig::from_json(
            r#"{"connections":[{"source":"a","user":"u","target":"b","target_user":"u"},
                               {"source":"a","user":"u","target":"b","target_user":"root"}]}"#,
        )
        .unwrap_err();
        assert!(e.0.contains("share the key file a-b-u"), "{e}");
    }

    #[test]
    fn refuses_unsafe_names() {
        for bad in ["Alice Example", "../x", "-oProxyCommand=x", ""] {
            let j = format!(r#"{{"connections":[{{"source":"a","user":"{bad}","target":"b","target_user":"u"}}]}}"#);
            assert!(RotationConfig::from_json(&j).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_missing_block_and_bad_options() {
        assert!(RotationConfig::from_json(r#"{"nodes":[]}"#).is_err());
        assert!(RotationConfig::from_json("not json").is_err());
        let j = r#"{"connections":[{"source":"a","user":"u","target":"b","target_user":"u","ssh_options":["-oProxyCommand"]}]}"#;
        assert!(RotationConfig::from_json(j).is_err());
        let j = r#"{"connections":[{"source":"a","user":"u","target":"b","target_user":"u","ssh_options":["ProxyCommand=sh -c x"]}]}"#;
        assert!(RotationConfig::from_json(j).is_err());
        let j = r#"{"connections":[{"source":"a","user":"u","target":"b","target_user":"u","ssh_options":["ProxyJump=bastion"]}]}"#;
        assert!(RotationConfig::from_json(j).is_ok());
    }
}
