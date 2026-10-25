//! Module flags. The control plane decides which modules a device shows; the client only knows their names.
//! Shape (control-plane reply or the cached `features.json`):
//!   {"modules": {"keys": {"enabled": true}, "homecloud-import": {"enabled": false, "reason": "..."}, "enrol": {...}}}
//! Unknown module names are ignored; a module the reply leaves out keeps its default.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const KEYS: &str = "keys";
pub const HOMECLOUD_IMPORT: &str = "homecloud-import";
pub const ENROL: &str = "enrol";
pub const KNOWN: [&str; 3] = [KEYS, HOMECLOUD_IMPORT, ENROL];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Module {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Features {
    pub modules: BTreeMap<String, Module>,
    /// "defaults" | "control-plane" | "cache"
    #[serde(default)]
    pub source: String,
}

impl Default for Features {
    fn default() -> Self {
        let mut m = BTreeMap::new();
        m.insert(KEYS.into(), Module { enabled: true, reason: None });
        m.insert(ENROL.into(), Module { enabled: true, reason: None });
        m.insert(
            HOMECLOUD_IMPORT.into(),
            Module { enabled: false, reason: Some("Needs a HomeCloud server — not available yet".into()) },
        );
        Features { modules: m, source: "defaults".into() }
    }
}

impl Features {
    /// Defaults overlaid with a control-plane reply (`{"features": {...}}` or the block itself).
    pub fn from_json(text: &str, source: &str) -> Result<Features, String> {
        let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("features are not JSON: {e}"))?;
        let block = v.get("features").cloned().unwrap_or(v);
        let modules = block.get("modules").and_then(|m| m.as_object()).ok_or("features need a modules object")?;
        let mut f = Features::default();
        for (name, val) in modules {
            if !KNOWN.contains(&name.as_str()) {
                continue;
            }
            let m: Module = serde_json::from_value(val.clone()).map_err(|e| format!("module {name}: {e}"))?;
            f.modules.insert(name.clone(), m);
        }
        f.source = source.into();
        Ok(f)
    }

    pub fn enabled(&self, name: &str) -> bool {
        self.modules.get(name).is_some_and(|m| m.enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_enable_keys_and_enrol_only() {
        let f = Features::default();
        assert!(f.enabled(KEYS) && f.enabled(ENROL) && !f.enabled(HOMECLOUD_IMPORT));
        assert!(f.modules[HOMECLOUD_IMPORT].reason.as_deref().unwrap().contains("HomeCloud server"));
    }

    #[test]
    fn control_plane_overrides_known_modules_only() {
        let f = Features::from_json(
            r#"{"features":{"modules":{"keys":{"enabled":false,"reason":"paused by operator"},"telnet":{"enabled":true}}}}"#,
            "control-plane",
        )
        .unwrap();
        assert!(!f.enabled(KEYS) && f.enabled(ENROL) && !f.modules.contains_key("telnet"));
        assert_eq!(f.source, "control-plane");
        assert!(Features::from_json("{}", "x").is_err());
    }
}
