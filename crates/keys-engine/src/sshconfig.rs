//! The source user's `~/.ssh/config` entry for a connection: `Host <target>` -> `IdentityFile` + `IdentitiesOnly yes`.
//! Written as a marked block at the top of the file (first match wins in ssh_config), replaced in place on later
//! rotations; everything outside the markers is left exactly as it was. Atomic write, 0600 on Unix.

use crate::model::Connection;
use crate::transport::Endpoint;
use std::fs;
use std::io::Write;
use std::path::Path;

fn markers(c: &Connection) -> (String, String) {
    (format!("# BEGIN niyantrak-keys {}", c.id()), format!("# END niyantrak-keys {}", c.id()))
}

/// How a key path is written after `IdentityFile`: forward slashes (OpenSSH accepts them on Windows too),
/// quoted when it contains a space (e.g. `C:/Users/First Last/.ssh/...`).
pub fn identity_file_value(key: &Path) -> String {
    let key = key.to_string_lossy().replace('\\', "/");
    if key.contains(' ') {
        format!("\"{key}\"")
    } else {
        key
    }
}

pub fn block(c: &Connection, ep: &Endpoint, key: &Path) -> String {
    let (b, e) = markers(c);
    let key = identity_file_value(key);
    let mut s = format!("{b}\nHost {}\n  HostName {}\n  User {}\n  Port {}\n  IdentityFile {key}\n  IdentitiesOnly yes\n",
                        c.target, ep.host, ep.user, ep.port);
    for o in &ep.options {
        if let Some((k, v)) = o.split_once('=') {
            s.push_str(&format!("  {k} {v}\n"));
        }
    }
    s.push_str(&e);
    s.push('\n');
    s
}

/// The config text with this connection's block inserted at the top or replaced where it already is.
pub fn upsert(existing: &str, c: &Connection, ep: &Endpoint, key: &Path) -> String {
    let (b, e) = markers(c);
    let new_block = block(c, ep, key);
    if let (Some(start), Some(end_rel)) = (existing.find(&format!("{b}\n")), existing.find(&format!("{e}\n"))) {
        if end_rel > start {
            let end = end_rel + e.len() + 1;
            return format!("{}{}{}", &existing[..start], new_block, &existing[end..]);
        }
    }
    if existing.is_empty() {
        new_block
    } else {
        format!("{new_block}\n{existing}")
    }
}

pub fn write(path: &Path, c: &Connection, ep: &Endpoint, key: &Path) -> std::io::Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let text = upsert(&existing, c, ep, key);
    if text == existing {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = crate::layout::with_suffix(path, ".niyantrak-tmp");
    {
        let mut o = fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{RotationConfig, TargetOs};
    use std::path::PathBuf;

    fn c() -> Connection {
        RotationConfig::from_json(r#"{"connections":[{"source":"ws-01","user":"alice","target":"edge-01","target_user":"alice"}]}"#)
            .unwrap().connections.remove(0)
    }
    fn ep() -> Endpoint {
        Endpoint { host: "203.0.113.7".into(), port: 22, user: "alice".into(), os: TargetOs::Linux,
                   authorized_keys: "~/.ssh/authorized_keys".into(), options: vec![] }
    }

    #[test]
    fn inserts_on_top_and_keeps_the_rest() {
        let old = "Host edge-01\n  HostName 203.0.113.7\n  IdentityFile ~/.ssh/id_ed25519\n";
        let out = upsert(old, &c(), &ep(), &PathBuf::from("/home/alice/.ssh/ws-01-edge-01-alice"));
        assert!(out.starts_with("# BEGIN niyantrak-keys ws-01-edge-01-alice\nHost edge-01\n"));
        assert!(out.contains("  IdentityFile /home/alice/.ssh/ws-01-edge-01-alice\n  IdentitiesOnly yes\n"));
        assert!(out.ends_with(old));
    }

    #[test]
    fn replaces_in_place_and_is_idempotent() {
        let k = PathBuf::from("/k/ws-01-edge-01-alice");
        let once = upsert("Host other\n  User x\n", &c(), &ep(), &k);
        let mut ep2 = ep();
        ep2.port = 2222;
        let twice = upsert(&once, &c(), &ep2, &k);
        assert_eq!(twice.matches("# BEGIN niyantrak-keys").count(), 1);
        assert!(twice.contains("Port 2222") && !twice.contains("Port 22\n"));
        assert!(twice.ends_with("Host other\n  User x\n"));
        assert_eq!(upsert(&twice, &c(), &ep2, &k), twice);
    }

    #[test]
    fn writes_atomically_with_private_mode() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join(".ssh/config");
        write(&p, &c(), &ep(), &t.path().join(".ssh/k")).unwrap();
        assert!(fs::read_to_string(&p).unwrap().contains("IdentitiesOnly yes"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
