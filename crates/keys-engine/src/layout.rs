//! Where things live on the device that owns the keys. Every path hangs off one home directory, so tests run
//! against a temporary home and never see the real `~/.ssh`.

use crate::model::Connection;
use crate::pubkey::PubKey;
use crate::timeutil;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Unix,
    Windows,
}

impl Platform {
    pub fn current() -> Platform {
        if cfg!(windows) {
            Platform::Windows
        } else {
            Platform::Unix
        }
    }
}

/// Paths per platform:
/// * Unix: `~/.config/niyantrak` (config) and `~/.local/state/niyantrak` (audit), XDG style.
/// * Windows: `%USERPROFILE%\.niyantrak` and `%USERPROFILE%\.niyantrak\state`, next to `~\.ssh`. Not `%APPDATA%`:
///   an MSIX (Store) install virtualizes `%APPDATA%` writes into package-private storage, which the CLI cannot
///   see and uninstall deletes. An older `%APPDATA%\niyantrak` is copied over once (`migrate_legacy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub home: PathBuf,
    pub ssh_dir: PathBuf,
    pub ssh_config: PathBuf,
    pub state_dir: PathBuf,
    /// connections.json, features.json, enrolment.json
    pub config_dir: PathBuf,
    /// (old dir, new dir) pairs copied once by `migrate_legacy` (Windows only)
    pub legacy_dirs: Vec<(PathBuf, PathBuf)>,
}

const MIGRATION_MARKER: &str = ".migrated-from-appdata";

impl Layout {
    pub fn for_home(home: impl Into<PathBuf>) -> Layout {
        Layout::for_home_on(home, Platform::current())
    }

    pub fn for_home_on(home: impl Into<PathBuf>, platform: Platform) -> Layout {
        let home = home.into();
        let ssh_dir = home.join(".ssh");
        let (config_dir, state_dir, legacy_dirs) = match platform {
            Platform::Unix => (home.join(".config").join("niyantrak"), home.join(".local").join("state").join("niyantrak"), vec![]),
            Platform::Windows => {
                let config = home.join(".niyantrak");
                let state = config.join("state");
                let legacy = vec![
                    (home.join("AppData").join("Roaming").join("niyantrak"), config.clone()),
                    (home.join("AppData").join("Local").join("niyantrak").join("state"), state.clone()),
                ];
                (config, state, legacy)
            }
        };
        Layout { ssh_config: ssh_dir.join("config"), ssh_dir, state_dir, config_dir, legacy_dirs, home }
    }

    /// The current user's home (HOME on Unix, USERPROFILE on Windows). On Windows the migration sources follow
    /// %APPDATA% / %LOCALAPPDATA% when those are set (redirected profile folders).
    pub fn current_user() -> Option<Layout> {
        let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let mut l = std::env::var_os(var).filter(|v| !v.is_empty()).map(|h| Layout::for_home(PathBuf::from(h)))?;
        if cfg!(windows) {
            let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
            if let Some(r) = env("APPDATA") {
                l.legacy_dirs[0].0 = r.join("niyantrak");
            }
            if let Some(lo) = env("LOCALAPPDATA") {
                l.legacy_dirs[1].0 = lo.join("niyantrak").join("state");
            }
        }
        Some(l)
    }

    /// Copy files from the old %APPDATA% locations once. Never overwrites a file that already exists in the new
    /// place, never deletes the source, and records what it did in `<state>/migration.log`. Returns the files
    /// copied. A marker in the config dir makes later calls a no-op.
    pub fn migrate_legacy(&self) -> Vec<String> {
        let marker = self.config_dir.join(MIGRATION_MARKER);
        if marker.exists() || !self.legacy_dirs.iter().any(|(from, _)| from.is_dir()) {
            return vec![];
        }
        let mut copied = vec![];
        let mut log = vec![];
        for (from, to) in &self.legacy_dirs {
            let Ok(rd) = fs::read_dir(from) else { continue };
            for e in rd.flatten() {
                let src = e.path();
                if !src.is_file() {
                    continue;
                }
                let dst = to.join(e.file_name());
                if dst.exists() {
                    log.push(format!("kept existing {} (not copied from {})", dst.display(), src.display()));
                    continue;
                }
                let res = fs::create_dir_all(to).and_then(|_| fs::copy(&src, &dst));
                match res {
                    Ok(_) => {
                        log.push(format!("copied {} -> {}", src.display(), dst.display()));
                        copied.push(dst.display().to_string());
                    }
                    Err(err) => log.push(format!("FAILED to copy {} -> {}: {err}", src.display(), dst.display())),
                }
            }
        }
        let ts = timeutil::iso(timeutil::now());
        let text: String = log.iter().map(|l| format!("{ts} migrate-from-appdata {l}\n")).collect();
        if fs::create_dir_all(&self.state_dir).is_ok() {
            if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(self.state_dir.join("migration.log")) {
                use std::io::Write;
                let _ = f.write_all(text.as_bytes());
            }
        }
        if fs::create_dir_all(&self.config_dir).is_ok() {
            let _ = fs::write(&marker, format!("{ts}\n"));
        }
        copied
    }

    pub fn key(&self, c: &Connection) -> PathBuf {
        self.ssh_dir.join(c.key_name())
    }
    pub fn new_key(&self, c: &Connection) -> PathBuf {
        with_suffix(&self.key(c), ".new")
    }
    pub fn rotated_at(&self, c: &Connection) -> PathBuf {
        with_suffix(&self.key(c), ".rotated-at")
    }
    pub fn retired(&self, c: &Connection, stamp: &str) -> PathBuf {
        with_suffix(&self.key(c), &format!(".retired-{stamp}"))
    }
    pub fn audit_log(&self) -> PathBuf {
        self.state_dir.join("ssh-rotation.jsonl")
    }
    /// 6W events. The file keeps its original `.5w.jsonl` name so existing `niyantrak telemetry ingest` jobs and
    /// older logs stay where they are; the core reads both `niyantrak.5w/1` and `niyantrak.6w/1` lines.
    pub fn sixw_log(&self) -> PathBuf {
        self.state_dir.join("ssh-rotation.5w.jsonl")
    }
    pub fn connections_file(&self) -> PathBuf {
        self.config_dir.join("connections.json")
    }
    pub fn features_file(&self) -> PathBuf {
        self.config_dir.join("features.json")
    }
    pub fn enrolment_file(&self) -> PathBuf {
        self.config_dir.join("enrolment.json")
    }
    pub fn expand(&self, p: &str) -> PathBuf {
        if let Some(rest) = p.strip_prefix("~/").or_else(|| p.strip_prefix("~\\")) {
            self.home.join(rest)
        } else {
            PathBuf::from(p)
        }
    }
}

pub fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

pub fn pub_of(p: &Path) -> PathBuf {
    with_suffix(p, ".pub")
}

pub fn read_pub(p: &Path) -> Option<PubKey> {
    fs::read_to_string(pub_of(p)).ok().and_then(|s| PubKey::parse(s.lines().next().unwrap_or("")))
}

fn mtime(p: &Path) -> Option<i64> {
    let t = fs::metadata(p).ok()?.modified().ok()?;
    Some(t.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64)
}

/// The key a connection uses right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentKey {
    pub path: PathBuf,
    pub pubkey: PubKey,
    /// true while the connection still uses its pre-migration key (e.g. a shared id_ed25519)
    pub legacy: bool,
    /// when it was last rotated: the `.rotated-at` sidecar, else the `.pub` file's date
    pub since: Option<i64>,
}

pub fn current_key(l: &Layout, c: &Connection) -> Result<CurrentKey, String> {
    let own = l.key(c);
    if own.is_file() {
        let pubkey = read_pub(&own).ok_or_else(|| format!("{} has no readable .pub next to it", own.display()))?;
        let since = fs::read_to_string(l.rotated_at(c))
            .ok()
            .and_then(|s| timeutil::parse_iso(&s))
            .or_else(|| mtime(&pub_of(&own)));
        return Ok(CurrentKey { path: own, pubkey, legacy: false, since });
    }
    if let Some(lk) = &c.legacy_key {
        let p = l.expand(lk);
        if p.is_file() {
            let pubkey = read_pub(&p).ok_or_else(|| format!("{} has no readable .pub next to it", p.display()))?;
            let since = mtime(&pub_of(&p));
            return Ok(CurrentKey { path: p, pubkey, legacy: true, since });
        }
        return Err(format!("legacy key {} not found", p.display()));
    }
    Err(format!("no key for this connection ({} missing and no legacy_key declared)", own.display()))
}

/// Retired copies of a connection's key with the time they were retired.
pub fn retired_files(l: &Layout, c: &Connection) -> Vec<(PathBuf, i64)> {
    let prefix = format!("{}.retired-", c.key_name());
    let mut out = vec![];
    if let Ok(rd) = fs::read_dir(&l.ssh_dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(rest) = name.strip_prefix(&prefix) {
                let stamp = rest.strip_suffix(".pub").unwrap_or(rest);
                if let Some(ts) = timeutil::parse_stamp(stamp) {
                    out.push((e.path(), ts));
                }
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RotationConfig;

    fn conn() -> Connection {
        RotationConfig::from_json(r#"{"connections":[{"source":"desk","user":"alice","target":"aipc","target_user":"alice","legacy_key":"~/.ssh/id_ed25519"}]}"#)
            .unwrap()
            .connections
            .remove(0)
    }
    const PUBL: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA c\n";

    #[test]
    fn unix_keeps_xdg_and_windows_uses_dot_niyantrak() {
        let u = Layout::for_home_on("/h", Platform::Unix);
        assert_eq!(u.config_dir, PathBuf::from("/h/.config/niyantrak"));
        assert_eq!(u.state_dir, PathBuf::from("/h/.local/state/niyantrak"));
        assert!(u.legacy_dirs.is_empty());
        let w = Layout::for_home_on("/h", Platform::Windows);
        assert_eq!(w.config_dir, PathBuf::from("/h/.niyantrak"));
        assert_eq!(w.state_dir, PathBuf::from("/h/.niyantrak/state"));
        assert_eq!(w.connections_file(), PathBuf::from("/h/.niyantrak/connections.json"));
        assert_eq!(w.ssh_dir, PathBuf::from("/h/.ssh"));
        // %APPDATA% (MSIX-virtualized) is only ever a migration source
        assert_eq!(w.legacy_dirs, vec![
            (PathBuf::from("/h/AppData/Roaming/niyantrak"), PathBuf::from("/h/.niyantrak")),
            (PathBuf::from("/h/AppData/Local/niyantrak/state"), PathBuf::from("/h/.niyantrak/state")),
        ]);
    }

    #[test]
    fn migration_copies_appdata_once_and_logs_it() {
        let t = tempfile::tempdir().unwrap();
        let l = Layout::for_home_on(t.path(), Platform::Windows);
        let roaming = t.path().join("AppData/Roaming/niyantrak");
        let local = t.path().join("AppData/Local/niyantrak/state");
        fs::create_dir_all(&roaming).unwrap();
        fs::create_dir_all(&local).unwrap();
        fs::write(roaming.join("connections.json"), "{\"old\":1}").unwrap();
        fs::write(roaming.join("enrolment.json"), "{}").unwrap();
        fs::write(local.join("ssh-rotation.jsonl"), "line\n").unwrap();
        // a file already in the new place is never overwritten
        fs::create_dir_all(&l.config_dir).unwrap();
        fs::write(l.config_dir.join("enrolment.json"), "{\"new\":1}").unwrap();

        let copied = l.migrate_legacy();
        assert_eq!(copied.len(), 2, "{copied:?}");
        assert_eq!(fs::read_to_string(l.connections_file()).unwrap(), "{\"old\":1}");
        assert_eq!(fs::read_to_string(l.enrolment_file()).unwrap(), "{\"new\":1}");
        assert_eq!(fs::read_to_string(l.audit_log()).unwrap(), "line\n");
        assert!(roaming.join("connections.json").exists(), "copied, never moved");
        let log = fs::read_to_string(l.state_dir.join("migration.log")).unwrap();
        assert!(log.contains("connections.json") && log.contains("ssh-rotation.jsonl"), "{log}");
        assert!(log.contains("kept existing") && log.contains("enrolment.json"), "{log}");

        // second run: marker present, nothing copied, even if the source changes
        fs::write(roaming.join("features.json"), "{}").unwrap();
        assert!(l.migrate_legacy().is_empty());
        assert!(!l.features_file().exists());
    }

    #[test]
    fn migration_is_a_noop_without_legacy_dirs() {
        let t = tempfile::tempdir().unwrap();
        let w = Layout::for_home_on(t.path(), Platform::Windows);
        assert!(w.migrate_legacy().is_empty());
        assert!(!w.config_dir.exists(), "nothing created when there is nothing to migrate");
        let u = Layout::for_home_on(t.path(), Platform::Unix);
        assert!(u.migrate_legacy().is_empty());
    }

    #[test]
    fn paths_hang_off_home() {
        let l = Layout::for_home("/h");
        let c = conn();
        assert_eq!(l.key(&c), PathBuf::from("/h/.ssh/desk-aipc-alice"));
        assert_eq!(l.new_key(&c), PathBuf::from("/h/.ssh/desk-aipc-alice.new"));
        assert_eq!(pub_of(&l.new_key(&c)), PathBuf::from("/h/.ssh/desk-aipc-alice.new.pub"));
        assert_eq!(l.retired(&c, "20261023T033000Z"), PathBuf::from("/h/.ssh/desk-aipc-alice.retired-20261023T033000Z"));
        assert_eq!(l.expand("~/.ssh/id_ed25519"), PathBuf::from("/h/.ssh/id_ed25519"));
    }

    #[test]
    fn current_key_prefers_own_then_legacy() {
        let t = tempfile::tempdir().unwrap();
        let l = Layout::for_home(t.path());
        fs::create_dir_all(&l.ssh_dir).unwrap();
        let c = conn();
        assert!(current_key(&l, &c).unwrap_err().contains("legacy key"));
        fs::write(l.ssh_dir.join("id_ed25519"), "x").unwrap();
        fs::write(l.ssh_dir.join("id_ed25519.pub"), PUBL).unwrap();
        let k = current_key(&l, &c).unwrap();
        assert!(k.legacy && k.since.is_some());
        fs::write(l.key(&c), "x").unwrap();
        fs::write(pub_of(&l.key(&c)), PUBL).unwrap();
        fs::write(l.rotated_at(&c), "2026-01-01T00:00:00Z\n").unwrap();
        let k = current_key(&l, &c).unwrap();
        assert!(!k.legacy);
        assert_eq!(k.since, timeutil::parse_iso("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn finds_retired_copies() {
        let t = tempfile::tempdir().unwrap();
        let l = Layout::for_home(t.path());
        fs::create_dir_all(&l.ssh_dir).unwrap();
        let c = conn();
        fs::write(l.retired(&c, "20260101T000000Z"), "x").unwrap();
        fs::write(pub_of(&l.retired(&c, "20260101T000000Z")), "x").unwrap();
        fs::write(l.ssh_dir.join("desk-aipc-alice.retired-garbage"), "x").unwrap();
        let r = retired_files(&l, &c);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|(_, ts)| *ts == timeutil::parse_iso("2026-01-01T00:00:00Z").unwrap()));
    }
}
