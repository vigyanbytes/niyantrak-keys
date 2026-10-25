//! The 7-step per-connection rotation contract (DESIGN_SSH_ROTATION_AND_WHATSAPP_ALERTS.md, Part A).
//!
//! 1 due        key age (`.rotated-at`, else the `.pub` date) >= max_age_days, or the connection still uses its
//!              legacy key (first run = migration) -> else skip quietly
//! 2 preflight  target reachable with the CURRENT key -> else skip today, retry next run
//! 3 stage      new key at `<key>.new`; the current key is untouched
//! 4 install    new public key appended on the target (Linux authorized_keys; Windows administrators_authorized_keys)
//! 5 verify     log in with ONLY the new key (`ssh -F <null> -i <key>.new -o IdentitiesOnly=yes`);
//!              failure -> remove the new key from the target, delete it locally, old key unchanged, alert
//! 6 switch     old -> `<key>.retired-<ts>` (kept retired_keep_days), new -> `<key>`, write `.rotated-at`,
//!              point `Host <target>` in ~/.ssh/config at it (IdentityFile + IdentitiesOnly yes)
//! 7 retire     remove the old public key from the target, re-verify with the current key; a failure alerts with
//!              the exact recovery command
//! Dry run (the default everywhere): steps 1-2 run (read-only), 3-7 are reported as planned.
//! One target per connection, so a rotation is never partial across targets. Private keys never leave this device.

use crate::audit::{Audit, AuditLine};
use crate::identity::Identity;
use crate::layout::{self, current_key, pub_of, read_pub, CurrentKey, Layout};
use crate::model::{Connection, Policy};
use crate::sshconfig;
use crate::timeutil::{self, DAY};
use crate::transport::{Endpoint, Transport};
use serde::Serialize;
use std::fs;
use std::path::Path;

pub const STEPS: [&str; 7] = ["due", "preflight", "stage", "install", "verify", "switch", "retire"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StepResult {
    Ok,
    Skip,
    Fail,
    Warn,
    Planned,
}

impl StepResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            StepResult::Ok => "ok",
            StepResult::Skip => "skip",
            StepResult::Fail => "fail",
            StepResult::Warn => "warn",
            StepResult::Planned => "planned",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepEvent {
    pub connection: String,
    pub no: u8,
    pub step: String,
    pub result: StepResult,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_fp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_fp: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    NotDue,
    Unreachable,
    Planned,
    Rotated,
    RotatedWithWarning,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    /// warning | critical
    pub level: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RotationReport {
    pub connection: String,
    pub outcome: Outcome,
    pub steps: Vec<StepEvent>,
    pub old_fp: Option<String>,
    pub new_fp: Option<String>,
    pub overdue: bool,
    pub alert: Option<Alert>,
}

pub struct Rotator<'a> {
    pub layout: &'a Layout,
    pub policy: &'a Policy,
    pub transport: &'a mut dyn Transport,
    pub audit: &'a mut Audit,
    pub actor: Identity,
    pub now: i64,
    pub apply: bool,
    /// rotate even when not due
    pub force: bool,
    /// every connection this device owns (to keep a legacy key on a target another connection still uses)
    pub owned: Vec<Connection>,
}

struct Run<'r> {
    c: &'r Connection,
    steps: Vec<StepEvent>,
    old_fp: Option<String>,
    new_fp: Option<String>,
}

fn remove_pair(p: &Path) {
    let _ = fs::remove_file(p);
    let _ = fs::remove_file(pub_of(p));
}

/// A path as one shell word: double-quoted when it holds whitespace or quotes, so a printed command pastes and
/// runs as-is in POSIX shells, cmd and PowerShell (e.g. `C:\Users\First Last\.ssh\...`).
pub fn shell_arg(p: &Path) -> String {
    let s = p.display().to_string();
    if s.chars().any(|c| c.is_whitespace() || c == '\'' || c == '"') {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s
    }
}

/// The command that shows what a connection would do; printed in alerts.
pub fn login_command(ep: &Endpoint, key: &Path) -> String {
    format!(
        "ssh -F {} -i {} -o IdentitiesOnly=yes -p {} {}@{}",
        crate::transport::NULL_CONFIG,
        shell_arg(key),
        ep.port,
        ep.user,
        ep.host
    )
}

impl<'a> Rotator<'a> {
    fn emit(&mut self, run: &mut Run, no: u8, result: StepResult, detail: String, progress: &mut dyn FnMut(&StepEvent)) {
        let ev = StepEvent {
            connection: run.c.id(),
            no,
            step: if no == 0 { "cleanup".into() } else { STEPS[(no - 1) as usize].into() },
            result,
            detail: detail.clone(),
            old_fp: run.old_fp.clone(),
            new_fp: run.new_fp.clone(),
        };
        progress(&ev);
        self.audit.record(AuditLine {
            ts: timeutil::iso(self.now),
            connection: run.c.id(),
            source: run.c.source.clone(),
            user: run.c.user.clone(),
            target: run.c.target.clone(),
            target_user: run.c.target_user.clone(),
            step: ev.step.clone(),
            step_no: no,
            result: result.as_str().into(),
            old_fp: run.old_fp.clone(),
            new_fp: run.new_fp.clone(),
            detail,
            who: self.actor.name.clone(),
            who_id: self.actor.stable_id.clone(),
            dry_run: !self.apply,
        });
        run.steps.push(ev);
    }

    fn finish(run: Run, outcome: Outcome, overdue: bool, alert: Option<Alert>) -> RotationReport {
        RotationReport { connection: run.c.id(), outcome, steps: run.steps, old_fp: run.old_fp, new_fp: run.new_fp, overdue, alert }
    }

    /// Delete retired copies older than retired_keep_days (apply mode only).
    fn cleanup(&mut self, run: &mut Run, progress: &mut dyn FnMut(&StepEvent)) {
        let keep = self.policy.retired_keep_days as i64 * DAY;
        let mut gone = vec![];
        for (p, ts) in layout::retired_files(self.layout, run.c) {
            if self.now - ts >= keep && fs::remove_file(&p).is_ok() {
                gone.push(p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
            }
        }
        if !gone.is_empty() {
            self.emit(run, 0, StepResult::Ok, format!("deleted retired copies older than {} days: {}", self.policy.retired_keep_days, gone.join(", ")), progress);
        }
    }

    /// Is the legacy key still the current key of another owned connection to the same target account?
    fn legacy_shared_with(&self, c: &Connection, cur: &CurrentKey) -> Option<String> {
        self.owned
            .iter()
            .filter(|o| o.id() != c.id() && o.target == c.target && o.target_user == c.target_user)
            .find(|o| current_key(self.layout, o).map(|k| k.legacy && k.pubkey.blob == cur.pubkey.blob).unwrap_or(false))
            .map(|o| o.id())
    }

    pub fn rotate(&mut self, c: &Connection, progress: &mut dyn FnMut(&StepEvent)) -> RotationReport {
        let mut run = Run { c, steps: vec![], old_fp: None, new_fp: None };
        if self.apply {
            self.cleanup(&mut run, progress);
        }

        // 1 due
        let cur = match current_key(self.layout, c) {
            Ok(k) => k,
            Err(e) => {
                self.emit(&mut run, 1, StepResult::Fail, e.clone(), progress);
                let alert = Alert { level: "warning".into(), message: format!("{}: {e}", c.id()), recovery: None };
                return Self::finish(run, Outcome::Failed, false, Some(alert));
            }
        };
        run.old_fp = Some(cur.pubkey.fingerprint());
        let age_days = cur.since.map(|s| (self.now - s).max(0) / DAY);
        let max = self.policy.max_age_days as i64;
        let overdue = age_days.is_some_and(|a| a >= max + self.policy.overdue_alert_days as i64);
        let due = self.force || cur.legacy || age_days.is_none_or(|a| a >= max);
        if !due {
            self.emit(&mut run, 1, StepResult::Skip, format!("key is {} days old; due at {max}", age_days.unwrap_or(0)), progress);
            return Self::finish(run, Outcome::NotDue, false, None);
        }
        let why = if self.force {
            "forced".to_string()
        } else if cur.legacy {
            format!("migration from {} to its own key", cur.path.display())
        } else {
            match age_days {
                Some(a) => format!("key is {a} days old (max {max})"),
                None => "key age unknown".into(),
            }
        };
        self.emit(&mut run, 1, StepResult::Ok, why, progress);

        // 2 preflight
        let ep = match self.transport.resolve(c) {
            Ok(ep) => ep,
            Err(e) => {
                self.emit(&mut run, 2, StepResult::Skip, format!("cannot resolve {}: {e}", c.target), progress);
                let alert = overdue.then(|| Alert {
                    level: "warning".into(),
                    message: format!("{} is overdue for rotation and its target cannot be resolved", c.id()),
                    recovery: None,
                });
                return Self::finish(run, Outcome::Unreachable, overdue, alert);
            }
        };
        if let Err(e) = self.transport.login(&ep, &cur.path) {
            self.emit(&mut run, 2, StepResult::Skip, format!("{} not reachable with the current key; retry next run ({e})", ep.label()), progress);
            let alert = overdue.then(|| Alert {
                level: "warning".into(),
                message: format!("{} is {} days old, past due + {} days, and {} is unreachable", c.id(), age_days.unwrap_or(0), self.policy.overdue_alert_days, ep.label()),
                recovery: None,
            });
            return Self::finish(run, Outcome::Unreachable, overdue, alert);
        }
        self.emit(&mut run, 2, StepResult::Ok, format!("{} reachable with the current key", ep.label()), progress);

        let key = self.layout.key(c);
        let new = self.layout.new_key(c);
        if !self.apply {
            let comment = c.comment(&timeutil::ymd(self.now));
            let planned = [
                format!("would create {} ({comment})", new.display()),
                format!("would append the new public key to {} on {}", ep.authorized_keys, ep.label()),
                format!("would verify with only the new key: {}", login_command(&ep, &new)),
                if cur.legacy {
                    format!("would move the new key to {} and point Host {} at it ({} stays as is)", key.display(), c.target, cur.path.display())
                } else {
                    format!("would keep the old key as {}.retired-<ts> for {} days", key.display(), self.policy.retired_keep_days)
                },
                format!("would remove the old public key {} from the target and re-verify", run.old_fp.clone().unwrap_or_default()),
            ];
            for (i, d) in planned.into_iter().enumerate() {
                self.emit(&mut run, 3 + i as u8, StepResult::Planned, d, progress);
            }
            return Self::finish(run, Outcome::Planned, overdue, None);
        }

        // 3 stage
        if new.exists() {
            if let Some(stale) = read_pub(&new) {
                let _ = self.transport.remove(&ep, &cur.path, &stale.blob); // a crashed run may have installed it
            }
            remove_pair(&new);
        }
        if let Some(dir) = new.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let comment = c.comment(&timeutil::ymd(self.now));
        let staged = self.transport.keygen(&new, &comment).map_err(|e| e.0).and_then(|_| read_pub(&new).ok_or_else(|| "new key has no readable .pub".to_string()));
        let new_pub = match staged {
            Ok(p) => p,
            Err(e) => {
                remove_pair(&new);
                self.emit(&mut run, 3, StepResult::Fail, format!("could not create the new key: {e}"), progress);
                return Self::finish(run, Outcome::Failed, overdue, Some(Alert { level: "warning".into(), message: format!("{}: key generation failed, nothing changed", c.id()), recovery: None }));
            }
        };
        run.new_fp = Some(new_pub.fingerprint());
        self.emit(&mut run, 3, StepResult::Ok, format!("created {} ({comment})", new.display()), progress);

        // 4 install
        if let Err(e) = self.transport.install(&ep, &cur.path, &new_pub.line()) {
            let _ = self.transport.remove(&ep, &cur.path, &new_pub.blob);
            remove_pair(&new);
            self.emit(&mut run, 4, StepResult::Fail, format!("could not add the new key on {}: {e}; old key unchanged", ep.label()), progress);
            return Self::finish(run, Outcome::Failed, overdue, Some(Alert { level: "warning".into(), message: format!("{}: install on {} failed, old key unchanged", c.id(), ep.label()), recovery: None }));
        }
        self.emit(&mut run, 4, StepResult::Ok, format!("new public key added to {} on {}", ep.authorized_keys, ep.label()), progress);

        // 5 verify — only the new key
        if let Err(e) = self.transport.login(&ep, &new) {
            let removed = self.transport.remove(&ep, &cur.path, &new_pub.blob);
            remove_pair(&new);
            let tail = match removed {
                Ok(()) => "new key removed from the target and deleted here; old key unchanged".to_string(),
                Err(r) => format!("could not remove the new key from the target ({r}); it was deleted here, so it cannot be used; old key unchanged"),
            };
            self.emit(&mut run, 5, StepResult::Fail, format!("login with only the new key failed ({e}); {tail}"), progress);
            return Self::finish(run, Outcome::Failed, overdue, Some(Alert {
                level: "warning".into(),
                message: format!("{}: verification with the new key failed on {}; {tail}", c.id(), ep.label()),
                recovery: None,
            }));
        }
        self.emit(&mut run, 5, StepResult::Ok, format!("logged in with only the new key: {}", login_command(&ep, &new)), progress);

        // 6 switch
        let stamp = timeutil::stamp(self.now);
        let retired = self.layout.retired(c, &stamp);
        let switched: Result<(), String> = (|| {
            if !cur.legacy {
                fs::rename(&key, &retired).map_err(|e| format!("retire {}: {e}", key.display()))?;
                if let Err(e) = fs::rename(pub_of(&key), pub_of(&retired)) {
                    let _ = fs::rename(&retired, &key);
                    return Err(format!("retire {}: {e}", pub_of(&key).display()));
                }
            }
            let back = |l: &Layout| {
                if !cur.legacy {
                    let _ = fs::rename(&retired, l.key(c));
                    let _ = fs::rename(pub_of(&retired), pub_of(&l.key(c)));
                }
            };
            if let Err(e) = fs::rename(&new, &key) {
                back(self.layout);
                return Err(format!("move new key into place: {e}"));
            }
            if let Err(e) = fs::rename(pub_of(&new), pub_of(&key)) {
                let _ = fs::rename(&key, &new);
                back(self.layout);
                return Err(format!("move new public key into place: {e}"));
            }
            Ok(())
        })();
        if let Err(e) = switched {
            let removed = self.transport.remove(&ep, &cur.path, &new_pub.blob);
            remove_pair(&new);
            self.emit(&mut run, 6, StepResult::Fail, format!("{e}; rolled back, new key {}", if removed.is_ok() { "removed from the target" } else { "left on the target (unusable: deleted here)" }), progress);
            return Self::finish(run, Outcome::Failed, overdue, Some(Alert { level: "warning".into(), message: format!("{}: local switch failed, old key still in use", c.id()), recovery: None }));
        }
        let _ = fs::write(self.layout.rotated_at(c), format!("{}\n", timeutil::iso(self.now)));
        let cfg_note = match sshconfig::write(&self.layout.ssh_config, c, &ep, &key) {
            Ok(()) => format!("Host {} -> IdentityFile {}", c.target, key.display()),
            Err(e) => format!("ssh config not updated ({e}); add IdentityFile {} for Host {}", key.display(), c.target),
        };
        let kept = if cur.legacy { format!("legacy {} left in place", cur.path.display()) } else { format!("old key kept as {}", retired.display()) };
        self.emit(&mut run, 6, StepResult::Ok, format!("{kept}; {cfg_note}"), progress);

        // 7 retire
        let old_line = cur.pubkey.line();
        let mut warning: Option<Alert> = None;
        if let Some(other) = cur.legacy.then(|| self.legacy_shared_with(c, &cur)).flatten() {
            warning = Some(Alert {
                level: "warning".into(),
                message: format!("{}: old key kept on {} because {other} still uses it; it is removed when {other} rotates", c.id(), ep.label()),
                recovery: None,
            });
        } else if let Err(e) = self.transport.remove(&ep, &key, &cur.pubkey.blob) {
            warning = Some(Alert {
                level: "warning".into(),
                message: format!("{}: rotated, but the old key {} is still on {} ({e})", c.id(), run.old_fp.clone().unwrap_or_default(), ep.label()),
                recovery: Some(format!("on {} remove the line ending in '{}' from {}", ep.label(), cur.pubkey.comment, ep.authorized_keys)),
            });
        }
        if let Err(e) = self.transport.login(&ep, &key) {
            let old_private = if cur.legacy { cur.path.clone() } else { retired.clone() };
            let recovery = format!(
                "from a session that still reaches {host} (console or another admin account), restore the previous key: \
                 printf '%s\\n' '{old_line}' >> {ak}  — then log in with: {cmd}",
                host = ep.label(),
                ak = ep.authorized_keys,
                cmd = login_command(&ep, &old_private)
            );
            self.emit(&mut run, 7, StepResult::Fail, format!("re-verify with the current key failed: {e}"), progress);
            return Self::finish(run, Outcome::Failed, overdue, Some(Alert {
                level: "critical".into(),
                message: format!("{}: after rotation {} does not accept the current key", c.id(), ep.label()),
                recovery: Some(recovery),
            }));
        }
        match warning {
            Some(w) => {
                self.emit(&mut run, 7, StepResult::Warn, format!("{}; re-verified with the current key", w.message), progress);
                Self::finish(run, Outcome::RotatedWithWarning, false, Some(w))
            }
            None => {
                self.emit(&mut run, 7, StepResult::Ok, format!("old public key removed from {}; re-verified with the current key", ep.label()), progress);
                Self::finish(run, Outcome::Rotated, false, None)
            }
        }
    }
}
