//! Every step and every failure branch of the rotation contract, driven through FakeTransport in a temp home.

use crate::audit::Audit;
use crate::identity::Identity;
use crate::layout::{pub_of, read_pub, Layout};
use crate::model::{Connection, Policy, RotationConfig};
use crate::rotate::{Outcome, RotationReport, Rotator, StepResult};
use crate::timeutil::{self, DAY};
use crate::transport::{FakeTransport, Transport};
use std::fs;

const NOW: i64 = 1_792_726_200; // 2026-10-23T03:30:00Z
const REMOTE: &str = "alice@edge-01";

struct Env {
    _t: tempfile::TempDir,
    layout: Layout,
    cfg: RotationConfig,
    fake: FakeTransport,
}

fn actor() -> Identity {
    Identity { name: "alice".into(), uid: Some(1000), directory: "local".into(), stable_id: "local:uid:1000@0123456789ab".into() }
}

fn conn(e: &Env) -> Connection {
    e.cfg.connections[0].clone()
}

/// A connection whose own key exists, is `age_days` old and is authorised on the fake target.
fn env(age_days: i64) -> Env {
    let t = tempfile::tempdir().unwrap();
    let layout = Layout::for_home(t.path());
    fs::create_dir_all(&layout.ssh_dir).unwrap();
    let cfg = RotationConfig::from_json(
        r#"{"ssh_rotation":{"max_age_days":90,"overdue_alert_days":14,"retired_keep_days":30,"connections":[
            {"source":"ws-01","user":"alice","target":"edge-01","target_user":"alice"}]}}"#,
    )
    .unwrap();
    let mut fake = FakeTransport::new();
    let c = cfg.connections[0].clone();
    let key = layout.key(&c);
    fake.keygen(&key, &c.comment("20260425")).unwrap();
    fs::write(layout.rotated_at(&c), timeutil::iso(NOW - age_days * DAY)).unwrap();
    let line = read_pub(&key).unwrap().line();
    fake.add_line(REMOTE, &line);
    fake.add_line(REMOTE, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA someone-else");
    fake.reset();
    Env { _t: t, layout, cfg, fake }
}

fn run(e: &mut Env, apply: bool, force: bool) -> (RotationReport, Audit) {
    let mut audit = Audit::memory();
    let policy: Policy = e.cfg.policy.clone();
    let owned = e.cfg.connections.clone();
    let c = conn(e);
    let mut seen = vec![];
    let report = {
        let mut r = Rotator { layout: &e.layout, policy: &policy, transport: &mut e.fake, audit: &mut audit, actor: actor(), now: NOW, apply, force, owned };
        r.rotate(&c, &mut |ev| seen.push((ev.no, ev.result)))
    };
    assert_eq!(seen.len(), report.steps.len(), "progress callback sees every step");
    assert_eq!(audit.lines.len(), report.steps.len(), "one audit line per step");
    assert_eq!(audit.events.len(), report.steps.len(), "one valid 6W event per step: {:?}", audit.write_errors);
    (report, audit)
}

fn steps(r: &RotationReport) -> Vec<(u8, StepResult)> {
    r.steps.iter().map(|s| (s.no, s.result)).collect()
}

fn blobs(e: &Env) -> Vec<String> {
    e.fake.lines(REMOTE).iter().filter_map(|l| crate::pubkey::PubKey::parse(l)).map(|k| k.blob).collect()
}

fn own_blob(e: &Env) -> String {
    read_pub(&e.layout.key(&conn(e))).unwrap().blob
}

#[test]
fn step1_not_due_skips_quietly() {
    let mut e = env(10);
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::NotDue);
    assert_eq!(steps(&r), vec![(1, StepResult::Skip)]);
    assert!(r.alert.is_none());
    assert!(e.fake.calls.is_empty(), "no network when not due: {:?}", e.fake.calls);
}

#[test]
fn full_rotation_happy_path() {
    let mut e = env(91);
    let c = conn(&e);
    let old = own_blob(&e);
    let (r, audit) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Rotated, "{:#?}", r.steps);
    assert_eq!(steps(&r), (1..=7).map(|n| (n, StepResult::Ok)).collect::<Vec<_>>());
    let new = own_blob(&e);
    assert_ne!(old, new);
    // target: new key in, old key out, unrelated line untouched
    let b = blobs(&e);
    assert!(b.contains(&new) && !b.contains(&old) && b.len() == 2, "{b:?}");
    // local: no .new left, old kept as retired copy, rotated-at written, ssh config points at the key
    assert!(!e.layout.new_key(&c).exists() && !pub_of(&e.layout.new_key(&c)).exists());
    let retired = e.layout.retired(&c, &timeutil::stamp(NOW));
    assert_eq!(read_pub(&retired).unwrap().blob, old);
    assert_eq!(fs::read_to_string(e.layout.rotated_at(&c)).unwrap().trim(), timeutil::iso(NOW));
    let cfg = fs::read_to_string(&e.layout.ssh_config).unwrap();
    assert!(cfg.contains("Host edge-01") && cfg.contains("IdentitiesOnly yes"));
    assert!(cfg.contains(&format!("IdentityFile {}", crate::sshconfig::identity_file_value(&e.layout.key(&c)))));
    // comment follows the pattern with today's date
    assert_eq!(read_pub(&e.layout.key(&c)).unwrap().comment, "ws-01-edge-01-alice-20261023");
    // verification used ONLY the new key (the .new path), re-verify used the switched key
    let logins: Vec<_> = e.fake.calls.iter().filter(|l| l.starts_with("login")).collect();
    assert_eq!(logins.len(), 3);
    assert!(logins[1].ends_with(".new"), "{logins:?}");
    // audit: fingerprints only
    let all = serde_json::to_string(&audit.lines).unwrap();
    assert!(all.contains(&r.new_fp.clone().unwrap()) && !all.contains("PRIVATE") && !all.contains(&new));
}

#[test]
fn dry_run_changes_nothing() {
    let mut e = env(120);
    let c = conn(&e);
    let before = fs::read_to_string(pub_of(&e.layout.key(&c))).unwrap();
    let remote_before = e.fake.lines(REMOTE);
    let (r, audit) = run(&mut e, false, false);
    assert_eq!(r.outcome, Outcome::Planned);
    assert_eq!(steps(&r)[..2], [(1, StepResult::Ok), (2, StepResult::Ok)]);
    assert!(steps(&r)[2..].iter().all(|(_, s)| *s == StepResult::Planned) && r.steps.len() == 7);
    assert_eq!(fs::read_to_string(pub_of(&e.layout.key(&c))).unwrap(), before);
    assert_eq!(e.fake.lines(REMOTE), remote_before);
    assert!(!e.layout.new_key(&c).exists() && !e.layout.ssh_config.exists());
    assert!(!e.fake.calls.iter().any(|l| l.starts_with("keygen") || l.starts_with("install") || l.starts_with("remove")));
    assert!(audit.lines.iter().all(|l| l.dry_run));
}

#[test]
fn step2_preflight_failure_skips_until_next_run() {
    let mut e = env(95);
    e.fake.unreachable.push("edge-01".into());
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Unreachable);
    assert_eq!(steps(&r), vec![(1, StepResult::Ok), (2, StepResult::Skip)]);
    assert!(r.alert.is_none(), "not overdue yet: no alert");
    assert!(!e.layout.new_key(&conn(&e)).exists());
    assert!(!e.fake.calls.iter().any(|l| l.starts_with("keygen")));
}

#[test]
fn overdue_and_unreachable_alerts() {
    let mut e = env(90 + 14 + 1);
    e.fake.unreachable.push("edge-01".into());
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Unreachable);
    assert!(r.overdue);
    let a = r.alert.unwrap();
    assert_eq!(a.level, "warning");
    assert!(a.message.contains("unreachable"), "{}", a.message);
}

#[test]
fn step3_keygen_failure_leaves_nothing_behind() {
    let mut e = env(100);
    e.fake.fail_nth("keygen", 1);
    let old = own_blob(&e);
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Failed);
    assert_eq!(steps(&r).last(), Some(&(3, StepResult::Fail)));
    assert!(!e.layout.new_key(&conn(&e)).exists());
    assert_eq!(own_blob(&e), old);
    assert!(r.alert.is_some());
}

#[test]
fn step4_install_failure_keeps_old_key() {
    let mut e = env(100);
    e.fake.fail_nth("install", 1);
    let old = own_blob(&e);
    let remote_before = e.fake.lines(REMOTE);
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Failed);
    assert_eq!(steps(&r).last(), Some(&(4, StepResult::Fail)));
    assert_eq!(e.fake.lines(REMOTE), remote_before);
    assert_eq!(own_blob(&e), old);
    assert!(!e.layout.new_key(&conn(&e)).exists());
}

#[test]
fn step5_verify_failure_removes_new_key_and_leaves_old_untouched() {
    let mut e = env(100);
    e.fake.fail_nth("login", 2); // 1 = preflight, 2 = verify with the new key
    let c = conn(&e);
    let old = own_blob(&e);
    let old_file = fs::read_to_string(pub_of(&e.layout.key(&c))).unwrap();
    let remote_before = e.fake.lines(REMOTE);
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Failed);
    assert_eq!(steps(&r).last(), Some(&(5, StepResult::Fail)));
    assert_eq!(e.fake.lines(REMOTE), remote_before, "new key removed from the target");
    assert_eq!(fs::read_to_string(pub_of(&e.layout.key(&c))).unwrap(), old_file);
    assert!(blobs(&e).contains(&old));
    assert!(!e.layout.new_key(&c).exists() && !pub_of(&e.layout.new_key(&c)).exists());
    assert!(!e.layout.ssh_config.exists());
    assert!(r.steps.last().unwrap().detail.contains("old key unchanged"));
    assert!(r.alert.is_some());
}

#[test]
fn step5_verify_failure_when_cleanup_also_fails_still_deletes_local_new_key() {
    let mut e = env(100);
    e.fake.fail_nth("login", 2);
    e.fake.fail_nth("remove", 1);
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Failed);
    assert!(r.steps.last().unwrap().detail.contains("could not remove the new key"));
    assert!(!e.layout.new_key(&conn(&e)).exists());
}

#[test]
fn step6_switch_failure_rolls_back() {
    let mut e = env(100);
    let c = conn(&e);
    let old = own_blob(&e);
    fs::create_dir_all(e.layout.retired(&c, &timeutil::stamp(NOW)).join("blocker")).unwrap(); // rename onto a non-empty dir fails
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Failed);
    assert_eq!(steps(&r).last(), Some(&(6, StepResult::Fail)));
    assert_eq!(own_blob(&e), old);
    assert!(blobs(&e).contains(&old) && blobs(&e).len() == 2, "new key removed again");
    assert!(!e.layout.new_key(&c).exists());
}

#[test]
fn step7_retire_failure_warns_with_cleanup_instruction() {
    let mut e = env(100);
    e.fake.fail_nth("remove", 1);
    let old = own_blob(&e);
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::RotatedWithWarning);
    assert_eq!(steps(&r).last(), Some(&(7, StepResult::Warn)));
    assert!(blobs(&e).contains(&old), "old key still on the target");
    let a = r.alert.unwrap();
    assert!(a.recovery.unwrap().contains("ws-01-edge-01-alice-20260425"));
}

#[test]
fn step7_reverify_failure_alerts_with_exact_recovery_command() {
    let mut e = env(100);
    e.fake.fail_nth("login", 3); // re-verify
    let c = conn(&e);
    let old_line = read_pub(&e.layout.key(&c)).unwrap().line();
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Failed);
    assert_eq!(steps(&r).last(), Some(&(7, StepResult::Fail)));
    let a = r.alert.unwrap();
    assert_eq!(a.level, "critical");
    let rec = a.recovery.unwrap();
    let retired = e.layout.retired(&c, &timeutil::stamp(NOW));
    assert!(rec.contains(&old_line), "{rec}");
    assert!(rec.contains("~/.ssh/authorized_keys"));
    let want = format!(
        "ssh -F {} -i {} -o IdentitiesOnly=yes -p 22 alice@edge-01",
        crate::transport::NULL_CONFIG,
        crate::rotate::shell_arg(&retired)
    );
    assert!(rec.contains(&want), "{rec}");
    assert!(retired.exists(), "the retired private key is still there for recovery");
}

#[test]
fn printed_commands_quote_paths_with_spaces() {
    use std::path::Path;
    assert_eq!(crate::rotate::shell_arg(Path::new("/home/a/.ssh/k")), "/home/a/.ssh/k");
    assert_eq!(crate::rotate::shell_arg(Path::new("C:\\Users\\First Last\\.ssh\\k")), "\"C:\\Users\\First Last\\.ssh\\k\"");
    assert_eq!(crate::sshconfig::identity_file_value(Path::new("C:\\Users\\First Last\\.ssh\\k")), "\"C:/Users/First Last/.ssh/k\"");
}

#[test]
fn force_rotates_a_young_key() {
    let mut e = env(3);
    let (r, _) = run(&mut e, true, true);
    assert_eq!(r.outcome, Outcome::Rotated);
}

#[test]
fn missing_key_fails_at_step1() {
    let mut e = env(100);
    let c = conn(&e);
    fs::remove_file(e.layout.key(&c)).unwrap();
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Failed);
    assert_eq!(steps(&r), vec![(1, StepResult::Fail)]);
    assert!(r.alert.unwrap().message.contains("no key"));
}

#[test]
fn stale_new_key_from_a_crashed_run_is_removed_first() {
    let mut e = env(100);
    let c = conn(&e);
    let new = e.layout.new_key(&c);
    e.fake.keygen(&new, "stale").unwrap();
    let stale = read_pub(&new).unwrap();
    e.fake.add_line(REMOTE, &stale.line());
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Rotated);
    assert!(!blobs(&e).contains(&stale.blob));
}

#[test]
fn old_retired_copies_are_deleted_after_keep_days() {
    let mut e = env(10);
    let c = conn(&e);
    let old = e.layout.retired(&c, &timeutil::stamp(NOW - 31 * DAY));
    let young = e.layout.retired(&c, &timeutil::stamp(NOW - 5 * DAY));
    for p in [&old, &young] {
        fs::write(p, "x").unwrap();
        fs::write(pub_of(p), "x").unwrap();
    }
    let (r, _) = run(&mut e, true, false);
    assert_eq!(steps(&r)[0], (0, StepResult::Ok));
    assert!(!old.exists() && !pub_of(&old).exists());
    assert!(young.exists());
    // dry run never deletes
    let mut e2 = env(10);
    let c2 = conn(&e2);
    let o2 = e2.layout.retired(&c2, &timeutil::stamp(NOW - 31 * DAY));
    fs::write(&o2, "x").unwrap();
    run(&mut e2, false, false);
    assert!(o2.exists());
}

// ── migration from a shared legacy key ──

fn legacy_env(two: bool) -> Env {
    let t = tempfile::tempdir().unwrap();
    let layout = Layout::for_home(t.path());
    fs::create_dir_all(&layout.ssh_dir).unwrap();
    let second = if two {
        r#",{"source":"ws-01","user":"deploy","target":"edge-01","target_user":"alice","legacy_key":"~/.ssh/id_ed25519"}"#
    } else {
        ""
    };
    let cfg = RotationConfig::from_json(&format!(
        r#"{{"connections":[{{"source":"ws-01","user":"alice","target":"edge-01","target_user":"alice","legacy_key":"~/.ssh/id_ed25519"}}{second}]}}"#
    ))
    .unwrap();
    let mut fake = FakeTransport::new();
    let legacy = layout.ssh_dir.join("id_ed25519");
    fake.keygen(&legacy, "ws-01-gpu-01-alice-20260425").unwrap();
    fake.add_line(REMOTE, &read_pub(&legacy).unwrap().line());
    fake.reset();
    Env { _t: t, layout, cfg, fake }
}

#[test]
fn migration_moves_to_own_key_and_leaves_legacy_file() {
    let mut e = legacy_env(false);
    let c = conn(&e);
    let legacy = e.layout.ssh_dir.join("id_ed25519");
    let legacy_pub = fs::read_to_string(pub_of(&legacy)).unwrap();
    let legacy_blob = read_pub(&legacy).unwrap().blob;
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::Rotated, "{:#?}", r.steps);
    assert!(r.steps[0].detail.contains("migration"));
    assert!(e.layout.key(&c).exists());
    assert_eq!(fs::read_to_string(pub_of(&legacy)).unwrap(), legacy_pub, "legacy file untouched");
    assert!(!blobs(&e).contains(&legacy_blob), "legacy key removed from this target only");
    assert!(blobs(&e).contains(&own_blob(&e)));
    assert!(crate::layout::retired_files(&e.layout, &c).is_empty());
}

#[test]
fn migration_keeps_a_legacy_key_another_connection_still_needs() {
    let mut e = legacy_env(true);
    let legacy_blob = read_pub(&e.layout.ssh_dir.join("id_ed25519")).unwrap().blob;
    let (r, _) = run(&mut e, true, false);
    assert_eq!(r.outcome, Outcome::RotatedWithWarning);
    assert!(blobs(&e).contains(&legacy_blob));
    assert!(r.alert.unwrap().message.contains("ws-01-edge-01-deploy"));
}
