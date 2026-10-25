//! Full rotations against a real, throwaway OpenSSH server.
//!
//! The test starts `sshd` as the current (unprivileged) user on 127.0.0.1:<free port> from a temp dir, with its own
//! host key and its own authorized_keys file, and runs the 7-step contract through the system `ssh`/`ssh-keygen`.
//! Nothing touches the real ~/.ssh: the engine's home is a temp dir, the connection points at the temp
//! authorized_keys file, known_hosts is a temp file, and sshd is killed when the test ends.
//! Ignored unless the `real-sshd` feature is on (`cargo test -p keys-engine --features real-sshd`); with the
//! feature on it still skips (passes with a note) when /usr/sbin/sshd or ssh is not installed.

use keys_engine::audit::Audit;
use keys_engine::identity;
use keys_engine::layout::{pub_of, read_pub, Layout};
use keys_engine::plan::{plan, PlanOptions};
use keys_engine::rotate::{Outcome, Rotator, StepResult};
use keys_engine::timeutil::{self, DAY};
use keys_engine::transport::{SystemTransport, Transport};
use keys_engine::RotationConfig;
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SSHD: &str = "/usr/sbin/sshd";

struct Server {
    child: Child,
    port: u16,
    dir: tempfile::TempDir,
    ak: PathBuf,
    known_hosts: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn me() -> String {
    identity::current().name
}

fn keygen(path: &Path, comment: &str) {
    let ok = Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"]).arg(path).status().unwrap();
    assert!(ok.success());
}

fn start() -> Option<Server> {
    if !Path::new(SSHD).exists() || Command::new("ssh").arg("-V").output().is_err() {
        eprintln!("SKIP: {SSHD} or ssh not installed");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    keygen(&d.join("host_ed25519"), "throwaway-test-host");
    let ak = d.join("authorized_keys");
    fs::write(&ak, "").unwrap();
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let cfg = d.join("sshd_config");
    fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {hk}\nPidFile {pid}\nAuthorizedKeysFile {ak}\nStrictModes no\nUsePAM no\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitUserRC no\n\
             AllowUsers {user}\nLogLevel ERROR\n",
            hk = d.join("host_ed25519").display(),
            pid = d.join("sshd.pid").display(),
            ak = ak.display(),
            user = me()
        ),
    )
    .unwrap();
    let child = Command::new(SSHD).args(["-D", "-e", "-f"]).arg(&cfg).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let t0 = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(t0.elapsed() < Duration::from_secs(10), "sshd did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    let host_pub = fs::read_to_string(pub_of(&d.join("host_ed25519"))).unwrap();
    let known_hosts = d.join("known_hosts");
    fs::write(&known_hosts, format!("[127.0.0.1]:{port} {}", host_pub.trim())).unwrap();
    Some(Server { child, port, ak, known_hosts, dir })
}

/// A temp home with this connection's own key, `age_days` old and authorised on the server.
fn home_with_key(s: &Server, cfg: &RotationConfig, age_days: i64) -> (tempfile::TempDir, Layout) {
    let h = tempfile::tempdir().unwrap();
    let l = Layout::for_home(h.path());
    fs::create_dir_all(&l.ssh_dir).unwrap();
    let c = &cfg.connections[0];
    keygen(&l.key(c), &c.comment("20260425"));
    fs::write(l.rotated_at(c), timeutil::iso(timeutil::now() - age_days * DAY)).unwrap();
    let line = read_pub(&l.key(c)).unwrap().line();
    fs::write(&s.ak, format!("{line}\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA unrelated-line\n")).unwrap();
    (h, l)
}

fn config(s: &Server, ak: &Path) -> RotationConfig {
    RotationConfig::from_json(&format!(
        r#"{{"max_age_days":90,"connections":[{{"source":"test-client","user":"{u}","target":"throwaway-sshd","target_user":"{u}",
            "hostname":"127.0.0.1","port":{p},"authorized_keys":"{ak}"}}]}}"#,
        u = me(),
        p = s.port,
        ak = ak.display()
    ))
    .unwrap()
}

fn transport(s: &Server) -> SystemTransport {
    SystemTransport { known_hosts: Some(s.known_hosts.clone()), connect_timeout: 5, ..Default::default() }
}

#[test]
#[cfg_attr(not(feature = "real-sshd"), ignore = "needs a local OpenSSH server; run with --features real-sshd")]
fn real_rotation_end_to_end() {
    let Some(s) = start() else { return };
    let cfg = config(&s, &s.ak);
    let (_h, l) = home_with_key(&s, &cfg, 120);
    let c = cfg.connections[0].clone();
    let old = read_pub(&l.key(&c)).unwrap();
    let mut t = transport(&s);
    let ep = t.resolve(&c).unwrap();
    t.login(&ep, &l.key(&c)).expect("old key logs in before rotation");

    // plan is read-only and sees the connection due and reachable, with one off-pattern line
    let p = plan(&cfg, &l, &mut t, &PlanOptions { node: "test-client".into(), user: me(), probe: true, now: timeutil::now() });
    let st = &p.connections[0];
    assert_eq!((st.due, st.reachable, st.age_days), (true, Some(true), Some(120)));
    assert_eq!(p.summary.off_pattern, 1);
    assert_eq!(fs::read_to_string(&s.ak).unwrap().lines().count(), 2);

    // dry run: nothing changes
    let mut audit = Audit::files(l.audit_log(), l.sixw_log());
    let before = fs::read_to_string(&s.ak).unwrap();
    let r = Rotator { layout: &l, policy: &cfg.policy, transport: &mut t, audit: &mut audit, actor: identity::current(), now: timeutil::now(), apply: false, force: false, owned: cfg.connections.clone() }
        .rotate(&c, &mut |_| {});
    assert_eq!(r.outcome, Outcome::Planned);
    assert_eq!(fs::read_to_string(&s.ak).unwrap(), before);

    // apply: the 7 steps for real
    let mut steps = vec![];
    let r = Rotator { layout: &l, policy: &cfg.policy, transport: &mut t, audit: &mut audit, actor: identity::current(), now: timeutil::now(), apply: true, force: false, owned: cfg.connections.clone() }
        .rotate(&c, &mut |ev| steps.push((ev.no, ev.result)));
    assert_eq!(r.outcome, Outcome::Rotated, "{:#?}", r.steps);
    assert_eq!(steps, (1..=7).map(|n| (n, StepResult::Ok)).collect::<Vec<_>>());

    let new = read_pub(&l.key(&c)).unwrap();
    assert_ne!(new.blob, old.blob);
    assert!(new.comment.starts_with(&format!("test-client-throwaway-sshd-{}-", me())));
    let ak = fs::read_to_string(&s.ak).unwrap();
    assert!(ak.contains(&new.blob) && !ak.contains(&old.blob) && ak.contains("unrelated-line"), "{ak}");

    // only the new key gets in now; the retired copy is refused
    t.login(&ep, &l.key(&c)).expect("new key logs in");
    let retired = keys_engine::layout::retired_files(&l, &c);
    let retired_key = retired.iter().map(|(p, _)| p).find(|p| !p.to_string_lossy().ends_with(".pub")).unwrap();
    assert!(t.login(&ep, retired_key).is_err(), "old key no longer accepted");

    // ssh config written, audit carries fingerprints only
    assert!(fs::read_to_string(&l.ssh_config).unwrap().contains("IdentitiesOnly yes"));
    let log = fs::read_to_string(l.audit_log()).unwrap();
    assert_eq!(log.lines().filter(|x| x.contains("\"dry_run\":false")).count(), 7);
    assert!(log.contains(&new.fingerprint()) && !log.contains(&new.blob) && !log.contains("PRIVATE KEY"));
    assert_eq!(fs::read_to_string(l.sixw_log()).unwrap().lines().count(), 14);
}

#[test]
#[cfg_attr(not(feature = "real-sshd"), ignore = "needs a local OpenSSH server; run with --features real-sshd")]
fn real_verify_failure_removes_new_key_and_keeps_old() {
    let Some(s) = start() else { return };
    // the connection writes keys to a file this sshd never reads: install "succeeds", verify must fail
    let decoy = s.dir.path().join("not-read-by-sshd");
    fs::write(&decoy, "").unwrap();
    let cfg = config(&s, &decoy);
    let (_h, l) = home_with_key(&s, &cfg, 120);
    let c = cfg.connections[0].clone();
    let old = fs::read_to_string(pub_of(&l.key(&c))).unwrap();
    let mut t = transport(&s);
    let mut audit = Audit::memory();
    let r = Rotator { layout: &l, policy: &cfg.policy, transport: &mut t, audit: &mut audit, actor: identity::current(), now: timeutil::now(), apply: true, force: false, owned: cfg.connections.clone() }
        .rotate(&c, &mut |_| {});
    assert_eq!(r.outcome, Outcome::Failed);
    assert_eq!(r.steps.last().map(|x| (x.no, x.result)), Some((5, StepResult::Fail)));
    assert_eq!(fs::read_to_string(&decoy).unwrap().trim(), "", "new key removed again");
    assert_eq!(fs::read_to_string(pub_of(&l.key(&c))).unwrap(), old, "old key untouched");
    assert!(!l.new_key(&c).exists());
    let ep = t.resolve(&c).unwrap();
    t.login(&ep, &l.key(&c)).expect("old key still logs in");
}

#[test]
#[cfg_attr(not(feature = "real-sshd"), ignore = "needs a local OpenSSH server; run with --features real-sshd")]
fn real_preflight_failure_skips() {
    let Some(s) = start() else { return };
    let cfg = config(&s, &s.ak);
    let (_h, l) = home_with_key(&s, &cfg, 120);
    fs::write(&s.ak, "").unwrap(); // the target no longer accepts the current key
    let c = cfg.connections[0].clone();
    let mut t = transport(&s);
    let mut audit = Audit::memory();
    let r = Rotator { layout: &l, policy: &cfg.policy, transport: &mut t, audit: &mut audit, actor: identity::current(), now: timeutil::now(), apply: true, force: false, owned: cfg.connections.clone() }
        .rotate(&c, &mut |_| {});
    assert_eq!(r.outcome, Outcome::Unreachable);
    assert!(!l.new_key(&c).exists());
    assert_eq!(fs::read_to_string(&s.ak).unwrap(), "");
}
