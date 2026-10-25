//! The CLI end to end: temp home, temp connections.json, and (when installed) a throwaway sshd on 127.0.0.1.
//! Never touches the real ~/.ssh.

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_niyantrak-keys");

fn me() -> String {
    keys_engine::identity::effective_user()
}

fn cli(home: &Path, args: &[&str]) -> Output {
    Command::new(BIN).args(args).args(["--home"]).arg(home).env_remove("NIYANTRAK_CONNECTIONS").output().unwrap()
}

fn keygen(p: &Path, comment: &str) {
    assert!(Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"]).arg(p).status().unwrap().success());
}

struct Sshd(Child);
impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn plan_without_probe_is_json_and_read_only() {
    let t = tempfile::tempdir().unwrap();
    // the engine decides where the file lives (~/.config/niyantrak on Linux, AppData\Roaming\niyantrak on Windows)
    let l = keys_engine::layout::Layout::for_home(t.path());
    fs::create_dir_all(&l.config_dir).unwrap();
    fs::write(
        l.connections_file(),
        format!(r#"{{"ssh_rotation":{{"connections":[
            {{"source":"test-node","user":"{u}","target":"t1","target_user":"{u}"}},
            {{"source":"elsewhere","user":"root","target":"t1","target_user":"root"}}]}}}}"#, u = me()),
    )
    .unwrap();
    let o = cli(t.path(), &["plan", "--no-probe", "--json", "--node", "test-node"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["summary"]["total"], 2);
    assert_eq!(v["summary"]["owned"], 1);
    assert!(!t.path().join(".ssh").exists(), "plan created nothing");
}

#[test]
fn usage_errors_exit_1() {
    let t = tempfile::tempdir().unwrap();
    assert_eq!(cli(t.path(), &["rotate", "--bogus"]).status.code(), Some(1));
    let o = cli(t.path(), &["plan"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("connections.json"));
}

#[test]
fn refuses_a_connection_owned_elsewhere() {
    let t = tempfile::tempdir().unwrap();
    let f = t.path().join("c.json");
    fs::write(&f, r#"{"connections":[{"source":"other-node","user":"root","target":"t1","target_user":"root"}]}"#).unwrap();
    let o = cli(t.path(), &["rotate", "--config", f.to_str().unwrap(), "--connection", "other-node-t1-root", "--node", "test-node"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("run it there"));
}

#[test]
fn dry_run_then_apply_against_a_throwaway_sshd() {
    if !Path::new("/usr/sbin/sshd").exists() {
        eprintln!("SKIP: no sshd");
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let srv = d.join("srv");
    fs::create_dir_all(&srv).unwrap();
    keygen(&srv.join("host"), "throwaway-host");
    let ak = srv.join("authorized_keys");
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    fs::write(
        srv.join("sshd_config"),
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes no\nUsePAM no\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitUserRC no\nAllowUsers {}\nLogLevel ERROR\n",
            srv.join("host").display(), srv.join("pid").display(), ak.display(), me()
        ),
    )
    .unwrap();
    let _sshd = Sshd(
        Command::new("/usr/sbin/sshd").args(["-D", "-e", "-f"]).arg(srv.join("sshd_config")).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap(),
    );
    let t0 = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(t0.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(50));
    }
    let kh = srv.join("known_hosts");
    fs::write(&kh, format!("[127.0.0.1]:{port} {}", fs::read_to_string(srv.join("host.pub")).unwrap().trim())).unwrap();

    let home = d.join("home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    let key = home.join(".ssh").join(format!("test-node-sshd-{}", me()));
    keygen(&key, &format!("test-node-sshd-{}-20260101", me()));
    fs::write(&ak, fs::read_to_string(key.with_extension("pub")).unwrap_or_else(|_| fs::read_to_string(format!("{}.pub", key.display())).unwrap())).unwrap();
    fs::write(format!("{}.rotated-at", key.display()), "2026-01-01T00:00:00Z\n").unwrap();
    let cfg = d.join("connections.json");
    fs::write(&cfg, format!(
        r#"{{"connections":[{{"source":"test-node","user":"{u}","target":"sshd","target_user":"{u}","hostname":"127.0.0.1","port":{port},"authorized_keys":"{ak}"}}]}}"#,
        u = me(), ak = ak.display()
    )).unwrap();
    let common = ["--config", cfg.to_str().unwrap(), "--node", "test-node", "--known-hosts", kh.to_str().unwrap()];
    let before = fs::read_to_string(&ak).unwrap();

    let mut args = vec!["rotate"];
    args.extend(common);
    let o = cli(&home, &args);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{out}{}", String::from_utf8_lossy(&o.stderr));
    assert!(out.contains("dry run") && out.contains("[5/7] verify    plan") && out.contains("Planned"), "{out}");
    assert_eq!(fs::read_to_string(&ak).unwrap(), before);

    args.push("--apply");
    let o = cli(&home, &args);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{out}{}", String::from_utf8_lossy(&o.stderr));
    assert!(out.contains("[7/7] retire    ok") && out.contains("=> Rotated"), "{out}");
    assert_ne!(fs::read_to_string(&ak).unwrap(), before);

    let mut pargs = vec!["plan", "--json"];
    pargs.extend(common);
    let o = cli(&home, &pargs);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["connections"][0]["age_days"], 0);
    assert_eq!(v["connections"][0]["reachable"], true);
    assert_eq!(v["connections"][0]["due"], false);
}
