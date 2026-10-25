//! Compatibility with the Niyantrak control plane itself (Python). Runs only when NIYANTRAK_SRC points at a
//! niyantrak checkout and python3 is available; otherwise each test passes with a SKIP note.
//!
//!   NIYANTRAK_SRC=~/projects/niyantrak cargo test -p keys-engine --test niyantrak_compat
//!
//! * our 6W events (`niyantrak.6w/1`) pass niyantrak.telemetry.schema.validate()
//! * our `which` checks agree with the core's on the same samples (accepted and rejected alike)
//! * our canonical card bytes + ssh-keygen signature pass niyantrak.card.verify()
//! * a full join against the real join listener (pinned TLS): node recorded as pending with our card hash;
//!   a wrong pin is refused before the token is sent (the token stays usable)

use keys_engine::audit::Audit;
use keys_engine::enrol::{self, Invite, SshKeySigner};
use keys_engine::identity;
use keys_engine::layout::Layout;
use keys_engine::rotate::Rotator;
use keys_engine::transport::{FakeTransport, Transport};
use keys_engine::RotationConfig;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

fn src() -> Option<String> {
    let s = std::env::var("NIYANTRAK_SRC").ok().filter(|s| !s.is_empty());
    if s.is_none() {
        eprintln!("SKIP: set NIYANTRAK_SRC to a niyantrak checkout");
    }
    s
}

fn python(src: &str, code: &str, stdin: &str) -> (bool, String) {
    let mut c = Command::new("python3")
        .args(["-c", code])
        .env("PYTHONPATH", src)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3");
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

#[test]
fn sixw_events_pass_niyantrak_validate() {
    let Some(src) = src() else { return };
    let t = tempfile::tempdir().unwrap();
    let l = Layout::for_home(t.path());
    std::fs::create_dir_all(&l.ssh_dir).unwrap();
    let cfg = RotationConfig::from_json(r#"{"connections":[{"source":"ws-01","user":"alice","target":"edge-01","target_user":"alice"}]}"#).unwrap();
    let c = cfg.connections[0].clone();
    let mut f = FakeTransport::new();
    f.keygen(&l.key(&c), &c.comment("20260425")).unwrap();
    f.add_line("alice@edge-01", &keys_engine::layout::read_pub(&l.key(&c)).unwrap().line());
    let mut audit = Audit::memory();
    let r = Rotator { layout: &l, policy: &cfg.policy, transport: &mut f, audit: &mut audit, actor: identity::current(), now: keys_engine::timeutil::now(), apply: true, force: true, owned: cfg.connections.clone() }
        .rotate(&c, &mut |_| {});
    assert_eq!(r.steps.len(), 7);
    assert!(audit.events.iter().all(|e| e.schema == "niyantrak.6w/1" && e.which.is_none()));
    let events = serde_json::to_string(&audit.events).unwrap();
    let (ok, out) = python(&src, "import json,sys\nfrom niyantrak.telemetry.schema import validate, SCHEMA\nev=json.load(sys.stdin)\nassert all(e['schema'] == SCHEMA for e in ev), SCHEMA\nout=[validate(e) for e in ev]\nassert all(o['which'] is None for o in out)\nprint(len(ev))", &events);
    assert!(ok, "niyantrak rejected an event: {out}");
    assert_eq!(out.trim(), "7");
}

#[test]
fn which_rules_agree_with_niyantrak() {
    let Some(src) = src() else { return };
    let base = keys_engine::audit::SixW {
        schema: keys_engine::audit::SCHEMA_6W.into(),
        ts: "2026-10-25T03:30:00Z".into(),
        who: "alice".into(),
        who_id: "local:uid:1000@0123456789ab".into(),
        what: "ssh key rotation verify".into(),
        where_: "edge-01".into(),
        why: "SSH-ROT one key per connection".into(),
        which: None,
        outcome: "allowed".into(),
        agent: "niyantrak-keys".into(),
        route: "ws-01-edge-01-alice".into(),
        machine: "ws-01".into(),
        rule_ids: vec!["SSH-ROT-STEP-5".into()],
    };
    let samples = [
        "acme/payments-api", "group/sub/repo", "ws-01:~/projects/app", "edge-01:/srv/app", "payments", "/var/lib/app",
        "C:\\Users\\Public", "D:/data", "\\\\fileserver\\share", "ws-01:~/x;rm", "line\nbreak",
        "one two three four five six seven eight nine", "build 1234567890", "ws-01:~/9876-54321-0", "-flag", "a|b",
        "x`y", "$HOME/app", "ws-01:~/alice@example.com", "a/b c/d", "ws_01.lan:~/w",
    ];
    let mut long = "a".repeat(65);
    long.push('b');
    let mut cases: Vec<(String, bool)> = vec![];
    let mut events = vec![];
    for s in samples.iter().map(|s| s.to_string()).chain([long, "x".repeat(64)]) {
        let mut ev = base.clone();
        ev.which = Some(s.clone());
        cases.push((s, ev.validate().is_ok()));
        events.push(ev);
    }
    let payload = serde_json::to_string(&events).unwrap();
    let (ok, out) = python(
        &src,
        "import json,sys\nfrom niyantrak.telemetry.schema import validate, EventError\nr=[]\nfor e in json.load(sys.stdin):\n    try:\n        validate(e); r.append(True)\n    except EventError:\n        r.append(False)\nprint(json.dumps(r))",
        &payload,
    );
    assert!(ok, "{out}");
    let core: Vec<bool> = serde_json::from_str(out.trim()).unwrap();
    let disagree: Vec<_> = cases.iter().zip(&core).filter(|((_, c), k)| c != *k).map(|((s, c), k)| format!("{s:?}: client {c}, core {k}")).collect();
    assert!(disagree.is_empty(), "which verdicts differ: {disagree:?}");
    assert!(core.iter().any(|v| *v) && core.iter().any(|v| !*v));
}

#[test]
fn card_signature_verifies_with_card_py() {
    let Some(src) = src() else { return };
    let t = tempfile::tempdir().unwrap();
    let key = t.path().join("host_ed25519");
    assert!(Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "test-host", "-f"]).arg(&key).status().unwrap().success());
    let card = enrol::collect_card(Some("client"));
    let signer = SshKeySigner::new(&key);
    use keys_engine::enrol::Signer;
    let sig = signer.sign(&enrol::card_bytes(&card)).unwrap();
    let payload = serde_json::json!({"card": card, "sig": sig, "pub": signer.public_key().unwrap()}).to_string();
    let (ok, out) = python(
        &src,
        "import json,sys\nfrom niyantrak import card as c\nd=json.load(sys.stdin)\nprint(c.verify(c.card_bytes(d['card']), d['sig'], d['pub']), c.card_sha256(d['card']))",
        &payload,
    );
    assert!(ok, "{out}");
    assert_eq!(out.trim(), format!("True {}", enrol::card_sha256(&card)));
}

#[test]
fn join_against_the_real_join_listener() {
    let Some(src) = src() else { return };
    let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/niyantrak_join_server.py");
    let mut server = Command::new("python3").arg(fixture).env("PYTHONPATH", &src).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(server.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
    let info: Value = serde_json::from_str(&line).expect("server info");
    let port = info["port"].as_u64().unwrap() as u16;
    let pin = info["fingerprint"].as_str().unwrap().to_string();
    let token = info["token"].as_str().unwrap().to_string();

    let t = tempfile::tempdir().unwrap();
    let key = t.path().join("host_ed25519");
    assert!(Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "test-host", "-f"]).arg(&key).status().unwrap().success());
    let card = enrol::collect_card(Some("client"));
    let signer = SshKeySigner::new(&key);

    // wrong pin: refused during the handshake, token not spent
    let bad = Invite { url: format!("https://127.0.0.1:{port}"), host: "127.0.0.1".into(), port, token: token.clone(), pin: "0".repeat(64) };
    let e = enrol::join(&bad, &card, &signer, Duration::from_secs(10)).unwrap_err();
    assert!(e.0.contains("does not match the pinned certificate"), "{e}");

    let inv = enrol::parse_invite(&format!("sudo python3 -m niyantrak.join https://127.0.0.1:{port} {token} --pin sha256:{pin}")).unwrap();
    let rec = enrol::join(&inv, &card, &signer, Duration::from_secs(10)).expect("join accepted");
    assert_eq!(rec.state, "pending");
    assert_eq!(rec.node_id, card["node_id"].as_str().unwrap());
    let store: Value = serde_json::from_str(&std::fs::read_to_string(info["store"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(store["nodes"][&rec.node_id]["card_sha256"].as_str().unwrap(), rec.card_sha256);

    // the token is single-use
    let again = enrol::join(&inv, &card, &signer, Duration::from_secs(10)).unwrap_err();
    assert!(again.0.contains("already used"), "{again}");

    // status endpoint is not offered by this control plane yet -> Unsupported, not an error
    assert_eq!(enrol::status(&rec, Duration::from_secs(10)).unwrap(), enrol::Status::Unsupported);

    drop(server.stdin.take());
    let _ = server.wait();
}
