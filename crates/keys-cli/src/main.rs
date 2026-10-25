//! niyantrak-keys — plan and rotate per-connection SSH keys. Dry run unless --apply.
//!
//!   niyantrak-keys plan   [--no-probe] [--json]
//!   niyantrak-keys rotate [--apply] [--connection ID] [--force] [--json] [--alert-cmd PROG]
//!   niyantrak-keys card   [--role R]                          # this device's node card + sha256
//!   niyantrak-keys enrol  [--host-key PATH] [--role R] <invite> # join a Niyantrak control plane (root/Admin)
//!   niyantrak-keys status                                     # enrolment state
//!   niyantrak-keys identity
//!   niyantrak-keys version
//! Common: --config FILE (connections.json; default ~/.config/niyantrak/connections.json or $NIYANTRAK_CONNECTIONS)
//!         --home DIR (default $HOME / %USERPROFILE%) --node NAME (default this host) --known-hosts FILE
//! Exit: 0 ok · 1 error · 2 a rotation raised an alert (details on stdout, and on --alert-cmd's stdin as JSON)

use keys_engine::audit::Audit;
use keys_engine::enrol::{self, Enrolment, SshKeySigner};
use keys_engine::identity;
use keys_engine::layout::Layout;
use keys_engine::plan::{plan, PlanOptions};
use keys_engine::rotate::{Outcome, Rotator, StepResult};
use keys_engine::transport::SystemTransport;
use keys_engine::{timeutil, RotationConfig};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

const USAGE: &str = "usage: niyantrak-keys <plan|rotate|card|enrol|status|identity> [options]
  plan     [--no-probe] [--json]                       read-only: age, due, reachability, drift
  rotate   [--apply] [--connection ID] [--force] [--json] [--alert-cmd PROG]
           dry run unless --apply; rotates due connections owned by this device and user
  card     [--role R]                                  print this device's node card and its sha256
  enrol    [--host-key PATH] [--role R] <invite text>  join a control plane (needs the SSH host key: root/Administrator)
  status                                               enrolment state (asks the control plane when it can)
  identity                                             who is acting, as derived from the OS
  version                                              print the version
common: --config FILE  --home DIR  --node NAME  --known-hosts FILE";

#[derive(Default, Debug)]
struct Args {
    cmd: String,
    apply: bool,
    force: bool,
    json: bool,
    probe: bool,
    connection: Option<String>,
    config: Option<PathBuf>,
    home: Option<PathBuf>,
    node: Option<String>,
    known_hosts: Option<PathBuf>,
    alert_cmd: Option<String>,
    host_key: Option<PathBuf>,
    role: Option<String>,
    rest: Vec<String>,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let mut a = Args { probe: true, ..Default::default() };
    let mut it = argv.iter();
    a.cmd = it.next().cloned().ok_or("missing command")?;
    if !["plan", "rotate", "card", "enrol", "status", "identity", "help", "--help", "-h", "version", "--version", "-V"].contains(&a.cmd.as_str()) {
        return Err(format!("unknown command {}", a.cmd));
    }
    while let Some(x) = it.next() {
        let mut val = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        match x.as_str() {
            "--apply" => a.apply = true,
            "--force" => a.force = true,
            "--json" => a.json = true,
            "--no-probe" => a.probe = false,
            "--connection" => a.connection = Some(val(x)?),
            "--config" => a.config = Some(val(x)?.into()),
            "--home" => a.home = Some(val(x)?.into()),
            "--node" => a.node = Some(val(x)?),
            "--known-hosts" => a.known_hosts = Some(val(x)?.into()),
            "--alert-cmd" => a.alert_cmd = Some(val(x)?),
            "--host-key" => a.host_key = Some(val(x)?.into()),
            "--role" => a.role = Some(val(x)?),
            "--pin" => {
                a.rest.push("--pin".into());
                a.rest.push(val(x)?);
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            s => a.rest.push(s.to_string()),
        }
    }
    if a.apply && a.cmd != "rotate" {
        return Err("--apply only applies to rotate".into());
    }
    Ok(a)
}

fn layout(a: &Args) -> Result<Layout, String> {
    match &a.home {
        Some(h) => Ok(Layout::for_home(h)),
        None => match std::env::var_os("NIYANTRAK_HOME") {
            Some(h) if !h.is_empty() => Ok(Layout::for_home(PathBuf::from(h))),
            _ => {
                let l = Layout::current_user().ok_or_else(|| "no home directory (set HOME or --home)".to_string())?;
                for f in l.migrate_legacy() {
                    eprintln!("niyantrak-keys: migrated {f} from %APPDATA% (see migration.log)");
                }
                Ok(l)
            }
        },
    }
}

fn load_config(a: &Args, l: &Layout) -> Result<RotationConfig, String> {
    let path = a
        .config
        .clone()
        .or_else(|| std::env::var_os("NIYANTRAK_CONNECTIONS").filter(|v| !v.is_empty()).map(PathBuf::from))
        .unwrap_or_else(|| l.connections_file());
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    RotationConfig::from_json(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn transport(a: &Args) -> SystemTransport {
    SystemTransport { known_hosts: a.known_hosts.clone(), ..Default::default() }
}

fn node(a: &Args) -> String {
    a.node.clone().unwrap_or_else(identity::node_name)
}

fn chip(b: Option<bool>, yes: &str, no: &str) -> String {
    match b {
        Some(true) => yes.into(),
        Some(false) => no.into(),
        None => "-".into(),
    }
}

fn cmd_plan(a: &Args) -> Result<u8, String> {
    let l = layout(a)?;
    let cfg = load_config(a, &l)?;
    let mut t = transport(a);
    let p = plan(&cfg, &l, &mut t, &PlanOptions { node: node(a), user: identity::effective_user(), probe: a.probe, now: timeutil::now() });
    if a.json {
        println!("{}", serde_json::to_string_pretty(&p).unwrap());
        return Ok(0);
    }
    println!("niyantrak-keys plan (read-only) — node {} user {} — max age {} days", p.node, p.user, p.policy.max_age_days);
    println!("{:<44} {:>5} {:<10} {:<9} {:<10} detail", "connection", "age", "due", "reach", "comment");
    for c in &p.connections {
        if !c.owned {
            println!("{:<44} {:>5} {:<10} {:<9} {:<10} {}", c.id, "-", "-", "-", "-", c.detail.clone().unwrap_or_default());
            continue;
        }
        let due = if c.overdue { "OVERDUE" } else if c.due { "due" } else { "ok" };
        let due = match (&c.due_at, c.due) {
            (Some(d), false) => format!("{due} {}", &d[..10]),
            _ => due.to_string(),
        };
        println!(
            "{:<44} {:>5} {:<10} {:<9} {:<10} {}",
            c.id,
            c.age_days.map(|d| format!("{d}d")).unwrap_or_else(|| "?".into()),
            due,
            chip(c.reachable, "yes", "NO"),
            if c.comment_on_pattern { "pattern" } else { "OFF" },
            c.detail.clone().unwrap_or_default()
        );
    }
    if !p.drift.is_empty() {
        println!("\nauthorized_keys on targets:");
        for d in &p.drift {
            println!("  {:<18} {:<12} {:<52} {}", d.class, d.target, d.fingerprint, d.comment);
        }
    }
    let s = &p.summary;
    println!(
        "\n{} connections ({} on this device): {} due, {} overdue, {} unreachable; {} undeclared and {} off-pattern keys on targets",
        s.total, s.owned, s.due, s.overdue, s.unreachable, s.undeclared, s.off_pattern
    );
    Ok(0)
}

fn send_alert(prog: &str, alert: &serde_json::Value) {
    match Command::new(prog).stdin(Stdio::piped()).spawn() {
        Ok(mut c) => {
            if let Some(mut si) = c.stdin.take() {
                let _ = si.write_all(alert.to_string().as_bytes());
            }
            let _ = c.wait();
        }
        Err(e) => eprintln!("alert command {prog} failed: {e}"),
    }
}

fn cmd_rotate(a: &Args) -> Result<u8, String> {
    let l = layout(a)?;
    let cfg = load_config(a, &l)?;
    let (me_node, me_user) = (node(a), identity::effective_user());
    let owned: Vec<_> = cfg.connections.iter().filter(|c| c.source == me_node && c.user == me_user).cloned().collect();
    let selected: Vec<_> = match &a.connection {
        Some(id) => {
            let c = cfg.find(id).ok_or(format!("no connection {id}"))?;
            if !owned.iter().any(|o| o.id() == c.id()) {
                return Err(format!("{id} is owned by {} user {}; run it there (this is {me_node} user {me_user})", c.source, c.user));
            }
            vec![c.clone()]
        }
        None => owned.clone(),
    };
    if selected.is_empty() {
        println!("no connections owned by {me_node} user {me_user} in the connection list");
        return Ok(0);
    }
    let mut t = transport(a);
    let mut audit = Audit::files(l.audit_log(), l.sixw_log());
    audit.agent = identity::agent();
    let mut reports = vec![];
    if !a.json {
        println!("niyantrak-keys rotate — {} — {} connection(s)", if a.apply { "APPLY" } else { "dry run (add --apply to change anything)" }, selected.len());
    }
    for c in &selected {
        let json = a.json;
        if !json {
            println!("\n{}", c.id());
        }
        let r = Rotator {
            layout: &l,
            policy: &cfg.policy,
            transport: &mut t,
            audit: &mut audit,
            actor: identity::current(),
            now: timeutil::now(),
            apply: a.apply,
            force: a.force,
            owned: owned.clone(),
        }
        .rotate(c, &mut |ev| {
            if !json {
                let tag = match ev.result {
                    StepResult::Ok => "ok",
                    StepResult::Skip => "skip",
                    StepResult::Fail => "FAIL",
                    StepResult::Warn => "WARN",
                    StepResult::Planned => "plan",
                };
                println!("  [{}/7] {:<9} {:<4} {}", ev.no, ev.step, tag, ev.detail);
            }
        });
        if !json {
            println!("  => {:?}", r.outcome);
            if let Some(al) = &r.alert {
                println!("  ALERT ({}): {}", al.level, al.message);
                if let Some(rec) = &al.recovery {
                    println!("  recovery: {rec}");
                }
            }
        }
        if let (Some(prog), Some(al)) = (&a.alert_cmd, &r.alert) {
            send_alert(prog, &serde_json::json!({"event": "ssh_rotation_alert", "connection": r.connection, "outcome": r.outcome,
                                                 "level": al.level, "message": al.message, "recovery": al.recovery,
                                                 "old_fp": r.old_fp, "new_fp": r.new_fp}));
        }
        if let (Some(prog), Outcome::Rotated) = (&a.alert_cmd, r.outcome) {
            send_alert(prog, &serde_json::json!({"event": "ssh_rotated", "connection": r.connection, "target": c.target,
                                                 "old_fp": r.old_fp, "new_fp": r.new_fp}));
        }
        reports.push(r);
    }
    for e in &audit.write_errors {
        eprintln!("audit: {e}");
    }
    if a.json {
        println!("{}", serde_json::to_string_pretty(&reports).unwrap());
    } else {
        println!("\naudit: {}", l.audit_log().display());
    }
    Ok(if reports.iter().any(|r| r.alert.is_some()) { 2 } else { 0 })
}

fn cmd_card(a: &Args) -> Result<u8, String> {
    let card = enrol::collect_card(a.role.as_deref());
    println!("{}", serde_json::to_string_pretty(&card).unwrap());
    println!("card sha256: {}", enrol::card_sha256(&card));
    Ok(0)
}

fn cmd_enrol(a: &Args) -> Result<u8, String> {
    let l = layout(a)?;
    let text = if a.rest.is_empty() {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s).map_err(|e| e.to_string())?;
        s
    } else {
        a.rest.join(" ")
    };
    let invite = enrol::parse_invite(&text).map_err(|e| e.0)?;
    let card = enrol::collect_card(a.role.as_deref());
    let signer = SshKeySigner::new(a.host_key.clone().unwrap_or_else(enrol::default_host_key));
    println!("node {}  card sha256:{}", card["node_id"].as_str().unwrap_or("?"), enrol::card_sha256(&card));
    let rec = enrol::join(&invite, &card, &signer, Duration::from_secs(30)).map_err(|e| e.0)?;
    rec.save(&l.enrolment_file()).map_err(|e| e.to_string())?;
    println!(
        "{}: {}{}",
        rec.node_id,
        rec.state,
        if rec.state == "pending" { " — the operator approves it in the panel under Fleet." } else { "" }
    );
    Ok(0)
}

fn cmd_status(a: &Args) -> Result<u8, String> {
    let l = layout(a)?;
    let Some(mut rec) = Enrolment::load(&l.enrolment_file()) else {
        println!("not enrolled (no {})", l.enrolment_file().display());
        return Ok(0);
    };
    match enrol::status(&rec, Duration::from_secs(15)) {
        Ok(enrol::Status::State(s)) => {
            rec.state = s;
            rec.checked_at = Some(timeutil::iso(timeutil::now()));
            let _ = rec.save(&l.enrolment_file());
        }
        Ok(enrol::Status::Unsupported) => eprintln!("the control plane cannot report status yet; check Fleet in the panel"),
        Err(e) => eprintln!("status check failed: {e}"),
    }
    println!("{}", serde_json::to_string_pretty(&rec).unwrap());
    Ok(0)
}

fn run(argv: &[String]) -> Result<u8, String> {
    let a = parse(argv)?;
    match a.cmd.as_str() {
        "plan" => cmd_plan(&a),
        "rotate" => cmd_rotate(&a),
        "card" => cmd_card(&a),
        "enrol" => cmd_enrol(&a),
        "status" => cmd_status(&a),
        "identity" => {
            let id = identity::current();
            println!("{}", serde_json::json!({"person": id, "process_user": identity::effective_user(), "node": node(&a), "agent": identity::agent()}));
            Ok(0)
        }
        "version" | "--version" | "-V" => {
            println!("niyantrak-keys {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        _ => {
            println!("{USAGE}");
            Ok(0)
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match run(&argv) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("niyantrak-keys: {e}\n{USAGE}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Args, String> {
        parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>())
    }

    #[test]
    fn dry_run_is_the_default() {
        let a = p("rotate --connection x").unwrap();
        assert!(!a.apply && a.probe);
        assert!(p("rotate --apply").unwrap().apply);
    }

    #[test]
    fn rejects_unknown_and_misplaced_flags() {
        assert!(p("rotate --yolo").is_err());
        assert!(p("plan --apply").is_err());
        assert!(p("frobnicate").is_err());
        assert!(p("rotate --connection").is_err());
    }

    #[test]
    fn enrol_keeps_invite_words() {
        let a = p("enrol https://h:8771 tok --pin sha256:ab").unwrap();
        assert_eq!(a.rest, vec!["https://h:8771", "tok", "--pin", "sha256:ab"]);
    }
}
