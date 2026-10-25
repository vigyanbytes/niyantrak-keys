//! How the engine touches the world: one trait, two implementations.
//!
//! * `SystemTransport` runs the system `ssh` / `ssh-keygen` (OpenSSH on Linux and Windows). Every ssh call is
//!   strict: `-F <null> -i <key> -o IdentitiesOnly=yes -o BatchMode=yes`, so the user's ssh config and other keys
//!   can never make a check pass. Only public key lines travel to the target (on stdin, never on the command line).
//! * `FakeTransport` keeps "remote" authorized_keys in memory and fails on demand; the unit tests drive every
//!   step and failure branch through it.

use crate::layout::pub_of;
use crate::model::{Connection, TargetOs};
use crate::pubkey::PubKey;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError(pub String);

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for TransportError {}

pub type TResult<T> = Result<T, TransportError>;

/// Where a connection's target answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub os: TargetOs,
    pub authorized_keys: String,
    pub options: Vec<String>,
}

impl Endpoint {
    pub fn label(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
    }
}

pub trait Transport {
    /// Address for a connection (declared hostname/port, else `ssh -G <target>`).
    fn resolve(&mut self, c: &Connection) -> TResult<Endpoint>;
    /// Log in with ONLY this private key and run a no-op.
    fn login(&mut self, ep: &Endpoint, key: &Path) -> TResult<()>;
    /// Create an ed25519 key pair at `path` / `path.pub` with this comment and no passphrase.
    fn keygen(&mut self, path: &Path, comment: &str) -> TResult<()>;
    /// Append a public key line to the target's authorized_keys (idempotent), logging in with `via`.
    fn install(&mut self, ep: &Endpoint, via: &Path, pub_line: &str) -> TResult<()>;
    /// Remove every authorized_keys line carrying this key blob, logging in with `via`.
    fn remove(&mut self, ep: &Endpoint, via: &Path, blob: &str) -> TResult<()>;
    /// The target's authorized_keys lines (public data), logging in with `via`.
    fn authorized_keys(&mut self, ep: &Endpoint, via: &Path) -> TResult<Vec<String>>;
}

// ── system ssh ───────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SystemTransport {
    pub ssh: OsString,
    pub ssh_keygen: OsString,
    /// known_hosts file to trust (default: ssh's own default for this user)
    pub known_hosts: Option<PathBuf>,
    pub connect_timeout: u32,
}

impl Default for SystemTransport {
    fn default() -> Self {
        SystemTransport { ssh: "ssh".into(), ssh_keygen: "ssh-keygen".into(), known_hosts: None, connect_timeout: 10 }
    }
}

/// The null device ssh reads as an empty config (`-F`).
pub const NULL_CONFIG: &str = if cfg!(windows) { "NUL" } else { "/dev/null" };

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Shell expression for a remote Linux path (`~/x` -> `"$HOME"/'x'`).
pub fn sh_path(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => format!("\"$HOME\"/{}", sh_quote(rest)),
        None => sh_quote(p),
    }
}

/// PowerShell expression for a remote Windows path (`$env:ProgramData\ssh\x` -> `(Join-Path $env:ProgramData 'ssh\x')`).
pub fn ps_path(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("$env:") {
        if let Some((var, tail)) = rest.split_once('\\') {
            if var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return format!("(Join-Path $env:{var} {})", ps_quote(tail));
            }
        }
    }
    ps_quote(p)
}

/// Remote scripts. The key line / blob is read from stdin, so no key text is ever part of a command line.
pub fn remote_script(os: TargetOs, op: &str, path: &str) -> String {
    match os {
        TargetOs::Linux => {
            let f = sh_path(path);
            let body = match op {
                "install" => format!(
                    "umask 077; f={f}; mkdir -p \"$(dirname \"$f\")\"; IFS= read -r l; [ -n \"$l\" ] || exit 3; touch \"$f\"; \
                     if [ -s \"$f\" ] && [ -n \"$(tail -c1 \"$f\")\" ]; then printf '\\n' >> \"$f\"; fi; \
                     grep -qxF -- \"$l\" \"$f\" || printf '%s\\n' \"$l\" >> \"$f\""
                ),
                "remove" => format!(
                    "umask 077; f={f}; IFS= read -r k; [ -n \"$k\" ] || exit 3; [ -f \"$f\" ] || exit 0; t=\"$f.nyk-tmp.$$\"; \
                     awk -v k=\"$k\" '{{for(i=1;i<=NF;i++) if($i==k) next; print}}' \"$f\" > \"$t\" && cat \"$t\" > \"$f\"; r=$?; rm -f \"$t\"; exit $r"
                ),
                "read" => format!("f={f}; [ -f \"$f\" ] && cat \"$f\"; exit 0"),
                _ => "true".into(),
            };
            format!("sh -c {}", sh_quote(&body))
        }
        TargetOs::Windows => {
            let f = ps_path(path);
            let admin = path.contains("administrators_authorized_keys");
            let acl = if admin {
                "icacls $f /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null; "
            } else {
                ""
            };
            let body = match op {
                "install" => format!(
                    "$l=[Console]::In.ReadLine(); if(-not $l){{exit 3}}; $f={f}; \
                     if(-not (Test-Path -LiteralPath $f)){{New-Item -ItemType File -Force -Path $f | Out-Null; {acl}}}; \
                     $c=@(Get-Content -LiteralPath $f); if($c -notcontains $l){{Add-Content -LiteralPath $f -Value $l -Encoding ascii}}"
                ),
                "remove" => format!(
                    "$k=[Console]::In.ReadLine(); if(-not $k){{exit 3}}; $f={f}; if(Test-Path -LiteralPath $f){{ \
                     $c=@(Get-Content -LiteralPath $f | Where-Object {{ -not (($_ -split '\\s+') -contains $k) }}); \
                     Set-Content -LiteralPath $f -Value $c -Encoding ascii }}"
                ),
                "read" => format!("$f={f}; if(Test-Path -LiteralPath $f){{Get-Content -LiteralPath $f}}"),
                _ => "exit 0".into(),
            };
            format!("powershell -NoProfile -NonInteractive -Command \"{body}\"")
        }
    }
}

fn tail(s: &[u8]) -> String {
    let s = String::from_utf8_lossy(s);
    let s = s.trim();
    let start = s.char_indices().rev().nth(299).map(|(i, _)| i).unwrap_or(0);
    s[start..].replace('\n', " | ")
}

impl SystemTransport {
    pub fn ssh_args(&self, ep: &Endpoint, key: &Path) -> Vec<OsString> {
        let mut a: Vec<OsString> = vec!["-F".into(), NULL_CONFIG.into(), "-i".into(), key.as_os_str().to_owned()];
        let mut o = |v: String| {
            a.push("-o".into());
            a.push(v.into());
        };
        o("IdentitiesOnly=yes".into());
        o("BatchMode=yes".into());
        o("PasswordAuthentication=no".into());
        o("KbdInteractiveAuthentication=no".into());
        o(format!("ConnectTimeout={}", self.connect_timeout));
        o("StrictHostKeyChecking=yes".into());
        o("LogLevel=ERROR".into());
        if let Some(k) = &self.known_hosts {
            o(format!("UserKnownHostsFile={}", k.display()));
            o(format!("GlobalKnownHostsFile={NULL_CONFIG}"));
        }
        for opt in &ep.options {
            o(opt.clone());
        }
        a.extend(["-T".into(), "-p".into(), ep.port.to_string().into(), "-l".into(), ep.user.clone().into()]);
        a.push(ep.host.clone().into());
        a
    }

    fn run_ssh(&self, ep: &Endpoint, key: &Path, remote: &str, stdin: Option<&str>) -> TResult<Vec<u8>> {
        let mut cmd = Command::new(&self.ssh);
        cmd.args(self.ssh_args(ep, key)).arg(remote);
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| TransportError(format!("cannot start ssh: {e}")))?;
        if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
            let _ = si.write_all(data.as_bytes());
            let _ = si.write_all(b"\n");
        }
        let out = child.wait_with_output().map_err(|e| TransportError(format!("ssh failed: {e}")))?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(TransportError(format!(
                "ssh {} exited {}: {}",
                ep.label(),
                out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "by signal".into()),
                tail(&out.stderr)
            )))
        }
    }
}

impl Transport for SystemTransport {
    fn resolve(&mut self, c: &Connection) -> TResult<Endpoint> {
        let (mut host, mut port) = (c.hostname.clone(), c.port);
        if host.is_none() || port.is_none() {
            // read-only: prints the effective config for the alias, connects nowhere
            let out = Command::new(&self.ssh)
                .args(["-G", "-l", &c.target_user, &c.target])
                .stdin(Stdio::null())
                .output()
                .map_err(|e| TransportError(format!("cannot run ssh -G: {e}")))?;
            if !out.status.success() {
                return Err(TransportError(format!("ssh -G {} failed: {}", c.target, tail(&out.stderr))));
            }
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                match line.split_once(' ') {
                    Some(("hostname", v)) if host.is_none() => host = Some(v.trim().to_string()),
                    Some(("port", v)) if port.is_none() => port = v.trim().parse().ok(),
                    _ => {}
                }
            }
        }
        Ok(Endpoint {
            host: host.unwrap_or_else(|| c.target.clone()),
            port: port.unwrap_or(22),
            user: c.target_user.clone(),
            os: c.target_os,
            authorized_keys: c.authorized_keys_path(),
            options: c.ssh_options.clone(),
        })
    }

    fn login(&mut self, ep: &Endpoint, key: &Path) -> TResult<()> {
        let noop = if ep.os == TargetOs::Windows { "exit 0" } else { "true" };
        self.run_ssh(ep, key, noop, None).map(|_| ())
    }

    fn keygen(&mut self, path: &Path, comment: &str) -> TResult<()> {
        let out = Command::new(&self.ssh_keygen)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
            .arg(path)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| TransportError(format!("cannot run ssh-keygen: {e}")))?;
        if out.status.success() && path.is_file() && pub_of(path).is_file() {
            Ok(())
        } else {
            Err(TransportError(format!("ssh-keygen failed: {}", tail(&out.stderr))))
        }
    }

    fn install(&mut self, ep: &Endpoint, via: &Path, pub_line: &str) -> TResult<()> {
        self.run_ssh(ep, via, &remote_script(ep.os, "install", &ep.authorized_keys), Some(pub_line)).map(|_| ())
    }

    fn remove(&mut self, ep: &Endpoint, via: &Path, blob: &str) -> TResult<()> {
        self.run_ssh(ep, via, &remote_script(ep.os, "remove", &ep.authorized_keys), Some(blob)).map(|_| ())
    }

    fn authorized_keys(&mut self, ep: &Endpoint, via: &Path) -> TResult<Vec<String>> {
        let out = self.run_ssh(ep, via, &remote_script(ep.os, "read", &ep.authorized_keys), None)?;
        Ok(String::from_utf8_lossy(&out).lines().map(|l| l.trim_end_matches('\r').to_string()).collect())
    }
}

// ── fake (tests, demos) ──────────────────────────────────────────────────────────────────────────────────────

/// In-memory targets. A login succeeds when the target is reachable and the key's `.pub` blob is in that
/// target's authorized_keys. `fail_nth("login", 3)` makes the third login fail, and so on.
#[derive(Debug, Default)]
pub struct FakeTransport {
    pub remote: BTreeMap<String, Vec<String>>,
    pub unreachable: Vec<String>,
    pub fail: BTreeMap<String, Vec<usize>>,
    pub calls: Vec<String>,
    counts: BTreeMap<String, usize>,
    generated: usize,
}

impl FakeTransport {
    pub fn new() -> Self {
        Self::default()
    }
    fn key_of(ep: &Endpoint) -> String {
        format!("{}@{}", ep.user, ep.host)
    }
    pub fn lines(&self, user_at_host: &str) -> Vec<String> {
        self.remote.get(user_at_host).cloned().unwrap_or_default()
    }
    pub fn add_line(&mut self, user_at_host: &str, line: &str) {
        self.remote.entry(user_at_host.into()).or_default().push(line.into());
    }
    /// Forget recorded calls and call counts (after test setup).
    pub fn reset(&mut self) {
        self.calls.clear();
        self.counts.clear();
    }
    pub fn fail_nth(&mut self, op: &str, nth: usize) {
        self.fail.entry(op.into()).or_default().push(nth);
    }
    fn tick(&mut self, op: &str, detail: String) -> TResult<()> {
        let n = self.counts.entry(op.into()).or_insert(0);
        *n += 1;
        let nth = *n;
        self.calls.push(format!("{op} {detail}"));
        if self.fail.get(op).is_some_and(|v| v.contains(&nth)) {
            return Err(TransportError(format!("injected failure: {op} #{nth}")));
        }
        Ok(())
    }
    fn reach(&self, ep: &Endpoint) -> TResult<()> {
        if self.unreachable.contains(&ep.host) {
            Err(TransportError(format!("ssh: connect to host {} port {}: No route to host", ep.host, ep.port)))
        } else {
            Ok(())
        }
    }
    fn can_login(&self, ep: &Endpoint, key: &Path) -> TResult<()> {
        self.reach(ep)?;
        let blob = fs::read_to_string(pub_of(key))
            .ok()
            .and_then(|s| PubKey::parse(&s))
            .map(|k| k.blob)
            .ok_or_else(|| TransportError(format!("no public key next to {}", key.display())))?;
        let ok = self
            .lines(&Self::key_of(ep))
            .iter()
            .any(|l| PubKey::parse(l).is_some_and(|k| k.blob == blob));
        if ok {
            Ok(())
        } else {
            Err(TransportError(format!("{}: Permission denied (publickey)", Self::key_of(ep))))
        }
    }
}

impl Transport for FakeTransport {
    fn resolve(&mut self, c: &Connection) -> TResult<Endpoint> {
        self.tick("resolve", c.target.clone())?;
        Ok(Endpoint {
            host: c.hostname.clone().unwrap_or_else(|| c.target.clone()),
            port: c.port.unwrap_or(22),
            user: c.target_user.clone(),
            os: c.target_os,
            authorized_keys: c.authorized_keys_path(),
            options: c.ssh_options.clone(),
        })
    }
    fn login(&mut self, ep: &Endpoint, key: &Path) -> TResult<()> {
        self.tick("login", format!("{} {}", Self::key_of(ep), key.display()))?;
        self.can_login(ep, key)
    }
    fn keygen(&mut self, path: &Path, comment: &str) -> TResult<()> {
        self.tick("keygen", path.display().to_string())?;
        use base64::Engine;
        self.generated += 1;
        let raw = format!("fake-ed25519-public-key-{:08}-{}", self.generated, path.display());
        let blob = base64::engine::general_purpose::STANDARD.encode(raw);
        fs::write(path, "FAKE PRIVATE KEY (test fixture, not a key)\n").map_err(|e| TransportError(e.to_string()))?;
        fs::write(pub_of(path), format!("ssh-ed25519 {blob} {comment}\n")).map_err(|e| TransportError(e.to_string()))
    }
    fn install(&mut self, ep: &Endpoint, via: &Path, pub_line: &str) -> TResult<()> {
        self.tick("install", Self::key_of(ep))?;
        self.can_login(ep, via)?;
        let lines = self.remote.entry(Self::key_of(ep)).or_default();
        if !lines.iter().any(|l| l == pub_line) {
            lines.push(pub_line.to_string());
        }
        Ok(())
    }
    fn remove(&mut self, ep: &Endpoint, via: &Path, blob: &str) -> TResult<()> {
        self.tick("remove", Self::key_of(ep))?;
        self.can_login(ep, via)?;
        let lines = self.remote.entry(Self::key_of(ep)).or_default();
        lines.retain(|l| !l.split_whitespace().any(|t| t == blob));
        Ok(())
    }
    fn authorized_keys(&mut self, ep: &Endpoint, via: &Path) -> TResult<Vec<String>> {
        self.tick("read", Self::key_of(ep))?;
        self.can_login(ep, via)?;
        Ok(self.lines(&Self::key_of(ep)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(os: TargetOs, ak: &str) -> Endpoint {
        Endpoint { host: "h".into(), port: 2222, user: "u".into(), os, authorized_keys: ak.into(), options: vec!["ProxyJump=b".into()] }
    }

    #[test]
    fn ssh_args_are_strict_and_ignore_user_config() {
        let t = SystemTransport { known_hosts: Some("/tmp/kh".into()), ..Default::default() };
        let a: Vec<String> = t.ssh_args(&ep(TargetOs::Linux, "~/.ssh/authorized_keys"), Path::new("/k/key.new"))
            .into_iter().map(|s| s.to_string_lossy().into_owned()).collect();
        let j = a.join(" ");
        assert!(j.starts_with(&format!("-F {NULL_CONFIG} -i /k/key.new -o IdentitiesOnly=yes -o BatchMode=yes")), "{j}");
        assert!(j.contains("StrictHostKeyChecking=yes") && j.contains("UserKnownHostsFile=/tmp/kh"));
        assert!(j.contains("-o ProxyJump=b") && j.ends_with("-T -p 2222 -l u h"), "{j}");
    }

    #[test]
    fn remote_paths_are_quoted() {
        assert_eq!(sh_path("~/.ssh/authorized_keys"), "\"$HOME\"/'.ssh/authorized_keys'");
        assert_eq!(sh_path("/tmp/a b/it's"), "'/tmp/a b/it'\\''s'");
        assert_eq!(ps_path("$env:ProgramData\\ssh\\administrators_authorized_keys"),
                   "(Join-Path $env:ProgramData 'ssh\\administrators_authorized_keys')");
        assert_eq!(ps_path("C:\\x\\o'k"), "'C:\\x\\o''k'");
    }

    #[test]
    fn scripts_never_carry_key_text() {
        for op in ["install", "remove", "read"] {
            let s = remote_script(TargetOs::Linux, op, "~/.ssh/authorized_keys");
            assert!(s.starts_with("sh -c '") && !s.contains("ssh-ed25519"), "{s}");
            let w = remote_script(TargetOs::Windows, op, "$env:ProgramData\\ssh\\administrators_authorized_keys");
            assert!(w.starts_with("powershell -NoProfile") && !w[w.find('"').unwrap() + 1..w.len() - 1].contains('"'), "{w}");
        }
        assert!(remote_script(TargetOs::Windows, "install", "$env:ProgramData\\ssh\\administrators_authorized_keys").contains("icacls"));
        assert!(!remote_script(TargetOs::Windows, "install", "$env:USERPROFILE\\.ssh\\authorized_keys").contains("icacls"));
    }

    #[cfg(unix)] // needs a POSIX sh; the Linux scripts only ever run on Linux targets
    #[test]
    fn linux_scripts_work_against_a_local_file() {
        // run the generated install/remove/read scripts with the local sh against a temp file
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("sub").join("authorized_keys");
        let p = f.to_string_lossy().to_string();
        let run = |op: &str, input: &str| {
            let script = remote_script(TargetOs::Linux, op, &p);
            let mut c = Command::new("sh").arg("-c").arg(&script).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
            c.stdin.take().unwrap().write_all(format!("{input}\n").as_bytes()).unwrap();
            let o = c.wait_with_output().unwrap();
            assert!(o.status.success(), "{op}");
            String::from_utf8(o.stdout).unwrap()
        };
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(&f, "ssh-ed25519 AAAAold one").unwrap(); // no trailing newline
        run("install", "ssh-ed25519 AAAAnew two");
        run("install", "ssh-ed25519 AAAAnew two"); // idempotent
        assert_eq!(fs::read_to_string(&f).unwrap(), "ssh-ed25519 AAAAold one\nssh-ed25519 AAAAnew two\n");
        run("remove", "AAAAold");
        assert_eq!(run("read", ""), "ssh-ed25519 AAAAnew two\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let g = t.path().join("fresh").join("ak");
            let script = remote_script(TargetOs::Linux, "install", &g.to_string_lossy());
            let mut c = Command::new("sh").arg("-c").arg(&script).stdin(Stdio::piped()).spawn().unwrap();
            c.stdin.take().unwrap().write_all(b"ssh-ed25519 AAAAx\n").unwrap();
            assert!(c.wait().unwrap().success());
            assert_eq!(fs::metadata(&g).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn fake_logins_follow_authorized_keys() {
        let t = tempfile::tempdir().unwrap();
        let k = t.path().join("k");
        let mut f = FakeTransport::new();
        f.keygen(&k, "c").unwrap();
        let line = fs::read_to_string(pub_of(&k)).unwrap();
        let e = ep(TargetOs::Linux, "~/.ssh/authorized_keys");
        assert!(f.login(&e, &k).is_err());
        f.add_line("u@h", line.trim());
        assert!(f.login(&e, &k).is_ok());
        f.unreachable.push("h".into());
        assert!(f.login(&e, &k).unwrap_err().0.contains("No route"));
        f.unreachable.clear();
        f.fail_nth("login", 4);
        assert!(f.login(&e, &k).unwrap_err().0.contains("injected"));
    }
}
