//! Who is acting, derived from the operating system — never typed in, never a role label.
//! Same rules as niyantrak/identity.py:
//! * Linux: the login uid (/proc/self/loginuid survives sudo), then SUDO_UID, then the process uid; the name comes
//!   from NSS (getpwuid_r), so local, SSSD, authd and Kanidm accounts resolve the same way. The directory is "local"
//!   when the name is in /etc/passwd, else the first directory module on the passwd line of /etc/nsswitch.conf.
//!   Stable id: `<directory>:uid:<uid>[@<machine-id 12>]` (local) or `<directory>:uid:<uid>`.
//! * Windows: the account name and SID from `whoami /user`; stable id `sid:<SID>`.

use serde::Serialize;
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Identity {
    pub name: String,
    pub uid: Option<u32>,
    pub directory: String,
    pub stable_id: String,
}

pub const UNSET_LOGINUID: u32 = 4_294_967_295;
const NSS_DIRECTORIES: &[(&str, &str)] =
    &[("sss", "sssd"), ("authd", "authd"), ("kanidm", "kanidm"), ("ldap", "ldap"), ("winbind", "winbind")];

pub fn login_uid(proc_loginuid: &str, sudo_uid: Option<&str>, getuid: u32) -> u32 {
    if let Some(u) = fs::read_to_string(proc_loginuid).ok().and_then(|s| s.trim().parse::<u32>().ok()) {
        if u != UNSET_LOGINUID {
            return u;
        }
    }
    if let Some(u) = sudo_uid.and_then(|s| s.parse::<u32>().ok()) {
        return u;
    }
    getuid
}

pub fn directory_for(name: &str, passwd: &str, nsswitch: &str) -> String {
    if let Ok(p) = fs::read_to_string(passwd) {
        if p.lines().any(|l| !l.starts_with('#') && l.split(':').next() == Some(name)) {
            return "local".into();
        }
    }
    if let Ok(n) = fs::read_to_string(nsswitch) {
        for line in n.lines() {
            if let Some((key, rest)) = line.split_once(':') {
                if key.trim() == "passwd" {
                    let rest = rest.split('#').next().unwrap_or("");
                    for module in rest.split(|c: char| !(c.is_ascii_alphabetic() || c == '_')).filter(|m| !m.is_empty()) {
                        if let Some((_, d)) = NSS_DIRECTORIES.iter().find(|(m, _)| *m == module) {
                            return (*d).into();
                        }
                    }
                }
            }
        }
    }
    "unknown".into()
}

pub fn machine12(machine_id: &str) -> Option<String> {
    let m = fs::read_to_string(machine_id).ok()?.trim().to_lowercase();
    (m.len() >= 12 && m.chars().all(|c| c.is_ascii_hexdigit())).then(|| m[..12].to_string())
}

/// Pure part of the Unix derivation (paths injectable for tests).
pub fn derive_unix(uid: u32, name: Option<String>, passwd: &str, nsswitch: &str, machine_id: &str) -> Identity {
    let (name, directory) = match name {
        Some(n) => {
            let d = directory_for(&n, passwd, nsswitch);
            (n, d)
        }
        None => (format!("uid-{uid}"), "unknown".to_string()),
    };
    let stable_id = if directory == "local" || directory == "unknown" {
        match machine12(machine_id) {
            Some(m) => format!("{directory}:uid:{uid}@{m}"),
            None => format!("{directory}:uid:{uid}"),
        }
    } else {
        format!("{directory}:uid:{uid}")
    };
    Identity { name, uid: Some(uid), directory, stable_id }
}

#[cfg(unix)]
fn nss_name(uid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwuid_r writes into our buffers only; result is null or points at `pwd`.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: pw_name is a NUL-terminated string inside `buf`.
    let s = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    Some(s.to_string_lossy().into_owned())
}

#[cfg(unix)]
pub fn current() -> Identity {
    // SAFETY: getuid has no preconditions.
    let uid = login_uid("/proc/self/loginuid", std::env::var("SUDO_UID").ok().as_deref(), unsafe { libc::getuid() });
    derive_unix(uid, nss_name(uid), "/etc/passwd", "/etc/nsswitch.conf", "/etc/machine-id")
}

/// Parse `whoami /user /fo csv /nh` output: `"domain\user","S-1-5-21-..."`.
pub fn parse_whoami_csv(out: &str, computer: &str) -> Option<Identity> {
    let line = out.lines().find(|l| l.contains("S-1-"))?;
    let cols: Vec<&str> = line.split("\",\"").map(|c| c.trim().trim_matches('"')).collect();
    if cols.len() < 2 || !cols[1].starts_with("S-1-") {
        return None;
    }
    let (domain, name) = cols[0].split_once('\\').unwrap_or(("", cols[0]));
    let directory = if domain.is_empty() || domain.eq_ignore_ascii_case(computer) { "local" } else { "windows-domain" };
    Some(Identity { name: name.to_string(), uid: None, directory: directory.into(), stable_id: format!("sid:{}", cols[1]) })
}

#[cfg(windows)]
pub fn current() -> Identity {
    let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
    let out = std::process::Command::new("whoami").args(["/user", "/fo", "csv", "/nh"]).output();
    if let Ok(o) = out {
        if let Some(id) = parse_whoami_csv(&String::from_utf8_lossy(&o.stdout), &computer) {
            return id;
        }
    }
    let name = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into());
    Identity { name, uid: None, directory: "unknown".into(), stable_id: "unknown".into() }
}

/// The OS account this process runs as (whose ~/.ssh holds the keys). Differs from `current()` under sudo:
/// `current()` is the person, this is the account whose keys are rotated.
#[cfg(unix)]
pub fn effective_user() -> String {
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    nss_name(uid).unwrap_or_else(|| format!("uid-{uid}"))
}

#[cfg(windows)]
pub fn effective_user() -> String {
    std::env::var("USERNAME").unwrap_or_default()
}

/// The AI agent acting on the person's behalf, if any (same variables as niyantrak.identity.agent()).
pub fn agent() -> Option<String> {
    if let Ok(a) = std::env::var("NIYANTRAK_AGENT") {
        if !a.is_empty() {
            return Some(a);
        }
    }
    (std::env::var("CLAUDECODE").as_deref() == Ok("1")).then(|| "claude".to_string())
}

/// This machine's name (the `source` of the connections it owns).
pub fn node_name() -> String {
    if let Ok(n) = std::env::var("NIYANTRAK_NODE") {
        if !n.is_empty() {
            return n;
        }
    }
    if cfg!(windows) {
        return std::env::var("COMPUTERNAME").unwrap_or_default().to_lowercase();
    }
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::process::Command::new("hostname").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_uid_order() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("loginuid");
        fs::write(&p, "1001\n").unwrap();
        assert_eq!(login_uid(p.to_str().unwrap(), Some("1002"), 0), 1001);
        fs::write(&p, "4294967295").unwrap();
        assert_eq!(login_uid(p.to_str().unwrap(), Some("1002"), 0), 1002);
        assert_eq!(login_uid("/nonexistent", None, 7), 7);
    }

    #[test]
    fn local_and_directory_accounts() {
        let t = tempfile::tempdir().unwrap();
        let pw = t.path().join("passwd");
        let ns = t.path().join("nsswitch.conf");
        let mid = t.path().join("machine-id");
        fs::write(&pw, "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n").unwrap();
        fs::write(&ns, "# comment\npasswd:         files systemd kanidm # trailing\n").unwrap();
        fs::write(&mid, "0123456789abcdef0123456789abcdef\n").unwrap();
        let (pw, ns, mid) = (pw.to_str().unwrap(), ns.to_str().unwrap(), mid.to_str().unwrap());
        let a = derive_unix(1000, Some("alice".into()), pw, ns, mid);
        assert_eq!((a.directory.as_str(), a.stable_id.as_str()), ("local", "local:uid:1000@0123456789ab"));
        let b = derive_unix(70001, Some("carol".into()), pw, ns, mid);
        assert_eq!((b.directory.as_str(), b.stable_id.as_str()), ("kanidm", "kanidm:uid:70001"));
        let c = derive_unix(4242, None, pw, ns, "/nonexistent");
        assert_eq!((c.name.as_str(), c.stable_id.as_str()), ("uid-4242", "unknown:uid:4242"));
    }

    #[test]
    fn windows_whoami() {
        let id = parse_whoami_csv("\"laptop\\alice\",\"S-1-5-21-1-2-3-1001\"\r\n", "LAPTOP").unwrap();
        assert_eq!((id.name.as_str(), id.directory.as_str(), id.stable_id.as_str()), ("alice", "local", "sid:S-1-5-21-1-2-3-1001"));
        let ad = parse_whoami_csv("\"corp\\carol\",\"S-1-5-21-9-9-9-1105\"", "LAPTOP").unwrap();
        assert_eq!(ad.directory, "windows-domain");
        assert!(parse_whoami_csv("garbage", "x").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn current_is_derived_not_typed() {
        let id = current();
        assert!(!id.name.is_empty() && id.uid.is_some());
        assert!(id.stable_id.contains(":uid:"));
    }
}
