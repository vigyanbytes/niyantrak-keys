//! Enrolment: join this device to a Niyantrak control plane with the existing join flow (niyantrak/join.py).
//!
//! 1. The operator issues a single-use token in the panel; the invite carries the join URL, the token and the
//!    join listener's certificate pin (`sha256:<64 hex>`).
//! 2. This device collects its node card (same fields as niyantrak/card.py and windows/join.ps1), signs the
//!    canonical card bytes with its SSH host key (`ssh-keygen -Y sign -n niyantrak-node-card`) and POSTs
//!    `{token, card, signature, host_pubkey}` to `/api/join` over TLS pinned by fingerprint: the certificate is
//!    checked during the handshake, before the token leaves this device.
//! 3. The node is recorded as `pending` until the operator approves it in the panel (Fleet).
//!
//! The token is never written to disk; the local record keeps the URL, pin, node id and card hash only.

use crate::canon;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

pub const NAMESPACE: &str = "niyantrak-node-card";
pub const CARD_VERSION: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolError(pub String);
impl std::fmt::Display for EnrolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for EnrolError {}
type R<T> = Result<T, EnrolError>;
fn err<T>(s: impl Into<String>) -> R<T> {
    Err(EnrolError(s.into()))
}

// ── invite ───────────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub token: String,
    pub pin: String,
}

/// `sha256:<hex>`, plain hex or colon-separated hex -> 64 lower-case hex characters (as tls.normalise_pin).
pub fn normalise_pin(pin: &str) -> R<String> {
    let p = pin.trim().to_lowercase();
    let p = p.strip_prefix("sha256:").unwrap_or(&p);
    let h: String = p.chars().filter(|c| *c != ':' && !c.is_whitespace()).collect();
    if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(h)
    } else {
        err("certificate pin must be a SHA-256 fingerprint (64 hex characters)")
    }
}

fn split_url(url: &str) -> R<(String, u16)> {
    let rest = url.strip_prefix("https://").ok_or_else(|| EnrolError("the join address must be https:// (pinned)".into()))?;
    let hostport = rest.split('/').next().unwrap_or("");
    let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
        let (h, tail) = h.split_once(']').ok_or_else(|| EnrolError("bad IPv6 address".into()))?;
        (h.to_string(), tail.strip_prefix(':').map(|p| p.parse::<u16>()).transpose().map_err(|_| EnrolError("bad port".into()))?)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p.parse::<u16>().map_err(|_| EnrolError("bad port".into()))?)),
            None => (hostport.to_string(), None),
        }
    };
    if host.is_empty() {
        return err("the join address has no host");
    }
    Ok((host, port.unwrap_or(443)))
}

fn valid_token(t: &str) -> bool {
    (16..=200).contains(&t.len()) && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Accepts the panel one-liner (`sudo python3 -m niyantrak.join https://host:8771 <token> --pin sha256:<hex>`),
/// a `niyantrak://join?url=..&token=..&pin=..` link (what a QR code carries) or the three values on their own.
pub fn parse_invite(text: &str) -> R<Invite> {
    let text = text.trim();
    let (mut url, mut token, mut pin) = (None::<String>, None::<String>, None::<String>);
    if let Some(q) = text.strip_prefix("niyantrak://join?") {
        for kv in q.split('&') {
            if let Some((k, v)) = kv.split_once('=') {
                let v = percent_decode(v);
                match k {
                    "url" => url = Some(v),
                    "token" => token = Some(v),
                    "pin" => pin = Some(v),
                    _ => {}
                }
            }
        }
    } else {
        let toks: Vec<&str> = text.split_whitespace().collect();
        let mut i = 0;
        while i < toks.len() {
            let t = toks[i].trim_matches(|c| c == '"' || c == '\'');
            if t == "--pin" {
                pin = toks.get(i + 1).map(|s| s.trim_matches(|c| c == '"' || c == '\'').to_string());
                i += 2;
                continue;
            }
            if let Some(p) = t.strip_prefix("--pin=") {
                pin = Some(p.to_string());
            } else if t.starts_with("https://") {
                url = Some(t.to_string());
            } else if url.is_some() && token.is_none() && valid_token(t) {
                token = Some(t.to_string());
            } else if t.starts_with("sha256:") && pin.is_none() {
                pin = Some(t.to_string());
            }
            i += 1;
        }
    }
    let url = url.ok_or_else(|| EnrolError("no https:// join address found in the invite".into()))?;
    let token = token.ok_or_else(|| EnrolError("no join token found in the invite".into()))?;
    if !valid_token(&token) {
        return err("the join token has unexpected characters");
    }
    let pin = normalise_pin(&pin.ok_or_else(|| EnrolError("no --pin sha256:<fingerprint> found in the invite".into()))?)?;
    let (host, port) = split_url(&url)?;
    Ok(Invite { url: format!("https://{}:{port}", if host.contains(':') { format!("[{host}]") } else { host.clone() }), host, port, token, pin })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── node card ────────────────────────────────────────────────────────────────────────────────────────────────

pub fn node_id_from(raw: &str, verbatim: bool) -> String {
    let s = if verbatim { raw.to_string() } else { raw.trim().to_lowercase() };
    format!("nyk-{}", &canon::sha256_hex(s.as_bytes())[..12])
}

pub fn card_bytes(card: &Value) -> Vec<u8> {
    canon::to_bytes(card)
}

pub fn card_sha256(card: &Value) -> String {
    canon::sha256_hex(&card_bytes(card))
}

const SKIP_IFACES: [&str; 10] = ["lo", "docker", "br-", "veth", "virbr", "vnet", "cni", "flannel", "kube", "tap"];

/// Parse `ip -o addr show` like card._addresses(): physical/LAN/VPN only; link-local IPv6 keeps %iface.
pub fn parse_ip_addr(out: &str) -> (Vec<String>, Vec<String>) {
    let (mut v4, mut v6) = (std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
    for line in out.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let iface = parts[1].trim_end_matches(':').split('@').next().unwrap_or("");
        if SKIP_IFACES.iter().any(|p| iface.starts_with(p)) {
            continue;
        }
        if let Some(i) = parts.iter().position(|p| *p == "inet") {
            if let Some(a) = parts.get(i + 1).and_then(|a| a.split('/').next()) {
                if !a.starts_with("127.") {
                    v4.insert(a.to_string());
                }
            }
        }
        if let Some(i) = parts.iter().position(|p| *p == "inet6") {
            if parts.contains(&"temporary") {
                continue;
            }
            if let Some(a) = parts.get(i + 1).and_then(|a| a.split('/').next()) {
                if a != "::1" {
                    v6.insert(if a.starts_with("fe80") { format!("{a}%{iface}") } else { a.to_string() });
                }
            }
        }
    }
    (v4.into_iter().collect(), v6.into_iter().collect())
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn gpus() -> Vec<Value> {
    run("nvidia-smi", &["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
        .map(|s| {
            s.lines()
                .filter_map(|l| l.split_once(','))
                .filter_map(|(n, m)| m.trim().parse::<i64>().ok().map(|m| json!({"name": n.trim(), "vram_mb": m})))
                .collect()
        })
        .unwrap_or_default()
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// This machine's node card (facts only, no secrets).
#[cfg(not(windows))]
pub fn collect_card(role: Option<&str>) -> Value {
    let read = |p: &str| fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let node_id = match read("/sys/class/dmi/id/product_uuid").or_else(|| read("/etc/machine-id")) {
        Some(raw) => node_id_from(&raw, false),
        None => node_id_from(&hostname(), true),
    };
    let mem_kb: f64 = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("MemTotal")).and_then(|l| l.split_whitespace().nth(1)?.parse().ok()))
        .unwrap_or(0.0);
    let osr: std::collections::BTreeMap<String, String> = fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches('"').to_string()))
        .collect();
    let (v4, v6) = parse_ip_addr(&run("ip", &["-o", "addr", "show"]).unwrap_or_default());
    let role: Value = match role.map(str::to_string).or_else(|| read("/etc/niyantrak/role")) {
        Some(r) => Value::String(r),
        None => Value::Null,
    };
    json!({
        "card_version": CARD_VERSION, "node_id": node_id, "hostname": hostname(), "role": role,
        "os": {"id": osr.get("ID").cloned().unwrap_or_else(|| "Linux".into()), "version": osr.get("VERSION_ID").cloned().unwrap_or_default(),
               "kernel": read("/proc/sys/kernel/osrelease").unwrap_or_default(), "arch": std::env::consts::ARCH},
        "cpu": {"cores": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)},
        "memory_gb": round1(mem_kb / 1_048_576.0), "gpu": gpus(),
        "addresses": {"ipv4": v4, "ipv6": v6}
    })
}

/// Windows: the same facts windows/join.ps1 puts on the card, gathered with one PowerShell call.
#[cfg(windows)]
pub fn collect_card(role: Option<&str>) -> Value {
    const PS: &str = "$ErrorActionPreference='SilentlyContinue';$os=Get-CimInstance Win32_OperatingSystem;$cs=Get-CimInstance Win32_ComputerSystem;\
$u=[string](Get-CimInstance Win32_ComputerSystemProduct).UUID;$g=[string](Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid).MachineGuid;\
$ubr=[string](Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' -Name UBR).UBR;\
$a=@(Get-NetIPAddress | Where-Object { [string]$_.InterfaceAlias -notmatch 'vEthernet|Loopback|VirtualBox|VMware|Hyper-V' } | ForEach-Object { @{ip=[string]$_.IPAddress;fam=[string]$_.AddressFamily;idx=[int]$_.InterfaceIndex} });\
@{uuid=$u;guid=$g;host=[Net.Dns]::GetHostName();ptype=[int]$os.ProductType;ver=[string]$os.Version;ubr=$ubr;mem=[double]$cs.TotalPhysicalMemory;addr=$a} | ConvertTo-Json -Depth 4 -Compress";
    let out = run("powershell", &["-NoProfile", "-NonInteractive", "-Command", PS]).unwrap_or_default();
    let f: Value = serde_json::from_str(out.trim()).unwrap_or(json!({}));
    let s = |k: &str| f.get(k).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let host = if s("host").is_empty() { hostname() } else { s("host") };
    let node_id = if !s("uuid").is_empty() {
        node_id_from(&s("uuid"), false)
    } else if !s("guid").is_empty() {
        node_id_from(&s("guid"), false)
    } else {
        node_id_from(&host, true)
    };
    let (mut v4, mut v6) = (vec![], vec![]);
    for a in f.get("addr").and_then(|a| a.as_array()).cloned().unwrap_or_default() {
        let ip = a.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if a.get("fam").and_then(|v| v.as_str()) == Some("IPv4") {
            if !ip.starts_with("127.") && !v4.contains(&ip) {
                v4.push(ip);
            }
        } else if ip != "::1" {
            let ip = if ip.starts_with("fe80") && !ip.contains('%') { format!("{ip}%{}", a.get("idx").and_then(|v| v.as_i64()).unwrap_or(0)) } else { ip };
            if !v6.contains(&ip) {
                v6.push(ip);
            }
        }
    }
    v4.sort();
    v6.sort();
    let ver = s("ver");
    let kernel = if s("ubr").is_empty() { ver.clone() } else { format!("{ver}.{}", s("ubr")) };
    let arch = std::env::var("PROCESSOR_ARCHITEW6432").or_else(|_| std::env::var("PROCESSOR_ARCHITECTURE")).unwrap_or_default();
    let ptype = f.get("ptype").and_then(|v| v.as_i64()).unwrap_or(1);
    let mem = f.get("mem").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let role_file = std::env::var("ProgramData").map(|p| PathBuf::from(p).join("niyantrak").join("role")).ok();
    let role: Value = role
        .map(str::to_string)
        .or_else(|| role_file.and_then(|p| fs::read_to_string(p).ok()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
        .map(Value::String)
        .unwrap_or(Value::Null);
    json!({
        "card_version": CARD_VERSION, "node_id": node_id, "hostname": host, "role": role,
        "os": {"id": if ptype == 1 { "windows" } else { "windows-server" }, "version": ver, "kernel": kernel, "arch": arch},
        "cpu": {"cores": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)},
        "memory_gb": round1(mem / 1_073_741_824.0), "gpu": gpus(),
        "addresses": {"ipv4": v4, "ipv6": v6}
    })
}

pub fn hostname() -> String {
    if cfg!(windows) {
        return std::env::var("COMPUTERNAME").unwrap_or_default();
    }
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| run("hostname", &[]).map(|s| s.trim().to_string()))
        .unwrap_or_default()
}

/// The SSH host key that signs the card (root/Administrator only).
pub fn default_host_key() -> PathBuf {
    if cfg!(windows) {
        let pd = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        PathBuf::from(pd).join("ssh").join("ssh_host_ed25519_key")
    } else {
        PathBuf::from("/etc/ssh/ssh_host_ed25519_key")
    }
}

pub trait Signer {
    fn public_key(&self) -> R<String>;
    fn sign(&self, data: &[u8]) -> R<String>;
}

/// Signs with `ssh-keygen -Y sign` and an SSH private key file (the host key in production).
pub struct SshKeySigner {
    pub key: PathBuf,
    pub ssh_keygen: String,
}

impl SshKeySigner {
    pub fn new(key: impl Into<PathBuf>) -> Self {
        SshKeySigner { key: key.into(), ssh_keygen: "ssh-keygen".into() }
    }
}

impl Signer for SshKeySigner {
    fn public_key(&self) -> R<String> {
        let p = crate::layout::pub_of(&self.key);
        fs::read_to_string(&p).map(|s| s.trim().to_string()).map_err(|e| EnrolError(format!("{}: {e}", p.display())))
    }
    fn sign(&self, data: &[u8]) -> R<String> {
        let dir = std::env::temp_dir().join(format!("niyantrak-card-{}-{}", std::process::id(), crate::timeutil::now()));
        fs::create_dir_all(&dir).map_err(|e| EnrolError(e.to_string()))?;
        let f = dir.join("card.json");
        let res = (|| {
            fs::write(&f, data).map_err(|e| EnrolError(e.to_string()))?;
            let o = Command::new(&self.ssh_keygen)
                .args(["-q", "-Y", "sign", "-f"])
                .arg(&self.key)
                .args(["-n", NAMESPACE])
                .arg(&f)
                .stdin(Stdio::null())
                .output()
                .map_err(|e| EnrolError(format!("cannot run ssh-keygen: {e}")))?;
            if !o.status.success() {
                let msg = String::from_utf8_lossy(&o.stderr).trim().to_string();
                return err(if msg.contains("Permission denied") || !self.key.exists() || fs::File::open(&self.key).is_err() {
                    format!("cannot read the host key {} — run enrolment as root / Administrator ({msg})", self.key.display())
                } else {
                    format!("signing the card failed: {msg}")
                });
            }
            fs::read_to_string(crate::layout::with_suffix(&f, ".sig")).map_err(|e| EnrolError(e.to_string()))
        })();
        let _ = fs::remove_dir_all(&dir);
        res
    }
}

/// Fingerprint of an OpenSSH public key line (`SHA256:...`), for showing the operator what will be recorded.
pub fn host_key_fingerprint(pub_line: &str) -> Option<String> {
    crate::pubkey::PubKey::parse(pub_line).map(|k| k.fingerprint())
}

// ── pinned TLS ───────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct PinVerifier {
    pin: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = canon::sha256_hex(end_entity.as_ref());
        if got == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!("server certificate sha256:{got} does not match the pinned certificate")))
        }
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReply {
    pub status: u16,
    pub body: String,
}

/// One HTTP/1.1 request over TLS that trusts exactly the certificate whose SHA-256 is `pin`.
/// The handshake (and so the pin check) completes before any request byte is written.
pub fn pinned_request(host: &str, port: u16, pin: &str, method: &str, path: &str, body: Option<&str>, timeout: Duration) -> R<HttpReply> {
    let pin = normalise_pin(pin)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| EnrolError(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin, provider }))
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string()).unwrap_or_else(|_| ServerName::try_from("niyantrak-join".to_string()).unwrap());
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| EnrolError(format!("could not resolve {host}: {e}")))?
        .next()
        .ok_or_else(|| EnrolError(format!("could not resolve {host}")))?;
    let mut sock = TcpStream::connect_timeout(&addr, timeout).map_err(|e| EnrolError(format!("could not reach the control node: {e}")))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|e| EnrolError(e.to_string()))?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock).map_err(|e| EnrolError(format!("refusing to continue: {e}")))?;
    }
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let host_hdr = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: niyantrak-client/{}\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        env!("CARGO_PKG_VERSION"),
        body.len()
    );
    tls.write_all(req.as_bytes()).map_err(|e| EnrolError(format!("send failed: {e}")))?;
    let mut raw = vec![];
    let mut buf = [0u8; 8192];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof && !raw.is_empty() => break, // server closed without close_notify
            Err(e) => return err(format!("read failed: {e}")),
        }
        if raw.len() > 4 << 20 {
            return err("reply too large");
        }
    }
    parse_http(&raw)
}

pub fn parse_http(raw: &[u8]) -> R<HttpReply> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").ok_or_else(|| EnrolError("malformed HTTP reply".into()))?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| EnrolError("malformed HTTP status line".into()))?;
    let chunked = head.lines().any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        let mut out = String::new();
        let mut rest = body;
        while let Some((size, tail)) = rest.split_once("\r\n") {
            let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
            if n == 0 || tail.len() < n {
                break;
            }
            out.push_str(&tail[..n]);
            rest = tail[n..].trim_start_matches("\r\n");
        }
        out
    } else {
        body.to_string()
    };
    Ok(HttpReply { status, body })
}

// ── join / status / config ───────────────────────────────────────────────────────────────────────────────────

/// What this device remembers about its enrolment (no token, no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrolment {
    pub control_plane: String,
    pub host: String,
    pub port: u16,
    pub pin: String,
    pub node_id: String,
    pub card_sha256: String,
    pub host_key_fingerprint: String,
    pub state: String,
    pub requested_at: String,
    #[serde(default)]
    pub checked_at: Option<String>,
}

impl Enrolment {
    pub fn load(path: &Path) -> Option<Enrolment> {
        serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
    }
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(d) = path.parent() {
            fs::create_dir_all(d)?;
        }
        fs::write(path, serde_json::to_string_pretty(self).unwrap_or_default() + "\n")
    }
}

/// Sign the card and ask the control plane to join. Returns the local record (state usually "pending").
pub fn join(invite: &Invite, card: &Value, signer: &dyn Signer, timeout: Duration) -> R<Enrolment> {
    let pub_line = signer.public_key()?;
    let signature = signer.sign(&card_bytes(card))?;
    let body = json!({"token": invite.token, "card": card, "signature": signature, "host_pubkey": pub_line}).to_string();
    let r = pinned_request(&invite.host, invite.port, &invite.pin, "POST", "/api/join", Some(&body), timeout)?;
    let d: Value = serde_json::from_str(&r.body).unwrap_or(json!({"error": r.body.chars().take(200).collect::<String>()}));
    if r.status != 200 {
        return err(format!("join refused: {}", d.get("error").and_then(|e| e.as_str()).unwrap_or(&format!("HTTP {}", r.status))));
    }
    Ok(Enrolment {
        control_plane: invite.url.clone(),
        host: invite.host.clone(),
        port: invite.port,
        pin: invite.pin.clone(),
        node_id: d.get("node_id").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
        card_sha256: card_sha256(card),
        host_key_fingerprint: host_key_fingerprint(&pub_line).unwrap_or_default(),
        state: d.get("state").and_then(|v| v.as_str()).unwrap_or("pending").to_string(),
        requested_at: crate::timeutil::iso(crate::timeutil::now()),
        checked_at: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Status {
    State(String),
    /// the control plane does not offer a status endpoint (approve in the panel, then reopen the app)
    Unsupported,
}

/// Ask the control plane for this node's state: `GET /api/join/status?node_id=..&card_sha256=..` on the join listener.
pub fn status(e: &Enrolment, timeout: Duration) -> R<Status> {
    let path = format!("/api/join/status?node_id={}&card_sha256={}", e.node_id, e.card_sha256);
    let r = pinned_request(&e.host, e.port, &e.pin, "GET", &path, None, timeout)?;
    match r.status {
        200 => {
            let d: Value = serde_json::from_str(&r.body).map_err(|_| EnrolError("status reply is not JSON".into()))?;
            Ok(Status::State(d.get("state").and_then(|v| v.as_str()).unwrap_or("unknown").to_string()))
        }
        404 | 405 => Ok(Status::Unsupported),
        s => err(format!("status check failed: HTTP {s}")),
    }
}

/// Fetch this node's client configuration (`features` + `ssh_rotation`) once approved:
/// `GET /api/client/config?node_id=..`. Ok(None) when the control plane does not offer it yet.
pub fn fetch_client_config(e: &Enrolment, timeout: Duration) -> R<Option<String>> {
    let r = pinned_request(&e.host, e.port, &e.pin, "GET", &format!("/api/client/config?node_id={}", e.node_id), None, timeout)?;
    match r.status {
        200 => Ok(Some(r.body)),
        404 | 405 => Ok(None),
        s => err(format!("config fetch failed: HTTP {s}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34";
    const TOK: &str = "Zq3v_8x-LkP2mN5tR7yW9aB1cD3eF5gH7jK9lM1nO3p";

    #[test]
    fn parses_the_panel_one_liner() {
        let i = parse_invite(&format!("sudo python3 -m niyantrak.join https://ws-01.local:8771 {TOK} --pin sha256:{PIN}")).unwrap();
        assert_eq!((i.host.as_str(), i.port, i.token.as_str(), i.pin.as_str()), ("ws-01.local", 8771, TOK, PIN));
        assert_eq!(i.url, "https://ws-01.local:8771");
    }

    #[test]
    fn parses_qr_link_and_ipv6() {
        let i = parse_invite(&format!("niyantrak://join?url=https%3A%2F%2F%5Bfd7a%3A115c%3A%3A1%5D%3A8771&token={TOK}&pin=sha256%3A{PIN}")).unwrap();
        assert_eq!((i.host.as_str(), i.port), ("fd7a:115c::1", 8771));
        assert_eq!(i.url, "https://[fd7a:115c::1]:8771");
    }

    #[test]
    fn refuses_unpinned_or_plain_http() {
        assert!(parse_invite(&format!("https://h:8771 {TOK}")).unwrap_err().0.contains("--pin"));
        assert!(parse_invite(&format!("http://h:8771 {TOK} --pin {PIN}")).is_err());
        assert!(parse_invite(&format!("https://h:8771 {TOK} --pin sha256:1234")).is_err());
        assert!(normalise_pin(&PIN.to_uppercase()).is_ok());
        assert_eq!(normalise_pin(&format!("sha256:{}", PIN.as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":"))).unwrap(), PIN);
    }

    #[test]
    fn node_id_scheme_matches_card_py() {
        // card.node_id(): "nyk-" + sha256(lower(uuid))[:12]
        assert_eq!(node_id_from("  ABCDEF  ", false), node_id_from("abcdef", false));
        assert_eq!(node_id_from("abcdef", false), format!("nyk-{}", &canon::sha256_hex(b"abcdef")[..12]));
    }

    #[test]
    fn ip_addr_parsing_skips_virtual_interfaces() {
        let out = "1: lo    inet 127.0.0.1/8 scope host lo\n\
2: enp5s0    inet 198.51.100.20/24 brd 198.51.100.255 scope global enp5s0\n\
2: enp5s0    inet6 fe80::1/64 scope link \n\
3: docker0    inet 172.17.0.1/16 scope global docker0\n\
4: tailscale0    inet6 fd7a:115c::5/128 scope global \n\
4: tailscale0    inet6 fd7a:115c::6/64 scope global temporary dynamic \n";
        let (v4, v6) = parse_ip_addr(out);
        assert_eq!(v4, vec!["198.51.100.20"]);
        assert_eq!(v6, vec!["fd7a:115c::5", "fe80::1%enp5s0"]);
    }

    #[test]
    fn card_has_the_card_py_fields() {
        let c = collect_card(Some("client"));
        for k in ["card_version", "node_id", "hostname", "role", "os", "cpu", "memory_gb", "gpu", "addresses"] {
            assert!(c.get(k).is_some(), "{k}");
        }
        assert!(c["node_id"].as_str().unwrap().starts_with("nyk-"));
        assert_eq!(card_sha256(&c).len(), 64);
    }

    #[test]
    fn http_parsing() {
        let r = parse_http(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"state\":\"pending\"}").unwrap();
        assert_eq!((r.status, r.body.as_str()), (200, "{\"state\":\"pending\"}"));
        let c = parse_http(b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n").unwrap();
        assert_eq!((c.status, c.body.as_str()), (403, "hello"));
        assert!(parse_http(b"garbage").is_err());
    }
}
