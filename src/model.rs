//! Everything the user saves: one local workspace stored on disk.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default SSH port.
pub const DEFAULT_SSH_PORT: u16 = 22;

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(default)]
pub struct Host {
    pub id: u64,
    pub label: String,
    pub address: String,
    /// Empty means the default port 22.
    pub port: String,
    pub username: String,
    pub password: String,
    pub key_id: Option<u64>,
    pub group: String,
    pub tags: Vec<String>,
    /// "default" or "ctrl-h".
    pub backspace: String,
    pub startup_snippet: Option<u64>,
    pub agent_forwarding: bool,
    pub created: u64,
}

impl Host {
    pub fn display_name(&self) -> String {
        if !self.label.trim().is_empty() {
            self.label.clone()
        } else if !self.address.trim().is_empty() {
            self.address.clone()
        } else {
            "Unnamed host".into()
        }
    }
    pub fn port_number(&self) -> u16 {
        self.port.trim().parse().unwrap_or(DEFAULT_SSH_PORT)
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(default)]
pub struct Key {
    pub id: u64,
    pub label: String,
    pub private_key: String,
    pub public_key: String,
    pub passphrase: String,
    pub certificate: String,
    pub kind: String,
    pub created: u64,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum FwKind {
    #[default]
    Local,
    Remote,
    Dynamic,
}

impl FwKind {
    pub fn name(self) -> &'static str {
        match self {
            FwKind::Local => "Local",
            FwKind::Remote => "Remote",
            FwKind::Dynamic => "Dynamic",
        }
    }
    pub fn help(self) -> &'static str {
        match self {
            FwKind::Local => "Opens a port on this computer that leads to an address reachable from the server.",
            FwKind::Remote => "Opens a port on the server that leads back to an address reachable from this computer.",
            FwKind::Dynamic => "Runs a local SOCKS5 proxy: any app using it connects out through the server.",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(default)]
pub struct Forward {
    pub id: u64,
    pub label: String,
    pub kind: FwKind,
    pub host_id: Option<u64>,
    /// Local port (Local/Dynamic) or remote port (Remote).
    pub port: String,
    pub bind_address: String,
    pub dest_address: String,
    pub dest_port: String,
    pub created: u64,
}

impl Forward {
    pub fn summary(&self) -> String {
        let bind = if self.bind_address.trim().is_empty() { "localhost" } else { self.bind_address.trim() };
        match self.kind {
            FwKind::Local => format!("{}:{} → {}:{}", bind, self.port, self.dest_address, self.dest_port),
            FwKind::Remote => format!("remote {}:{} → {}:{}", bind, self.port, self.dest_address, self.dest_port),
            FwKind::Dynamic => format!("SOCKS on {}:{}", bind, self.port),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(default)]
pub struct Snippet {
    pub id: u64,
    pub label: String,
    pub script: String,
    pub created: u64,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(default)]
pub struct LogEntry {
    pub host: String,
    pub address: String,
    pub user: String,
    pub protocol: String,
    pub started: u64,
    pub ended: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    pub font_size: f32,
    /// Seconds between SSH keep-alives; 0 turns them off.
    pub keepalive_interval: u32,
    pub autoreconnect: bool,
    pub brighten_bold: bool,
}

/// Keep-alive default in seconds.
pub const DEFAULT_KEEPALIVE_SECS: u32 = 60;
/// Reconnect wait: starts at 0, +30 s after each try, at most 60 s.
pub const RECONNECT_STEP_MS: u64 = 30_000;
pub const RECONNECT_MAX_MS: u64 = 60_000;
/// Shown when a host has no address.
pub const MSG_HOST_EMPTY: &str = "This host has no address yet. Add one to connect.";

impl Default for Settings {
    fn default() -> Self {
        Self { font_size: 14.0, keepalive_interval: DEFAULT_KEEPALIVE_SECS, autoreconnect: true, brighten_bold: false }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(default)]
pub struct Vault {
    pub hosts: Vec<Host>,
    pub keys: Vec<Key>,
    pub forwards: Vec<Forward>,
    pub snippets: Vec<Snippet>,
    pub logs: Vec<LogEntry>,
    pub shell_history: Vec<String>,
    pub settings: Settings,
    pub next_id: u64,
}

impl Vault {
    pub fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
    pub fn host(&self, id: u64) -> Option<&Host> {
        self.hosts.iter().find(|h| h.id == id)
    }
    pub fn key(&self, id: u64) -> Option<&Key> {
        self.keys.iter().find(|k| k.id == id)
    }
    pub fn snippet(&self, id: u64) -> Option<&Snippet> {
        self.snippets.iter().find(|s| s.id == id)
    }

    /// Loads the workspace. Order: the encrypted `workspace.dat`, then an older
    /// plain `vault.json` (moved into the encrypted file on the next save).
    pub fn load() -> Vault {
        let dir = data_dir();
        let sealed_path = dir.join(SEALED_FILE);
        if let Ok(bytes) = std::fs::read(&sealed_path) {
            let parsed = bytes
                .strip_prefix(SEALED_MAGIC)
                .and_then(crate::secure::open)
                .and_then(|plain| serde_json::from_slice::<Vault>(&plain).ok());
            if let Some(v) = parsed {
                return v;
            }
            // Unreadable (another Windows user, damaged file): keep it aside rather
            // than overwrite it, and start empty.
            let _ = std::fs::rename(&sealed_path, dir.join(format!("{SEALED_FILE}.unreadable-{}", now())));
            return Vault::default();
        }
        std::fs::read_to_string(dir.join(LEGACY_FILE))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Saves the workspace encrypted for the current Windows user.
    pub fn save(&self) -> Result<(), String> {
        let dir = data_dir();
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let plain = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let sealed = crate::secure::seal(&plain).ok_or("Windows could not encrypt the workspace")?;
        let mut out = SEALED_MAGIC.to_vec();
        out.extend_from_slice(&sealed);
        let tmp = dir.join(format!("{SEALED_FILE}.tmp"));
        std::fs::write(&tmp, out).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, dir.join(SEALED_FILE)).map_err(|e| e.to_string())?;
        // The encrypted copy is safely on disk: remove the old plain-text file.
        let _ = std::fs::remove_file(dir.join(LEGACY_FILE));
        Ok(())
    }
}

const SEALED_FILE: &str = "workspace.dat";
const SEALED_MAGIC: &[u8] = b"FTW1";
const LEGACY_FILE: &str = "vault.json";

pub fn data_dir() -> PathBuf {
    dirs::config_dir().unwrap_or_else(std::env::temp_dir).join("FreeTerm")
}

pub fn known_hosts_path() -> PathBuf {
    data_dir().join("known_hosts")
}

/// Writes a key to a temporary file OpenSSH can read and returns its path.
/// The folder is emptied by [`clear_key_files`] shortly after the login, and when
/// the app starts and exits, so private keys do not stay on disk unencrypted.
pub fn key_file(key: &Key) -> Option<PathBuf> {
    if key.private_key.trim().is_empty() {
        return None;
    }
    let dir = key_dir();
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(format!("key-{}", key.id));
    let mut text = key.private_key.replace("\r\n", "\n");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    std::fs::write(&path, text).ok()?;
    if !key.certificate.trim().is_empty() {
        let _ = std::fs::write(dir.join(format!("key-{}-cert.pub", key.id)), key.certificate.trim());
    }
    Some(path)
}

fn key_dir() -> PathBuf {
    data_dir().join("keys")
}

/// Deletes every temporary key file.
pub fn clear_key_files() {
    let _ = std::fs::remove_dir_all(key_dir());
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A known host line from the app's own known_hosts file.
#[derive(Clone, Debug)]
pub struct KnownHost {
    pub host: String,
    pub key_type: String,
    pub line: String,
}

pub fn read_known_hosts() -> Vec<KnownHost> {
    let text = std::fs::read_to_string(known_hosts_path()).unwrap_or_default();
    parse_known_hosts(&text)
}

pub fn parse_known_hosts(text: &str) -> Vec<KnownHost> {
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let host = parts.next()?.to_string();
            let key_type = parts.next()?.to_string();
            Some(KnownHost { host, key_type, line: l.to_string() })
        })
        .collect()
}

pub fn write_known_hosts(list: &[KnownHost]) {
    let _ = std::fs::create_dir_all(data_dir());
    let mut s = String::new();
    for k in list {
        s.push_str(&k.line);
        s.push('\n');
    }
    let _ = std::fs::write(known_hosts_path(), s);
}

/// Parses the quick-connect box: `[ssh] [user@]host [-p port]`.
pub struct Quick {
    pub address: String,
    pub port: Option<u16>,
    pub username: Option<String>,
}

pub fn parse_quick(input: &str) -> Quick {
    let words: Vec<&str> = input.split_whitespace().collect();
    let mut positional = Vec::new();
    let mut port = None;
    let mut i = 0;
    while i < words.len() {
        let w = words[i];
        if w == "-p" {
            if let Some(n) = words.get(i + 1) {
                port = n.parse::<u16>().ok();
            }
            i += 2;
            continue;
        } else if let Some(rest) = w.strip_prefix("-p")
            && !rest.is_empty() {
                port = rest.parse::<u16>().ok();
                i += 1;
                continue;
            }
        if !w.starts_with('-') {
            positional.push(w);
        }
        i += 1;
    }
    let is_ssh = positional.first() == Some(&"ssh");
    let target = positional.get(if is_ssh { 1 } else { 0 }).copied().unwrap_or("");
    let (username, address) = match target.split_once('@') {
        Some((u, a)) => (Some(u.to_string()), a.to_string()),
        None => (None, target.to_string()),
    };
    Quick { address, port, username }
}

/// "12 Mar 2026, 14:05" from unix seconds (local offset not applied: UTC).
pub fn format_time(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!("{} {} {}, {:02}:{:02}", d, MONTHS[(m - 1) as usize], y, rem / 3600, (rem % 3600) / 60)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{} B", bytes) } else { format!("{:.1} {}", v, UNITS[u]) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quick_parse() {
        let q = parse_quick("ssh root@10.0.0.1 -p 2222");
        assert_eq!(q.address, "10.0.0.1");
        assert_eq!(q.port, Some(2222));
        assert_eq!(q.username.as_deref(), Some("root"));
        let q = parse_quick("example.com");
        assert_eq!(q.address, "example.com");
        assert!(q.username.is_none());
    }

    #[test]
    fn quick_parse_variants() {
        let q = parse_quick("admin@host -p2200");
        assert_eq!(q.port, Some(2200));
        assert_eq!(q.username.as_deref(), Some("admin"));
        let q = parse_quick("ssh host -p notaport");
        assert_eq!(q.port, None);
        assert_eq!(parse_quick("").address, "");
    }

    #[test]
    fn known_hosts_lines() {
        let list = parse_known_hosts("# comment\n\n[srv]:2222 ssh-ed25519 AAAA\nbox ssh-rsa BBBB\n");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].host, "[srv]:2222");
        assert_eq!(list[1].key_type, "ssh-rsa");
    }

    #[test]
    fn sizes_and_times() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_time(0), "1 Jan 1970, 00:00");
        assert_eq!(format_time(951_782_400), "29 Feb 2000, 00:00");
    }

    #[test]
    fn workspace_round_trip() {
        let mut v = Vault::default();
        let id = v.new_id();
        v.hosts.push(Host { id, label: "web".into(), address: "10.0.0.2".into(), ..Default::default() });
        let json = serde_json::to_vec(&v).unwrap();
        let back: Vault = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.hosts[0].address, "10.0.0.2");
        assert_eq!(back.host(id).unwrap().port_number(), DEFAULT_SSH_PORT);
        assert_eq!(back.settings.keepalive_interval, DEFAULT_KEEPALIVE_SECS);
    }
}
