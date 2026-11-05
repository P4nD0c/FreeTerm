//! SFTP: one background worker per connected pane (pure-Rust SSH), plus local files.

use eframe::egui;
use russh::client;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use tokio::io::AsyncWriteExt;

#[derive(Clone, Debug)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: u64,
}

impl FileEntry {
    pub fn kind(&self) -> String {
        if self.is_dir {
            "folder".into()
        } else {
            match self.name.rsplit_once('.') {
                Some((_, ext)) if !ext.is_empty() && ext.len() <= 6 => ext.to_lowercase(),
                _ => "file".into(),
            }
        }
    }
}

pub enum Req {
    List(String),
    Download { remote: String, local: PathBuf, is_dir: bool },
    Upload { local: PathBuf, remote: String, is_dir: bool },
    Mkdir(String),
    Delete { path: String, is_dir: bool },
    Rename { from: String, to: String },
}

pub enum Resp {
    Connected { home: String },
    Listing { path: String, entries: Vec<FileEntry> },
    Done(String),
    Error(String),
    Disconnected(String),
}

pub struct ConnectInfo {
    pub address: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub private_key: Option<(String, String)>,
    /// Keep-alive seconds; 0 = off.
    pub keepalive_secs: u32,
}

/// Transfer chunk size.
pub const SFTP_CHUNK: usize = 16 * 1024;

pub struct Remote {
    tx: tokio::sync::mpsc::UnboundedSender<Req>,
    pub rx: Receiver<Resp>,
}

impl Remote {
    pub fn send(&self, r: Req) {
        let _ = self.tx.send(r);
    }
}

pub fn connect(info: ConnectInfo, ctx: &egui::Context) -> Remote {
    let (tx, rx_req) = tokio::sync::mpsc::unbounded_channel();
    let (tx_resp, rx) = channel();
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tx_resp.send(Resp::Disconnected(e.to_string()));
                return;
            }
        };
        rt.block_on(worker(info, rx_req, tx_resp, ctx));
    });
    Remote { tx, rx }
}

struct Client {
    host: String,
    port: u16,
    /// Set when the server is not in known_hosts yet, so the error can show it.
    unknown: Arc<std::sync::Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    /// Only servers already in the app's known_hosts file are accepted. A new server
    /// is verified once in an SSH terminal, where OpenSSH shows its fingerprint and
    /// asks the user before saving it. Certificates are refused because no
    /// certificate authority is configured to check them against.
    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else {
            return Ok(false);
        };
        let path = crate::model::known_hosts_path();
        match russh::keys::check_known_hosts_path(&self.host, self.port, key, &path) {
            Ok(true) => Ok(true),
            Ok(false) => {
                let fp = key.fingerprint(russh::keys::HashAlg::Sha256).to_string();
                if let Ok(mut u) = self.unknown.lock() {
                    *u = Some(fp);
                }
                Ok(false)
            }
            Err(_) => Ok(false),
        }
    }
}

async fn open(info: &ConnectInfo) -> Result<(client::Handle<Client>, russh_sftp::client::SftpSession), String> {
    if info.address.trim().is_empty() {
        return Err(crate::model::MSG_HOST_EMPTY.to_string());
    }
    let mut config = client::Config::default();
    if info.keepalive_secs > 0 {
        config.keepalive_interval = Some(std::time::Duration::from_secs(info.keepalive_secs as u64));
    }
    let config = Arc::new(config);
    let unknown = Arc::new(std::sync::Mutex::new(None));
    let handler = Client { host: info.address.clone(), port: info.port, unknown: unknown.clone() };
    let mut handle = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        client::connect(config, (info.address.as_str(), info.port), handler),
    )
    .await
    .map_err(|_| "Connection timed out".to_string())?
    .map_err(|e| {
        if let Some(fp) = unknown.lock().ok().and_then(|u| u.clone()) {
            return format!(
                "This server is not trusted yet ({fp}). Open it once in an SSH terminal, check the fingerprint and accept it, then try SFTP again."
            );
        }
        match e {
            russh::Error::UnknownKey => "The server's identity changed or could not be verified (see Known Hosts).".to_string(),
            other => format!("Could not connect: {other}"),
        }
    })?;

    let user = if info.user.is_empty() { whoami() } else { info.user.clone() };
    let mut ok = false;
    if let Some((pem, pass)) = &info.private_key {
        let pass = if pass.is_empty() { None } else { Some(pass.as_str()) };
        match russh::keys::decode_secret_key(pem, pass) {
            Ok(key) => {
                let hash = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
                let res = handle
                    .authenticate_publickey(user.clone(), PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                    .await
                    .map_err(|e| e.to_string())?;
                ok = res.success();
            }
            Err(e) => return Err(format!("The key could not be read: {e}")),
        }
    }
    if !ok && !info.password.is_empty() {
        ok = handle
            .authenticate_password(user.clone(), info.password.clone())
            .await
            .map_err(|e| e.to_string())?
            .success();
    }
    if !ok {
        return Err(if info.password.is_empty() && info.private_key.is_none() {
            "Add a password or key to this host to use SFTP.".into()
        } else {
            "Authentication failed.".into()
        });
    }
    let channel = handle.channel_open_session().await.map_err(|e| e.to_string())?;
    channel.request_subsystem(true, "sftp").await.map_err(|e| e.to_string())?;
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream()).await.map_err(|e| e.to_string())?;
    Ok((handle, sftp))
}

fn whoami() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "root".into())
}

async fn worker(
    info: ConnectInfo,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Req>,
    tx: Sender<Resp>,
    ctx: egui::Context,
) {
    let (_handle, sftp) = match open(&info).await {
        Ok(v) => v,
        Err(e) => {
            let _ = tx.send(Resp::Disconnected(e));
            ctx.request_repaint();
            return;
        }
    };
    let home = sftp.canonicalize(".").await.unwrap_or_else(|_| "/".into());
    let _ = tx.send(Resp::Connected { home });
    ctx.request_repaint();
    while let Some(req) = rx.recv().await {
        let resp = match req {
            Req::List(path) => match list(&sftp, &path).await {
                Ok(entries) => Resp::Listing { path, entries },
                Err(e) => Resp::Error(e),
            },
            Req::Download { remote, local, is_dir } => match download(&sftp, remote.clone(), local, is_dir).await {
                Ok(()) => Resp::Done(format!("Downloaded {}", base_name(&remote))),
                Err(e) => Resp::Error(e),
            },
            Req::Upload { local, remote, is_dir } => match upload(&sftp, local.clone(), remote, is_dir).await {
                Ok(()) => Resp::Done(format!("Uploaded {}", local.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default())),
                Err(e) => Resp::Error(e),
            },
            Req::Mkdir(p) => match sftp.create_dir(p).await {
                Ok(()) => Resp::Done("Folder created".into()),
                Err(e) => Resp::Error(e.to_string()),
            },
            Req::Delete { path, is_dir } => match delete(&sftp, path, is_dir).await {
                Ok(()) => Resp::Done("Deleted".into()),
                Err(e) => Resp::Error(e),
            },
            Req::Rename { from, to } => match sftp.rename(from, to).await {
                Ok(()) => Resp::Done("Renamed".into()),
                Err(e) => Resp::Error(e.to_string()),
            },
        };
        if tx.send(resp).is_err() {
            break;
        }
        ctx.request_repaint();
    }
}

async fn list(sftp: &russh_sftp::client::SftpSession, path: &str) -> Result<Vec<FileEntry>, String> {
    let dir = sftp.read_dir(path).await.map_err(|e| e.to_string())?;
    let mut out: Vec<FileEntry> = dir
        .filter(|e| e.file_name() != "." && e.file_name() != "..")
        .map(|e| {
            let m = e.metadata();
            FileEntry {
                name: e.file_name(),
                is_dir: m.is_dir(),
                size: m.size.unwrap_or(0),
                modified: m.mtime.unwrap_or(0) as u64,
            }
        })
        .collect();
    sort_entries(&mut out);
    Ok(out)
}

pub fn sort_entries(v: &mut [FileEntry]) {
    v.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
}

fn download<'a>(
    sftp: &'a russh_sftp::client::SftpSession,
    remote: String,
    local_dir: PathBuf,
    is_dir: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let target = local_dir.join(base_name(&remote));
        if is_dir {
            tokio::fs::create_dir_all(&target).await.map_err(|e| e.to_string())?;
            for e in list(sftp, &remote).await? {
                download(sftp, join_remote(&remote, &e.name), target.clone(), e.is_dir).await?;
            }
            Ok(())
        } else {
            let mut src = sftp.open(remote).await.map_err(|e| e.to_string())?;
            let mut dst = tokio::fs::File::create(&target).await.map_err(|e| e.to_string())?;
            copy_chunks(&mut src, &mut dst).await?;
            dst.flush().await.map_err(|e| e.to_string())?;
            Ok(())
        }
    })
}

fn upload<'a>(
    sftp: &'a russh_sftp::client::SftpSession,
    local: PathBuf,
    remote_dir: String,
    is_dir: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        let name = local.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let target = join_remote(&remote_dir, &name);
        if is_dir {
            let _ = sftp.create_dir(target.clone()).await;
            let mut rd = tokio::fs::read_dir(&local).await.map_err(|e| e.to_string())?;
            while let Ok(Some(e)) = rd.next_entry().await {
                let d = e.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
                upload(sftp, e.path(), target.clone(), d).await?;
            }
            Ok(())
        } else {
            let mut src = tokio::fs::File::open(&local).await.map_err(|e| e.to_string())?;
            let mut dst = sftp.create(target).await.map_err(|e| e.to_string())?;
            copy_chunks(&mut src, &mut dst).await?;
            dst.shutdown().await.map_err(|e| e.to_string())?;
            Ok(())
        }
    })
}

fn delete<'a>(
    sftp: &'a russh_sftp::client::SftpSession,
    path: String,
    is_dir: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        if is_dir {
            for e in list(sftp, &path).await? {
                delete(sftp, join_remote(&path, &e.name), e.is_dir).await?;
            }
            sftp.remove_dir(path).await.map_err(|e| e.to_string())
        } else {
            sftp.remove_file(path).await.map_err(|e| e.to_string())
        }
    })
}

/// Copies in SFTP_CHUNK pieces.
async fn copy_chunks<R, W>(src: &mut R, dst: &mut W) -> Result<(), String>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; SFTP_CHUNK];
    loop {
        let n = src.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(());
        }
        dst.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
    }
}

pub fn join_remote(dir: &str, name: &str) -> String {
    if dir.ends_with('/') { format!("{dir}{name}") } else { format!("{dir}/{name}") }
}

pub fn parent_remote(dir: &str) -> String {
    let t = dir.trim_end_matches('/');
    match t.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => t[..i].to_string(),
    }
}

pub fn base_name(p: &str) -> String {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or(p).to_string()
}

// ---------------- local files ----------------

pub fn list_local(path: &Path) -> Result<Vec<FileEntry>, String> {
    let rd = std::fs::read_dir(path).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for e in rd.flatten() {
        let md = e.metadata();
        let (is_dir, size, modified) = match md {
            Ok(m) => (
                m.is_dir(),
                m.len(),
                m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0),
            ),
            Err(_) => (false, 0, 0),
        };
        out.push(FileEntry { name: e.file_name().to_string_lossy().to_string(), is_dir, size, modified });
    }
    sort_entries(&mut out);
    Ok(out)
}

pub fn copy_local(src: &Path, dst_dir: &Path) -> std::io::Result<()> {
    let name = src.file_name().unwrap_or_default();
    let target = dst_dir.join(name);
    if src.is_dir() {
        std::fs::create_dir_all(&target)?;
        for e in std::fs::read_dir(src)?.flatten() {
            copy_local(&e.path(), &target)?;
        }
        Ok(())
    } else {
        std::fs::copy(src, target).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unreachable_server_reports_error() {
        let ctx = egui::Context::default();
        let r = connect(
            ConnectInfo { address: "127.0.0.1".into(), port: 1, user: "x".into(), password: "y".into(), private_key: None, keepalive_secs: 60 },
            &ctx,
        );
        let got = r.rx.recv_timeout(std::time::Duration::from_secs(25)).expect("reply");
        assert!(matches!(got, Resp::Disconnected(_)));
    }
}
