//! The window: title bar with tabs, sidebar, the six vault pages, side editors,
//! terminal tabs and the SFTP tab.

use crate::look::*;
use crate::model::*;
use crate::sftp::{self, FileEntry, Remote, Req, Resp};
use crate::terminal::Term;
use eframe::egui::{
    self, Align2, Color32, Id, Pos2, Rect, Sense, Stroke, StrokeKind, Ui, UiBuilder, Vec2, pos2, vec2,
};
use portable_pty::CommandBuilder;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Hosts,
    Keychain,
    PortForwarding,
    Snippets,
    KnownHosts,
    Logs,
}

/// How long a temporary key file for ssh.exe may stay on disk.
const KEY_FILE_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);

const PAGES: [(Page, &str, Icon); 6] = [
    (Page::Hosts, "Hosts", Icon::Hosts),
    (Page::Keychain, "Keys", Icon::Key),
    (Page::PortForwarding, "Tunnels", Icon::Forward),
    (Page::Snippets, "Snippets", Icon::Braces),
    (Page::KnownHosts, "Known Hosts", Icon::Fingerprint),
    (Page::Logs, "Logs", Icon::Clock),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum TabSel {
    Vaults,
    Sftp,
    Session(u64),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Panel {
    None,
    Host(u64),
    Key(u64),
    Forward(u64),
    Snippet(u64),
    Generate,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Popup {
    MainMenu,
    Vaults,
    NewHost,
    NewKey,
    NewForward,
    NewSnippet,
    Sort,
    Tags,
    Notifications,
    NewTab,
    PanelMore,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    AZ,
    ZA,
    Newest,
    Oldest,
}

enum Modal {
    Settings,
    Serial { port: String, baud: u32, ports: Vec<String> },
    PickSftpHost(usize),
}

struct GenForm {
    label: String,
    kind: String,
    rsa_bits: u32,
    ecdsa_bits: u32,
    passphrase: String,
}

impl Default for GenForm {
    fn default() -> Self {
        // Key defaults: ED25519; RSA 4096 bits; ECDSA 521 bits.
        GenForm { label: String::new(), kind: "ED25519".into(), rsa_bits: 4096, ecdsa_bits: 521, passphrase: String::new() }
    }
}

enum SessionKind {
    Ssh,
    Local,
    Serial,
}

struct Session {
    id: u64,
    title: String,
    kind: SessionKind,
    term: Term,
    log: Option<usize>,
    startup: Option<String>,
    started: f64,
    /// The host behind an SSH tab (used to reconnect).
    host: Option<Host>,
    /// When a dropped SSH connection will be retried (app time, seconds).
    reconnect_at: Option<f64>,
}

enum PaneState {
    Empty,
    Local { path: PathBuf, entries: Vec<FileEntry> },
    Remote { remote: Remote, title: String, path: String, entries: Vec<FileEntry> },
}

struct Pane {
    state: PaneState,
    selected: Option<String>,
    status: String,
    busy: bool,
    new_folder: Option<String>,
    rename: Option<(String, String)>,
}

impl Pane {
    fn new() -> Self {
        Pane { state: PaneState::Empty, selected: None, status: String::new(), busy: false, new_folder: None, rename: None }
    }
}

pub struct App {
    vault: Vault,
    persist: bool,
    /// Last save failure, shown as a toast on the next frame.
    save_error: Option<String>,
    /// When to delete the temporary key files written for ssh.exe.
    key_cleanup_at: std::cell::Cell<Option<std::time::Instant>>,
    page: Page,
    tab: TabSel,
    sessions: Vec<Session>,
    next_session: u64,
    panel: Panel,
    quick: String,
    new_host_addr: String,
    grid_view: bool,
    sort: Sort,
    tag_filter: Option<String>,
    group_filter: Option<String>,
    search: String,
    search_open: bool,
    forwards: HashMap<u64, Term>,
    known: Vec<KnownHost>,
    show_history: bool,
    panes: [Pane; 2],
    pending_copy: Option<(usize, PathBuf, String, bool)>,
    refresh_local_after: Option<usize>,
    popup: Option<(Popup, Pos2)>,
    popup_frame: u64,
    modal: Option<Modal>,
    toast: Option<(String, f64)>,
    gen_form: GenForm,
    gen_job: Option<Receiver<Result<Key, String>>>,
    show_password: bool,
    frame_no: u64,
    shot: Option<PathBuf>,
    shot_sent: bool,
    shot_done: Arc<AtomicBool>,
    focus_term: bool,
    initial: String,
    /// Reconnect wait in ms: 0, then +30 s per try, capped at 60 s.
    reconnect_timer_ms: u64,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, shot: Option<PathBuf>) -> Self {
        install_fonts(&cc.egui_ctx);
        style(&cc.egui_ctx);
        let persist = shot.is_none();
        crate::model::clear_key_files();
        let vault = if persist { Vault::load() } else { Vault::default() };
        let initial = std::env::var("USERNAME")
            .ok()
            .and_then(|u| u.chars().next())
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "P".into());
        App {
            vault,
            persist,
            save_error: None,
            key_cleanup_at: std::cell::Cell::new(None),
            page: Page::Hosts,
            tab: TabSel::Vaults,
            sessions: Vec::new(),
            next_session: 1,
            panel: Panel::None,
            quick: String::new(),
            new_host_addr: String::new(),
            grid_view: true,
            sort: Sort::AZ,
            tag_filter: None,
            group_filter: None,
            search: String::new(),
            search_open: false,
            forwards: HashMap::new(),
            known: if persist { read_known_hosts() } else { Vec::new() },
            show_history: false,
            panes: [Pane::new(), Pane::new()],
            pending_copy: None,
            refresh_local_after: None,
            popup: None,
            popup_frame: 0,
            modal: None,
            toast: None,
            gen_form: GenForm::default(),
            gen_job: None,
            show_password: false,
            frame_no: 0,
            shot,
            shot_sent: false,
            shot_done: Arc::new(AtomicBool::new(false)),
            focus_term: false,
            initial,
            reconnect_timer_ms: 0,
        }
    }

    /// Test aid for screenshots: FREETERM_SHOT_VIEW picks the screen to show.
    pub fn apply_test_view(&mut self, ctx: &egui::Context) {
        let Ok(v) = std::env::var("FREETERM_SHOT_VIEW") else { return };
        match v.as_str() {
            "keychain" => self.page = Page::Keychain,
            "forwarding" => self.page = Page::PortForwarding,
            "snippets" => self.page = Page::Snippets,
            "known" => self.page = Page::KnownHosts,
            "logs" => self.page = Page::Logs,
            "sftp" => self.tab = TabSel::Sftp,
            "newhost" => {
                let id = self.vault.new_id();
                self.vault.hosts.push(Host { id, backspace: "default".into(), created: now(), ..Default::default() });
                self.panel = Panel::Host(id);
            }
            "terminal" => self.open_local_terminal(ctx),
            _ => {}
        }
    }

    fn save(&mut self) {
        if self.persist
            && let Err(e) = self.vault.save() {
                self.save_error = Some(format!("Could not save your data: {e}"));
            }
    }

    fn toast(&mut self, ctx: &egui::Context, msg: impl Into<String>) {
        self.toast = Some((msg.into(), ctx.input(|i| i.time) + 3.5));
    }

    fn open_popup(&mut self, p: Popup, pos: Pos2) {
        if self.popup.map(|(q, _)| q) == Some(p) {
            self.popup = None;
        } else {
            self.popup = Some((p, pos));
            self.popup_frame = self.frame_no;
        }
    }

    // ------------------------------------------------------------------ sessions

    fn new_session(&mut self, title: String, kind: SessionKind, term: Term, log: Option<usize>, ctx: &egui::Context) {
        let id = self.next_session;
        self.next_session += 1;
        let started = ctx.input(|i| i.time);
        self.sessions.push(Session { id, title, kind, term, log, startup: None, started, host: None, reconnect_at: None });
        self.tab = TabSel::Session(id);
        self.focus_term = true;
    }

    fn ssh_command(&self, host: &Host) -> CommandBuilder {
        let mut c = CommandBuilder::new("ssh.exe");
        let _ = std::fs::create_dir_all(data_dir());
        c.arg("-o");
        c.arg(format!("UserKnownHostsFile={}", known_hosts_path().display()));
        // Keep-alive only when the interval is not 0 (default 60 s).
        let ka = self.vault.settings.keepalive_interval;
        if ka > 0 {
            c.arg("-o");
            c.arg(format!("ServerAliveInterval={ka}"));
        }
        c.arg("-p");
        c.arg(host.port_number().to_string());
        if let Some(k) = host.key_id.and_then(|id| self.vault.key(id))
            && let Some(path) = key_file(k) {
                // OpenSSH reads the key while logging in; delete the file soon after.
                self.key_cleanup_at.set(Some(std::time::Instant::now() + KEY_FILE_LIFETIME));
                c.arg("-i");
                c.arg(path.display().to_string());
                c.arg("-o");
                c.arg("IdentitiesOnly=yes");
            }
        if host.agent_forwarding {
            c.arg("-A");
        }
        let target = if host.username.trim().is_empty() {
            host.address.trim().to_string()
        } else {
            format!("{}@{}", host.username.trim(), host.address.trim())
        };
        c.arg(target);
        // terminalEmulationType default; ssh.exe sends $TERM in its terminal request.
        c.env("TERM", crate::terminal::TERM_TYPE);
        c
    }

    fn spawn_ssh_term(&self, host: &Host, ctx: &egui::Context) -> Result<Term, String> {
        let mut term = Term::spawn(self.ssh_command(host), ctx)?;
        term.auto_password(&host.password);
        if let Some(k) = host.key_id.and_then(|id| self.vault.key(id)) {
            term.auto_passphrase(&k.passphrase);
        }
        term.ctrl_h = host.backspace == "ctrl-h";
        Ok(term)
    }

    fn connect_host(&mut self, host: Host, ctx: &egui::Context) {
        if host.address.trim().is_empty() {
            self.toast(ctx, MSG_HOST_EMPTY);
            return;
        }
        match self.spawn_ssh_term(&host, ctx) {
            Ok(term) => {
                self.vault.logs.push(LogEntry {
                    host: host.display_name(),
                    address: host.address.clone(),
                    user: host.username.clone(),
                    protocol: "SSH".into(),
                    started: now(),
                    ended: None,
                });
                let log = Some(self.vault.logs.len() - 1);
                self.save();
                let startup = host.startup_snippet.and_then(|id| self.vault.snippet(id)).map(|s| s.script.clone());
                self.new_session(host.display_name(), SessionKind::Ssh, term, log, ctx);
                if let Some(s) = self.sessions.last_mut() {
                    s.startup = startup;
                    s.host = Some(host);
                }
            }
            Err(e) => self.toast(ctx, format!("Could not start SSH: {e}")),
        }
    }

    fn open_local_terminal(&mut self, ctx: &egui::Context) {
        let mut c = CommandBuilder::new("powershell.exe");
        c.arg("-NoLogo");
        // Local terminal environment: advertise 256 colours and true colour.
        c.env("TERM", crate::terminal::TERM_TYPE);
        c.env("COLORTERM", "truecolor");
        if let Some(h) = dirs::home_dir() {
            c.cwd(h);
        }
        match Term::spawn(c, ctx) {
            Ok(t) => {
                let n = self.sessions.iter().filter(|s| matches!(s.kind, SessionKind::Local)).count();
                let title = if n == 0 { "Local Terminal".to_string() } else { format!("Local Terminal {}", n + 1) };
                self.new_session(title, SessionKind::Local, t, None, ctx);
            }
            Err(e) => self.toast(ctx, format!("Could not open a terminal: {e}")),
        }
    }

    fn quick_connect(&mut self, ctx: &egui::Context) {
        let q = parse_quick(&self.quick);
        if q.address.is_empty() {
            return;
        }
        let host = Host {
            address: q.address,
            port: q.port.map(|p| p.to_string()).unwrap_or_default(),
            username: q.username.unwrap_or_default(),
            backspace: "default".into(),
            ..Default::default()
        };
        self.quick.clear();
        self.connect_host(host, ctx);
    }

    fn close_session(&mut self, id: u64) {
        if let Some(i) = self.sessions.iter().position(|s| s.id == id) {
            let mut s = self.sessions.remove(i);
            s.term.kill();
            if let Some(li) = s.log
                && let Some(l) = self.vault.logs.get_mut(li)
                    && l.ended.is_none() {
                        l.ended = Some(now());
                    }
            self.save();
            if self.tab == TabSel::Session(id) {
                self.tab = self.sessions.last().map(|s| TabSel::Session(s.id)).unwrap_or(TabSel::Vaults);
            }
        }
    }

    fn run_snippet(&mut self, script: String, ctx: &egui::Context) {
        let target = match self.tab {
            TabSel::Session(id) => Some(id),
            _ => self.sessions.iter().rev().find(|s| !s.term.exited).map(|s| s.id),
        };
        if let Some(id) = target
            && let Some(s) = self.sessions.iter_mut().find(|s| s.id == id) {
                s.term.run_command(&script);
                self.tab = TabSel::Session(id);
                self.focus_term = true;
                return;
            }
        self.open_local_terminal(ctx);
        if let Some(s) = self.sessions.last_mut() {
            s.startup = Some(script);
        }
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let t = ctx.input(|i| i.time);
        if let Some(e) = self.save_error.take() {
            self.toast(ctx, e);
        }
        if self.key_cleanup_at.get().is_some_and(|at| std::time::Instant::now() >= at) {
            self.key_cleanup_at.set(None);
            crate::model::clear_key_files();
        }
        let mut history = Vec::new();
        let mut ended_any = false;
        let autoreconnect = self.vault.settings.autoreconnect;
        let bright = self.vault.settings.brighten_bold;
        let mut reconnect_due: Vec<u64> = Vec::new();
        for s in self.sessions.iter_mut() {
            s.term.bright_bold = bright;
            let was_running = !s.term.exited;
            s.term.poll();
            // Auto-reconnect (on by default): a connected SSH tab whose connection dropped
            // (ssh.exe exit code 255) is retried after the reconnect timer.
            if was_running
                && s.term.exited
                && autoreconnect
                && s.host.is_some()
                && s.term.exit_code == Some(255)
                && t - s.started > 10.0
            {
                let wait = self.reconnect_timer_ms;
                self.reconnect_timer_ms = (self.reconnect_timer_ms + RECONNECT_STEP_MS).min(RECONNECT_MAX_MS);
                s.reconnect_at = Some(t + wait as f64 / 1000.0);
                s.term.print(&format!("\r\n\x1b[90mConnection lost. Reconnecting in {} s…\x1b[0m\r\n", wait / 1000));
            }
            if let Some(at) = s.reconnect_at {
                if t >= at {
                    s.reconnect_at = None;
                    reconnect_due.push(s.id);
                } else {
                    ctx.request_repaint_after(std::time::Duration::from_millis(200));
                }
            }
            // A session that stays up resets the timer (resetReconnectTimer).
            if !s.term.exited && s.host.is_some() && t - s.started > 60.0 && self.reconnect_timer_ms != 0 {
                self.reconnect_timer_ms = 0;
            }
            history.append(&mut s.term.typed_commands);
            if s.startup.is_some() && s.term.has_output && t - s.started > 1.0 {
                let text = s.term.screen_text();
                let last = text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim_end();
                let lower = last.to_lowercase();
                if (last.ends_with('$') || last.ends_with('#') || last.ends_with('>') || last.ends_with('%'))
                    && !lower.contains("password")
                    && let Some(script) = s.startup.take() {
                        s.term.run_command(&script);
                    }
            }
            if s.term.exited
                && let Some(li) = s.log
                    && let Some(l) = self.vault.logs.get_mut(li)
                        && l.ended.is_none() {
                            l.ended = Some(now());
                            ended_any = true;
                        }
        }
        for id in reconnect_due {
            let Some(host) = self.sessions.iter().find(|s| s.id == id).and_then(|s| s.host.clone()) else { continue };
            match self.spawn_ssh_term(&host, ctx) {
                Ok(term) => {
                    if let Some(s) = self.sessions.iter_mut().find(|s| s.id == id) {
                        s.term = term;
                        s.started = t;
                    }
                }
                Err(e) => self.toast(ctx, format!("Could not reconnect: {e}")),
            }
        }
        if !history.is_empty() {
            for h in history {
                self.vault.shell_history.retain(|x| x != &h);
                self.vault.shell_history.push(h);
            }
            let n = self.vault.shell_history.len();
            if n > 500 {
                self.vault.shell_history.drain(..n - 500);
            }
            ended_any = true;
        }
        if ended_any {
            self.save();
        }
        for f in self.forwards.values_mut() {
            f.poll();
        }
        // Key generation results
        if let Some(rx) = &self.gen_job
            && let Ok(res) = rx.try_recv() {
                self.gen_job = None;
                match res {
                    Ok(mut key) => {
                        key.id = self.vault.new_id();
                        key.created = now();
                        let id = key.id;
                        self.vault.keys.push(key);
                        self.save();
                        self.panel = Panel::Key(id);
                        self.toast(ctx, "Key generated");
                    }
                    Err(e) => self.toast(ctx, e),
                }
            }
        self.poll_panes();
    }

    // ------------------------------------------------------------------ frame

    fn title_bar(&mut self, ui: &mut Ui, r: Rect) {
        let ctx = ui.ctx().clone();
        ui.painter().rect_filled(r, 0.0, TITLE_BG);
        let drag = ui.interact(r, Id::unique("titlebar-drag"), Sense::click_and_drag());
        if drag.drag_started() {
            ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }
        if drag.double_clicked() {
            let max = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!max));
        }
        let cy = r.min.y + s(30.0);
        if icon_button(ui, pos2(r.min.x + s(30.0), cy), s(44.0), "menu", Icon::Menu, TEXT, TITLE_BG).clicked() {
            self.open_popup(Popup::MainMenu, pos2(r.min.x + s(10.0), r.min.y + s(60.0)));
        }
        // Vaults button (left part opens the vault, chevron opens the vault list)
        let vb = rect_xywh(r.min.x + s(60.0), r.min.y + s(8.0), s(208.0), s(44.0));
        let active = self.tab == TabSel::Vaults;
        let main = Rect::from_min_max(vb.min, pos2(vb.min.x + s(164.0), vb.max.y));
        let chev = Rect::from_min_max(pos2(vb.min.x + s(166.0), vb.min.y), vb.max);
        let rm = hit(ui, main, "vaults-tab");
        let rc = hit(ui, chev, "vaults-chev");
        let base = if active { VAULT_BTN } else { TITLE_BG };
        ui.painter().rect_filled(vb, s(10.0), base);
        if rm.hovered() {
            ui.painter().rect_filled(main, s(10.0), HOVER);
        }
        if rc.hovered() {
            ui.painter().rect_filled(chev, s(10.0), HOVER);
        }
        ui.painter().line_segment(
            [pos2(vb.min.x + s(165.0), vb.min.y), pos2(vb.min.x + s(165.0), vb.max.y)],
            Stroke::new(s(3.0), TITLE_BG),
        );
        draw_icon(ui.painter(), Icon::Vault, pos2(vb.min.x + s(23.0), cy), s(20.0), TEXT, base);
        text(ui.painter(), pos2(vb.min.x + s(45.0), cy), Align2::LEFT_CENTER, "Home", semi(s(21.0)), TEXT);
        draw_icon(ui.painter(), Icon::ChevronDown, pos2(chev.center().x, cy), s(18.0), TEXT, base);
        if rm.clicked() {
            self.tab = TabSel::Vaults;
        }
        if rc.clicked() {
            self.open_popup(Popup::Vaults, pos2(vb.min.x, vb.max.y + s(6.0)));
        }
        // SFTP tab
        let sb = rect_xywh(r.min.x + s(278.0), r.min.y + s(8.0), s(119.0), s(44.0));
        let rs = hit(ui, sb, "sftp-tab");
        let sactive = self.tab == TabSel::Sftp;
        let sbase = if sactive { SELECTED } else { VAULT_BTN };
        ui.painter().rect_filled(sb, s(10.0), if rs.hovered() && !sactive { HOVER } else { sbase });
        draw_icon(ui.painter(), Icon::Folder, pos2(sb.min.x + s(22.0), cy), s(19.0), TEXT, sbase);
        text(ui.painter(), pos2(sb.min.x + s(44.0), cy), Align2::LEFT_CENTER, "SFTP", semi(s(21.0)), TEXT);
        if rs.clicked() {
            self.tab = TabSel::Sftp;
        }
        // Session tabs
        let mut x = sb.max.x + s(10.0);
        let right_limit = r.max.x - s(220.0);
        let n = self.sessions.len().max(1) as f32;
        let tab_w = ((right_limit - x - s(50.0)) / n).clamp(s(90.0), s(220.0));
        let mut close_id = None;
        let mut select = None;
        for sess in &self.sessions {
            let tb = rect_xywh(x, r.min.y + s(8.0), tab_w, s(44.0));
            let id = sess.id;
            let resp = hit(ui, tb, ("sess-tab", id));
            let act = self.tab == TabSel::Session(id);
            let base = if act { SELECTED } else { VAULT_BTN };
            ui.painter().rect_filled(tb, s(10.0), if resp.hovered() && !act { HOVER } else { base });
            let icon = match sess.kind {
                SessionKind::Serial => Icon::Serial,
                _ => Icon::Terminal,
            };
            let col = if sess.term.exited { GREY } else { TEXT };
            draw_icon(ui.painter(), icon, pos2(tb.min.x + s(22.0), cy), s(19.0), col, base);
            text_fit(ui, pos2(tb.min.x + s(42.0), cy), Align2::LEFT_CENTER, &sess.title, semi(s(19.0)), col, tab_w - s(80.0));
            let cb = Rect::from_center_size(pos2(tb.max.x - s(20.0), cy), Vec2::splat(s(26.0)));
            let rcl = hit(ui, cb, ("sess-close", id));
            if rcl.hovered() {
                ui.painter().rect_filled(cb, s(6.0), BUTTON_HOVER);
            }
            draw_icon(ui.painter(), Icon::Close, cb.center(), s(12.0), GREY, base);
            if rcl.clicked() || resp.middle_clicked() {
                close_id = Some(id);
            } else if resp.clicked() {
                select = Some(id);
            }
            x += tab_w + s(8.0);
        }
        if let Some(id) = select {
            self.tab = TabSel::Session(id);
            self.focus_term = true;
        }
        if let Some(id) = close_id {
            self.close_session(id);
        }
        let plus_c = pos2(x + s(20.0), cy);
        if icon_button(ui, plus_c, s(40.0), "new-tab", Icon::Plus, GREY, TITLE_BG).clicked() {
            self.open_popup(Popup::NewTab, pos2(plus_c.x - s(20.0), r.min.y + s(58.0)));
        }
        // Right side
        let rx = r.max.x;
        if icon_button(ui, pos2(rx - s(190.0), cy), s(44.0), "bell", Icon::Bell, GREY, TITLE_BG).clicked() {
            self.open_popup(Popup::Notifications, pos2(rx - s(520.0), r.min.y + s(60.0)));
        }
        if icon_button(ui, pos2(rx - s(138.0), cy), s(44.0), "min", Icon::Minimize, GREY, TITLE_BG).clicked() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }
        if icon_button(ui, pos2(rx - s(85.0), cy), s(44.0), "max", Icon::Maximize, GREY, TITLE_BG).clicked() {
            let max = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!max));
        }
        let close_r = Rect::from_center_size(pos2(rx - s(33.0), cy), vec2(s(52.0), s(44.0)));
        let rcl = hit(ui, close_r, "close-window");
        if rcl.hovered() {
            ui.painter().rect_filled(close_r, s(8.0), RED);
        }
        draw_icon(ui.painter(), Icon::Close, close_r.center(), s(24.0) * 0.55, if rcl.hovered() { TEXT } else { GREY }, TITLE_BG);
        if rcl.clicked() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn sidebar(&mut self, ui: &mut Ui, r: Rect) {
        ui.painter().rect_filled(r, 0.0, SIDEBAR_BG);
        ui.painter().line_segment([pos2(r.max.x - 0.5, r.min.y), pos2(r.max.x - 0.5, r.max.y)], Stroke::new(1.0, BORDER));
        for (i, (page, label, icon)) in PAGES.iter().enumerate() {
            let item = rect_xywh(r.min.x + s(9.0), r.min.y + s(16.0) + i as f32 * s(66.0), s(248.0), s(54.0));
            let resp = hit(ui, item, ("side", i));
            let sel = self.page == *page;
            let bg = if sel { SELECTED } else if resp.hovered() { HOVER } else { SIDEBAR_BG };
            if bg != SIDEBAR_BG {
                ui.painter().rect_filled(item, s(10.0), bg);
            }
            draw_icon(ui.painter(), *icon, pos2(item.min.x + s(26.0), item.center().y), s(22.0), TEXT, bg);
            text(ui.painter(), pos2(item.min.x + s(56.0), item.center().y), Align2::LEFT_CENTER, label, semi(s(21.0)), TEXT);
            if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                if self.page != *page {
                    self.close_panel();
                    self.search.clear();
                    self.search_open = false;
                    self.show_history = false;
                }
                self.page = *page;
                if *page == Page::KnownHosts && self.persist {
                    self.known = read_known_hosts();
                }
            }
        }
    }

    /// Header with toolbar (all pages except Logs); returns the content area below it.
    fn header(&mut self, ui: &mut Ui, r: Rect) -> Rect {
        let ctx = ui.ctx().clone();
        if self.page == Page::Logs {
            return r;
        }
        let has_quick = self.page == Page::Hosts;
        let h = if has_quick { s(152.0) } else { s(85.0) };
        let hr = Rect::from_min_max(r.min, pos2(r.max.x, r.min.y + h));
        ui.painter().rect_filled(hr, 0.0, SIDEBAR_BG);
        ui.painter().line_segment([pos2(hr.min.x, hr.max.y - 0.5), pos2(hr.max.x, hr.max.y - 0.5)], Stroke::new(1.0, BORDER));
        let mut ty = hr.min.y + s(24.0);
        if has_quick {
            let bar = Rect::from_min_max(pos2(hr.min.x + s(12.0), hr.min.y + s(13.0)), pos2(hr.max.x - s(12.0), hr.min.y + s(66.0)));
            let cbtn = Rect::from_min_max(pos2(bar.max.x - s(112.0), bar.min.y + s(8.0)), pos2(bar.max.x - s(8.0), bar.max.y - s(8.0)));
            let field_r = Rect::from_min_max(bar.min, pos2(cbtn.min.x - s(4.0), bar.max.y));
            ui.painter().rect_filled(bar, s(9.0), FIELD_BG);
            let hint = if self.vault.hosts.is_empty() {
                "Quick connect: user@server -p port"
            } else {
                "Search hosts, or type user@server -p port"
            };
            let resp = field(ui, field_r, "quick", &mut self.quick, hint, FIELD_BG, None, false, regular(s(20.0)));
            let ready = !parse_quick(&self.quick).address.is_empty();
            let off = Color32::from_rgb(0x3A, 0x40, 0x4B);
            let (fill, hover, col) = if ready { (ACCENT, ACCENT_HOVER, TEXT) } else { (off, off, DIM) };
            let cb = button(ui, cbtn, "quick-connect", "Connect", None, fill, hover, col, semi(s(20.0)));
            if ready && (cb.clicked() || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))) {
                self.quick_connect(&ctx);
            }
            ty = hr.min.y + s(95.0);
        }
        let bh = if has_quick { s(45.0) } else { s(43.0) };
        let x = hr.min.x + s(18.0);
        let (new_label, new_popup) = match self.page {
            Page::Hosts => ("New host", Popup::NewHost),
            Page::Keychain => ("New key", Popup::NewKey),
            Page::PortForwarding => ("New forwarding", Popup::NewForward),
            _ => ("New snippet", Popup::NewSnippet),
        };
        if self.page == Page::KnownHosts {
            let br = rect_xywh(x, ty, s(95.0), bh);
            if button(ui, br, "kh-import", "Import", None, BUTTON, BUTTON_HOVER, TEXT, semi(s(21.0))).on_hover_text("Import from your .ssh folder").clicked() {
                self.import_known_hosts(&ctx);
            }
        } else {
            let tw = ctx.fonts_mut(|f| f.layout_no_wrap(new_label.to_string(), semi(s(21.0)), TEXT).size().x);
            let bw = tw + s(58.0);
            let br = rect_xywh(x, ty, bw, bh);
            let resp = hit(ui, br, "new-main");
            let bfill = if resp.hovered() { BUTTON_HOVER } else { BUTTON };
            ui.painter().rect_filled(br, s(8.0), bfill);
            draw_icon(ui.painter(), Icon::Plus, pos2(br.min.x + s(25.0), br.center().y), s(22.0), TEXT, bfill);
            text(ui.painter(), pos2(br.min.x + s(43.0), br.center().y), Align2::LEFT_CENTER, new_label, semi(s(21.0)), TEXT);
            let chev = rect_xywh(br.max.x + s(4.0), ty, s(45.0), bh);
            let rc = hit(ui, chev, "new-chev");
            let cfill = if rc.hovered() { BUTTON_HOVER } else { BUTTON };
            ui.painter().rect_filled(chev, s(8.0), cfill);
            draw_icon(ui.painter(), Icon::ChevronDown, chev.center(), s(18.0), TEXT, cfill);
            if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                self.new_item(None, &ctx);
            }
            if rc.clicked() {
                self.open_popup(new_popup, pos2(br.min.x, chev.max.y + s(6.0)));
            }
            let gx = chev.max.x + s(18.0);
            match self.page {
                Page::Hosts => {
                    let (r1, w1) = ghost(ui, pos2(gx, ty), bh, "g-terminal", "Terminal", Icon::Terminal);
                    if r1.clicked() {
                        self.open_local_terminal(&ctx);
                    }
                    let (r2, _) = ghost(ui, pos2(gx + w1 + s(8.0), ty), bh, "g-serial", "Serial", Icon::Serial);
                    if r2.clicked() {
                        let ports: Vec<String> = serialport::available_ports().map(|v| v.into_iter().map(|p| p.port_name).collect()).unwrap_or_default();
                        let port = ports.first().cloned().unwrap_or_default();
                        // Common serial default.
                        self.modal = Some(Modal::Serial { port, baud: 9600, ports });
                    }
                }
                Page::Keychain => {
                    let (r1, w1) = ghost(ui, pos2(gx, ty), bh, "g-cert", "Certificate", Icon::Certificate);
                    if r1.clicked() {
                        self.new_item(None, &ctx);
                    }
                    let (r2, w2) = ghost(ui, pos2(gx + w1 + s(8.0), ty), bh, "g-hello", "Windows Hello", Icon::Face);
                    if r2.clicked() {
                        self.generate_hardware_key("Windows Hello key", &ctx);
                    }
                    let (r3, _) = ghost(ui, pos2(gx + w1 + w2 + s(16.0), ty), bh, "g-fido", "FIDO2", Icon::Fido);
                    if r3.clicked() {
                        self.generate_hardware_key("FIDO2 key", &ctx);
                    }
                }
                Page::Snippets => {
                    let (r1, _) = ghost(ui, pos2(gx, ty), bh, "g-history", "Shell History", Icon::Clock);
                    if self.show_history {
                        ui.painter().rect_stroke(r1.rect, s(8.0), Stroke::new(1.0, ACCENT), StrokeKind::Inside);
                    }
                    if r1.clicked() {
                        self.show_history = !self.show_history;
                    }
                }
                _ => {}
            }
        }
        // Right icons
        let cy = ty + bh / 2.0;
        let rx = hr.max.x;
        if self.page == Page::Hosts {
            let av = Rect::from_center_size(pos2(rx - s(65.0), cy), Vec2::splat(s(42.0)));
            let plus = Rect::from_center_size(pos2(rx - s(30.0), cy), vec2(s(40.0), s(42.0)));
            ui.painter().rect_filled(plus, s(9.0), BUTTON);
            ui.painter().rect_filled(av.expand(s(2.0)), s(11.0), ACCENT);
            ui.painter().rect_filled(av, s(9.0), PINK);
            text(ui.painter(), av.center(), Align2::CENTER_CENTER, &self.initial, regular(s(21.0)), TEXT);
            draw_icon(ui.painter(), Icon::Plus, pos2(plus.max.x - s(12.0), cy), s(20.0), TEXT, BUTTON);
            let _ = hit(ui, av, "avatar").on_hover_text("Local workspace on this computer");
            if hit(ui, plus, "share-plus").on_hover_text("New host").clicked() {
                self.new_item(None, &ctx);
            }
            if icon_button(ui, pos2(rx - s(125.0), cy), s(44.0), "sort", Icon::Calendar, TEXT, SIDEBAR_BG).on_hover_text("Sort").clicked() {
                self.open_popup(Popup::Sort, pos2(rx - s(330.0), cy + s(30.0)));
            }
            let tcol = if self.tag_filter.is_some() { ACCENT } else { TEXT };
            if icon_button(ui, pos2(rx - s(185.0), cy), s(44.0), "tags", Icon::Tag, tcol, SIDEBAR_BG).on_hover_text("Filter by tag").clicked() {
                self.open_popup(Popup::Tags, pos2(rx - s(390.0), cy + s(30.0)));
            }
            let gi = if self.grid_view { Icon::Grid } else { Icon::List };
            if icon_button(ui, pos2(rx - s(245.0), cy), s(44.0), "gridlist", gi, TEXT, SIDEBAR_BG).on_hover_text("Grid or list").clicked() {
                self.grid_view = !self.grid_view;
            }
        } else {
            if icon_button(ui, pos2(rx - s(36.0), cy), s(44.0), "sort", Icon::Calendar, TEXT, SIDEBAR_BG).on_hover_text("Sort").clicked() {
                self.open_popup(Popup::Sort, pos2(rx - s(260.0), cy + s(30.0)));
            }
            let gi = if self.grid_view { Icon::Grid } else { Icon::List };
            if icon_button(ui, pos2(rx - s(96.0), cy), s(44.0), "gridlist", gi, TEXT, SIDEBAR_BG).on_hover_text("Grid or list").clicked() {
                self.grid_view = !self.grid_view;
            }
            let sc = pos2(rx - s(156.0), cy);
            if self.search_open {
                let fr = Rect::from_min_max(pos2(sc.x - s(330.0), cy - s(22.0)), pos2(sc.x + s(22.0), cy + s(22.0)));
                let resp = field(ui, fr, "page-search", &mut self.search, "Search", FIELD_BG, None, false, regular(s(19.0)));
                if self.search_open && !resp.has_focus() && self.search.is_empty() && resp.lost_focus() {
                    self.search_open = false;
                }
                if !resp.has_focus() && self.search.is_empty() && ctx.input(|i| i.pointer.any_pressed()) && !resp.hovered() {
                    self.search_open = false;
                }
                if self.search.is_empty() && !resp.has_focus() && !resp.lost_focus() {
                    resp.request_focus();
                }
            } else if icon_button(ui, sc, s(44.0), "search", Icon::Search, TEXT, SIDEBAR_BG).on_hover_text("Search").clicked() {
                self.search_open = true;
            }
        }
        Rect::from_min_max(pos2(r.min.x, hr.max.y), r.max)
    }

    fn new_item(&mut self, variant: Option<&str>, _ctx: &egui::Context) {
        if self.page == Page::Keychain && variant == Some("generate") {
            self.gen_form = GenForm::default();
            self.panel = Panel::Generate;
            return;
        }
        self.close_panel();
        let id = self.vault.new_id();
        let t = now();
        match self.page {
            Page::Hosts => {
                self.vault.hosts.push(Host { id, backspace: "default".into(), created: t, ..Default::default() });
                self.panel = Panel::Host(id);
            }
            Page::Keychain => {
                self.vault.keys.push(Key { id, created: t, ..Default::default() });
                self.panel = Panel::Key(id);
            }
            Page::PortForwarding => {
                let kind = match variant {
                    Some("Remote") => FwKind::Remote,
                    Some("Dynamic") => FwKind::Dynamic,
                    _ => FwKind::Local,
                };
                self.vault.forwards.push(Forward { id, kind, created: t, ..Default::default() });
                self.panel = Panel::Forward(id);
            }
            Page::Snippets => {
                self.vault.snippets.push(Snippet { id, created: t, ..Default::default() });
                self.panel = Panel::Snippet(id);
            }
            _ => {}
        }
        self.save();
    }

    fn import_known_hosts(&mut self, ctx: &egui::Context) {
        let path = dirs::home_dir().map(|h| h.join(".ssh").join("known_hosts"));
        let Some(text) = path.and_then(|p| std::fs::read_to_string(p).ok()) else {
            self.toast(ctx, "No known_hosts file found in your .ssh folder.");
            return;
        };
        let mut list = read_known_hosts();
        let mut added = 0;
        for k in parse_known_hosts(&text) {
            if !list.iter().any(|x| x.line == k.line) {
                list.push(k);
                added += 1;
            }
        }
        write_known_hosts(&list);
        self.known = list;
        self.toast(ctx, format!("Imported {added} known host(s)."));
    }

    fn generate_key(&mut self, ctx: &egui::Context) {
        let f = &self.gen_form;
        let (t, bits) = match f.kind.as_str() {
            "RSA" => ("rsa", Some(f.rsa_bits)),
            "ECDSA" => ("ecdsa", Some(f.ecdsa_bits)),
            _ => ("ed25519", None),
        };
        let label = if f.label.trim().is_empty() { format!("{} key", f.kind) } else { f.label.trim().to_string() };
        let (pass, kind) = (f.passphrase.clone(), f.kind.clone());
        self.spawn_keygen(t.to_string(), bits, pass, label, kind, ctx);
    }

    fn generate_hardware_key(&mut self, label: &str, ctx: &egui::Context) {
        self.toast(ctx, "Follow the Windows security prompt to create the key…");
        self.spawn_keygen("ecdsa-sk".into(), None, String::new(), label.into(), "ECDSA-SK".into(), ctx);
    }

    fn spawn_keygen(&mut self, t: String, bits: Option<u32>, pass: String, label: String, kind: String, ctx: &egui::Context) {
        let (tx, rx) = std::sync::mpsc::channel();
        self.gen_job = Some(rx);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let dir = std::env::temp_dir().join(format!("freeterm-keygen-{}", now()));
            let _ = std::fs::create_dir_all(&dir);
            let file = dir.join("key");
            let mut cmd = std::process::Command::new("ssh-keygen.exe");
            cmd.arg("-q").arg("-t").arg(&t).arg("-f").arg(&file).arg("-N").arg(&pass).arg("-C").arg(&label);
            // KDF rounds for the private key file.
            cmd.arg("-a").arg("100");
            if let Some(b) = bits {
                cmd.arg("-b").arg(b.to_string());
            }
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                if t != "ecdsa-sk" {
                    cmd.creation_flags(0x08000000);
                }
            }
            let res = match cmd.output() {
                Ok(out) if out.status.success() => {
                    let private_key = std::fs::read_to_string(&file).unwrap_or_default();
                    let public_key = std::fs::read_to_string(dir.join("key.pub")).unwrap_or_default();
                    if private_key.is_empty() {
                        Err("Key generation failed".to_string())
                    } else {
                        Ok(Key { label, private_key, public_key: public_key.trim().to_string(), passphrase: pass, kind, ..Default::default() })
                    }
                }
                Ok(out) => Err(format!("Key generation failed: {}", String::from_utf8_lossy(&out.stderr).trim())),
                Err(e) => Err(format!("ssh-keygen is not available: {e}")),
            };
            let _ = std::fs::remove_dir_all(&dir);
            let _ = tx.send(res);
            ctx.request_repaint();
        });
    }

    // ------------------------------------------------------------------ pages

    fn sorted<T, F: Fn(&T) -> (String, u64)>(&self, items: &[T], key: F) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..items.len()).collect();
        let q = self.search.to_lowercase();
        idx.retain(|&i| q.is_empty() || key(&items[i]).0.to_lowercase().contains(&q));
        idx.sort_by(|&a, &b| {
            let (la, ta) = key(&items[a]);
            let (lb, tb) = key(&items[b]);
            match self.sort {
                Sort::AZ => la.to_lowercase().cmp(&lb.to_lowercase()),
                Sort::ZA => lb.to_lowercase().cmp(&la.to_lowercase()),
                Sort::Newest => tb.cmp(&ta),
                Sort::Oldest => ta.cmp(&tb),
            }
        });
        idx
    }

    /// Lays out cards in a grid (or one column in list view) and returns their rects.
    fn card_rects(&self, area: Rect, n: usize, top: f32) -> Vec<Rect> {
        let gap = s(20.0);
        let w = area.width() - s(46.0) * 2.0;
        let cols = if self.grid_view { (((w + gap) / (s(420.0) + gap)).floor() as usize).max(1) } else { 1 };
        let cw = (w - gap * (cols as f32 - 1.0)) / cols as f32;
        let ch = s(88.0);
        (0..n)
            .map(|i| {
                let (row, col) = (i / cols, i % cols);
                rect_xywh(area.min.x + s(46.0) + col as f32 * (cw + gap), top + row as f32 * (ch + s(16.0)), cw, ch)
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn card(ui: &mut Ui, r: Rect, id: impl std::hash::Hash + std::fmt::Debug, icon: Icon, icon_bg: Color32, title: &str, sub: &str, selected: bool) -> egui::Response {
        let resp = hit(ui, r, id);
        let p = ui.painter();
        p.rect_filled(r, s(12.0), if resp.hovered() { CARD_HOVER } else { CARD });
        if selected {
            p.rect_stroke(r, s(12.0), Stroke::new(s(3.0), ACCENT), StrokeKind::Inside);
        }
        let ib = Rect::from_center_size(pos2(r.min.x + s(48.0), r.center().y), Vec2::splat(s(60.0)));
        p.rect_filled(ib, s(10.0), icon_bg);
        draw_icon(p, icon, ib.center(), s(28.0), TEXT, icon_bg);
        let tx = r.min.x + s(92.0);
        let maxw = r.width() - s(92.0) - s(60.0);
        let tcol = if title.starts_with("Enter IP") { GREY } else { TEXT };
        text_fit(ui, pos2(tx, r.center().y - s(11.0)), Align2::LEFT_CENTER, title, semi(s(20.0)), tcol, maxw);
        text_fit(ui, pos2(tx, r.center().y + s(14.0)), Align2::LEFT_CENTER, sub, regular(s(16.0)), GREY, maxw);
        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    }

    fn section_title(ui: &Ui, pos: Pos2, t: &str) {
        text(ui.painter(), pos, Align2::LEFT_CENTER, t, bold(s(21.0)), TEXT);
    }

    fn hosts_page(&mut self, ui: &mut Ui, area: Rect) {
        let ctx = ui.ctx().clone();
        if self.vault.hosts.is_empty() {
            let y = empty_screen(ui, area, Icon::Hosts, "Add your first server", "Add a server once, then open it whenever you need it.", s(46.0) + s(52.0) + s(31.0) + s(53.0));
            let w = s(577.0).min(area.width() - s(60.0));
            let fr = rect_xywh(area.center().x - w / 2.0, y + s(34.0), w, s(52.0));
            let resp = field(ui, fr, "create-host", &mut self.new_host_addr, "Server address", CONTENT_BG, Some(FIELD_BORDER), false, regular(s(20.0)));
            let br = rect_xywh(fr.min.x, fr.max.y + s(31.0), w, s(53.0));
            let b = button(ui, br, "create-continue", "Continue", None, ACCENT, ACCENT_HOVER, TEXT, semi(s(20.0)));
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if b.clicked() || enter {
                let id = self.vault.new_id();
                let addr = self.new_host_addr.trim().to_string();
                self.vault.hosts.push(Host { id, address: addr, backspace: "default".into(), created: now(), ..Default::default() });
                self.new_host_addr.clear();
                self.panel = Panel::Host(id);
                self.save();
            }
            return;
        }
        // The quick bar text also filters the host list (unless it is an ssh command).
        let q = self.quick.trim().to_lowercase();
        let filter_text = if q.starts_with("ssh ") { String::new() } else { q };
        let mut groups: Vec<String> = self.vault.hosts.iter().map(|h| h.group.trim().to_string()).filter(|g| !g.is_empty()).collect();
        groups.sort();
        groups.dedup();
        let mut hosts: Vec<Host> = self
            .vault
            .hosts
            .iter()
            .filter(|h| filter_text.is_empty() || h.display_name().to_lowercase().contains(&filter_text) || h.address.to_lowercase().contains(&filter_text))
            .filter(|h| self.tag_filter.as_ref().is_none_or(|t| h.tags.contains(t)))
            .filter(|h| match &self.group_filter {
                Some(g) => h.group.trim() == g,
                None => !filter_text.is_empty() || h.group.trim().is_empty(),
            })
            .cloned()
            .collect();
        match self.sort {
            Sort::AZ => hosts.sort_by_key(|h| h.display_name().to_lowercase()),
            Sort::ZA => {
                hosts.sort_by_key(|h| h.display_name().to_lowercase());
                hosts.reverse()
            }
            Sort::Newest => hosts.sort_by_key(|h| std::cmp::Reverse(h.created)),
            Sort::Oldest => hosts.sort_by_key(|h| h.created),
        }
        let mut connect = None;
        let mut edit = None;
        let mut remove = None;
        let mut duplicate = None;
        let mut sftp_open = None;
        egui::ScrollArea::vertical().id_salt("hosts-scroll").auto_shrink([false, false]).show(ui, |ui| {
            let base = ui.max_rect().min.y;
            let mut yy = base + s(43.0);
            if let Some(g) = self.group_filter.clone() {
                if icon_button(ui, pos2(area.min.x + s(60.0), yy), s(36.0), "group-back", Icon::ChevronLeft, TEXT, CONTENT_BG).clicked() {
                    self.group_filter = None;
                }
                Self::section_title(ui, pos2(area.min.x + s(90.0), yy), &g);
                yy += s(38.0);
            } else if !groups.is_empty() && filter_text.is_empty() {
                Self::section_title(ui, pos2(area.min.x + s(46.0), yy), "Groups");
                yy += s(38.0);
                let rects = self.card_rects(area, groups.len(), yy);
                for (g, r) in groups.iter().zip(rects.iter()) {
                    let n = self.vault.hosts.iter().filter(|h| h.group.trim() == g).count();
                    let sub = format!("{n} host{}", if n == 1 { "" } else { "s" });
                    if Self::card(ui, *r, ("group", g), Icon::Group, BUTTON, g, &sub, false).clicked() {
                        self.group_filter = Some(g.clone());
                    }
                }
                yy = rects.last().map(|r| r.max.y).unwrap_or(yy) + s(40.0);
            }
            Self::section_title(ui, pos2(area.min.x + s(46.0), yy), "Hosts");
            yy += s(38.0);
            let rects = self.card_rects(area, hosts.len(), yy);
            for (h, r) in hosts.iter().zip(rects.iter()) {
                let mut sub = "ssh".to_string();
                if !h.username.is_empty() {
                    sub.push_str(", ");
                    sub.push_str(&h.username);
                }
                if !h.tags.is_empty() {
                    sub.push_str("  ·  ");
                    sub.push_str(&h.tags.join(", "));
                }
                let sel = self.panel == Panel::Host(h.id);
                let resp = Self::card(ui, *r, ("host", h.id), Icon::Hosts, HOST_ICON, &h.display_name(), &sub, sel);
                let er = Rect::from_center_size(pos2(r.max.x - s(32.0), r.center().y), Vec2::splat(s(40.0)));
                let mut edit_clicked = false;
                if resp.hovered() || sel || ui.rect_contains_pointer(er) {
                    edit_clicked = icon_button(ui, er.center(), s(40.0), &format!("edit-{}", h.id), Icon::More, GREY, CARD_HOVER).on_hover_text("Edit").clicked();
                }
                if edit_clicked {
                    edit = Some(h.id);
                } else if resp.clicked() {
                    connect = Some(h.id);
                }
                resp.context_menu(|ui| {
                    if ui.button("Connect").clicked() {
                        connect = Some(h.id);
                        ui.close();
                    }
                    if ui.button("Open in SFTP").clicked() {
                        sftp_open = Some(h.id);
                        ui.close();
                    }
                    if ui.button("Edit").clicked() {
                        edit = Some(h.id);
                        ui.close();
                    }
                    if ui.button("Duplicate").clicked() {
                        duplicate = Some(h.id);
                        ui.close();
                    }
                    if ui.button("Remove").clicked() {
                        remove = Some(h.id);
                        ui.close();
                    }
                });
            }
            let end = rects.last().map(|r| r.max.y).unwrap_or(yy) + s(40.0);
            ui.allocate_space(vec2(ui.available_width(), (end - base).max(0.0)));
        });
        if let Some(id) = connect
            && let Some(h) = self.vault.host(id).cloned() {
                self.connect_host(h, &ctx);
            }
        if let Some(id) = edit {
            self.close_panel();
            self.panel = Panel::Host(id);
        }
        if let Some(id) = duplicate
            && let Some(mut h) = self.vault.host(id).cloned() {
                h.id = self.vault.new_id();
                h.label = format!("{} (copy)", h.display_name());
                h.created = now();
                self.vault.hosts.push(h);
                self.save();
            }
        if let Some(id) = remove {
            self.vault.hosts.retain(|h| h.id != id);
            if self.panel == Panel::Host(id) {
                self.panel = Panel::None;
            }
            self.save();
        }
        if let Some(id) = sftp_open
            && let Some(h) = self.vault.host(id).cloned() {
                self.tab = TabSel::Sftp;
                if matches!(self.panes[0].state, PaneState::Empty) {
                    self.open_pane_local(0);
                }
                self.open_pane_remote(1, &h, &ctx);
            }
    }

    fn keychain_page(&mut self, ui: &mut Ui, area: Rect) {
        if self.vault.keys.is_empty() {
            empty_screen(ui, area, Icon::Key, "Add a key", "Keep SSH keys here and reuse them across your hosts.", 0.0);
            return;
        }
        let idx = self.sorted(&self.vault.keys, |k| (k.label.clone(), k.created));
        let mut open = None;
        let mut remove = None;
        egui::ScrollArea::vertical().id_salt("keys-scroll").auto_shrink([false, false]).show(ui, |ui| {
            let base = ui.max_rect().min.y;
            Self::section_title(ui, pos2(area.min.x + s(46.0), base + s(43.0)), "Keys");
            let rects = self.card_rects(area, idx.len(), base + s(81.0));
            for (&i, r) in idx.iter().zip(rects.iter()) {
                let k = &self.vault.keys[i];
                let title = if k.label.is_empty() { "Untitled key" } else { k.label.as_str() };
                let sub = format!("Type {}", if k.kind.is_empty() { key_type_of(&k.public_key) } else { k.kind.clone() });
                let resp = Self::card(ui, *r, ("key", k.id), Icon::Key, BUTTON, title, &sub, self.panel == Panel::Key(k.id));
                if resp.clicked() {
                    open = Some(k.id);
                }
                resp.context_menu(|ui| {
                    if ui.button("Copy public key").clicked() {
                        ui.ctx().copy_text(k.public_key.clone());
                        ui.close();
                    }
                    if ui.button("Remove").clicked() {
                        remove = Some(k.id);
                        ui.close();
                    }
                });
            }
            let end = rects.last().map(|r| r.max.y).unwrap_or(base) + s(40.0);
            ui.allocate_space(vec2(ui.available_width(), end - base));
        });
        if let Some(id) = open {
            self.close_panel();
            self.panel = Panel::Key(id);
        }
        if let Some(id) = remove {
            self.vault.keys.retain(|k| k.id != id);
            for h in self.vault.hosts.iter_mut() {
                if h.key_id == Some(id) {
                    h.key_id = None;
                }
            }
            if self.panel == Panel::Key(id) {
                self.panel = Panel::None;
            }
            self.save();
        }
    }

    fn forwarding_page(&mut self, ui: &mut Ui, area: Rect) {
        let ctx = ui.ctx().clone();
        if self.vault.forwards.is_empty() {
            empty_screen(ui, area, Icon::Forward, "Create a tunnel", "Reach remote databases and services through an SSH tunnel.", 0.0);
            return;
        }
        let idx = self.sorted(&self.vault.forwards, |f| (if f.label.is_empty() { f.summary() } else { f.label.clone() }, f.created));
        let mut open = None;
        let mut toggle = None;
        let mut remove = None;
        egui::ScrollArea::vertical().id_salt("fw-scroll").auto_shrink([false, false]).show(ui, |ui| {
            let base = ui.max_rect().min.y;
            Self::section_title(ui, pos2(area.min.x + s(46.0), base + s(43.0)), "Tunnels");
            let rects = self.card_rects(area, idx.len(), base + s(81.0));
            for (&i, r) in idx.iter().zip(rects.iter()) {
                let f = &self.vault.forwards[i];
                let running = self.forwards.get(&f.id).is_some_and(|t| !t.exited);
                let title = if f.label.is_empty() { f.summary() } else { f.label.clone() };
                let host = f.host_id.and_then(|h| self.vault.host(h)).map(|h| h.display_name()).unwrap_or_else(|| "no host".into());
                let sub = format!("{} · {} · {}", f.kind.name(), host, if running { "active" } else { "stopped" });
                let resp = Self::card(ui, *r, ("fw", f.id), Icon::Forward, if running { GREEN } else { BUTTON }, &title, &sub, self.panel == Panel::Forward(f.id));
                let pc = pos2(r.max.x - s(34.0), r.center().y);
                let pb = icon_button(ui, pc, s(44.0), &format!("fw-play-{}", f.id), if running { Icon::Stop } else { Icon::Play }, if running { RED } else { GREEN }, CARD);
                if pb.on_hover_text(if running { "Stop" } else { "Start" }).clicked() {
                    toggle = Some(f.id);
                } else if resp.clicked() {
                    open = Some(f.id);
                }
                resp.context_menu(|ui| {
                    if ui.button("Remove").clicked() {
                        remove = Some(f.id);
                        ui.close();
                    }
                });
            }
            let end = rects.last().map(|r| r.max.y).unwrap_or(base) + s(40.0);
            ui.allocate_space(vec2(ui.available_width(), end - base));
        });
        if let Some(id) = open {
            self.close_panel();
            self.panel = Panel::Forward(id);
        }
        if let Some(id) = toggle {
            self.toggle_forward(id, &ctx);
        }
        if let Some(id) = remove {
            if let Some(mut t) = self.forwards.remove(&id) {
                t.kill();
            }
            self.vault.forwards.retain(|f| f.id != id);
            if self.panel == Panel::Forward(id) {
                self.panel = Panel::None;
            }
            self.save();
        }
    }

    fn toggle_forward(&mut self, id: u64, ctx: &egui::Context) {
        if let Some(t) = self.forwards.get_mut(&id) {
            let was_running = !t.exited;
            t.kill();
            self.forwards.remove(&id);
            if was_running {
                self.toast(ctx, "Port forwarding stopped");
                return;
            }
        }
        let Some(f) = self.vault.forwards.iter().find(|f| f.id == id).cloned() else { return };
        let Some(host) = f.host_id.and_then(|h| self.vault.host(h)).cloned() else {
            self.toast(ctx, "Choose a host for this rule first.");
            self.panel = Panel::Forward(id);
            return;
        };
        if f.port.trim().is_empty() || (f.kind != FwKind::Dynamic && (f.dest_address.trim().is_empty() || f.dest_port.trim().is_empty())) {
            self.toast(ctx, "Fill in the ports and destination first.");
            self.panel = Panel::Forward(id);
            return;
        }
        let mut cmd = self.ssh_command(&host);
        let bind = f.bind_address.trim();
        let spec = match f.kind {
            FwKind::Local | FwKind::Remote => {
                if bind.is_empty() {
                    format!("{}:{}:{}", f.port.trim(), f.dest_address.trim(), f.dest_port.trim())
                } else {
                    format!("{}:{}:{}:{}", bind, f.port.trim(), f.dest_address.trim(), f.dest_port.trim())
                }
            }
            FwKind::Dynamic => {
                if bind.is_empty() { f.port.trim().to_string() } else { format!("{}:{}", bind, f.port.trim()) }
            }
        };
        cmd.arg("-N");
        cmd.arg(match f.kind {
            FwKind::Local => "-L",
            FwKind::Remote => "-R",
            FwKind::Dynamic => "-D",
        });
        cmd.arg(spec);
        match Term::spawn(cmd, ctx) {
            Ok(mut t) => {
                t.auto_password(&host.password);
                if let Some(k) = host.key_id.and_then(|i| self.vault.key(i)) {
                    t.auto_passphrase(&k.passphrase);
                }
                self.forwards.insert(id, t);
                self.toast(ctx, "Port forwarding started");
            }
            Err(e) => self.toast(ctx, format!("Could not start: {e}")),
        }
    }

    fn snippets_page(&mut self, ui: &mut Ui, area: Rect) {
        let ctx = ui.ctx().clone();
        if self.show_history {
            let mut run = None;
            let mut save = None;
            let mut clear_history = false;
            egui::ScrollArea::vertical().id_salt("hist-scroll").auto_shrink([false, false]).show(ui, |ui| {
                let base = ui.max_rect().min.y;
                Self::section_title(ui, pos2(area.min.x + s(46.0), base + s(43.0)), "Shell History");
                if !self.vault.shell_history.is_empty() {
                    let cb = rect_xywh(area.max.x - s(46.0) - s(110.0), base + s(22.0), s(110.0), s(40.0));
                    if button(ui, cb, "hist-clear", "Clear", None, BUTTON, BUTTON_HOVER, TEXT, semi(s(18.0))).clicked() {
                        clear_history = true;
                    }
                }
                let mut y = base + s(81.0);
                if self.vault.shell_history.is_empty() {
                    text(ui.painter(), pos2(area.min.x + s(46.0), y + s(10.0)), Align2::LEFT_TOP, "Commands you type in terminals will appear here.", regular(s(19.0)), GREY);
                    y += s(60.0);
                }
                let q = self.search.to_lowercase();
                for (i, cmd) in self.vault.shell_history.iter().enumerate().rev() {
                    if !q.is_empty() && !cmd.to_lowercase().contains(&q) {
                        continue;
                    }
                    let r = rect_xywh(area.min.x + s(46.0), y, area.width() - s(92.0), s(56.0));
                    let resp = hit(ui, r, ("hist", i));
                    ui.painter().rect_filled(r, s(10.0), if resp.hovered() { CARD_HOVER } else { CARD });
                    text_fit(ui, pos2(r.min.x + s(20.0), r.center().y), Align2::LEFT_CENTER, cmd, egui::FontId::monospace(s(18.0)), TEXT, r.width() - s(260.0));
                    let b1 = rect_xywh(r.max.x - s(230.0), r.min.y + s(9.0), s(110.0), s(38.0));
                    let b2 = rect_xywh(r.max.x - s(112.0), r.min.y + s(9.0), s(100.0), s(38.0));
                    if button(ui, b1, &format!("hs-save-{i}"), "Save", None, BUTTON, BUTTON_HOVER, TEXT, semi(s(18.0))).clicked() {
                        save = Some(cmd.clone());
                    }
                    if button(ui, b2, &format!("hs-run-{i}"), "Run", None, ACCENT, ACCENT_HOVER, TEXT, semi(s(18.0))).clicked() {
                        run = Some(cmd.clone());
                    }
                    y += s(66.0);
                }
                ui.allocate_space(vec2(ui.available_width(), y - base + s(20.0)));
            });
            if clear_history {
                self.vault.shell_history.clear();
                self.save();
            }
            if let Some(c) = run {
                self.run_snippet(c, &ctx);
            }
            if let Some(c) = save {
                let id = self.vault.new_id();
                self.vault.snippets.push(Snippet { id, label: c.clone(), script: c, created: now() });
                self.save();
                self.show_history = false;
                self.panel = Panel::Snippet(id);
            }
            return;
        }
        if self.vault.snippets.is_empty() {
            empty_screen(ui, area, Icon::Braces, "New snippet", "Store commands you run often and send them to any terminal.", 0.0);
            return;
        }
        let idx = self.sorted(&self.vault.snippets, |sn| (format!("{} {}", sn.label, sn.script), sn.created));
        let mut open = None;
        let mut run = None;
        let mut remove = None;
        egui::ScrollArea::vertical().id_salt("snip-scroll").auto_shrink([false, false]).show(ui, |ui| {
            let base = ui.max_rect().min.y;
            Self::section_title(ui, pos2(area.min.x + s(46.0), base + s(43.0)), "Snippets");
            let rects = self.card_rects(area, idx.len(), base + s(81.0));
            for (&i, r) in idx.iter().zip(rects.iter()) {
                let sn = &self.vault.snippets[i];
                let title = if sn.label.is_empty() { "Untitled snippet" } else { sn.label.as_str() };
                let first = sn.script.lines().next().unwrap_or("").to_string();
                let resp = Self::card(ui, *r, ("snip", sn.id), Icon::Braces, BUTTON, title, &first, self.panel == Panel::Snippet(sn.id));
                let pc = pos2(r.max.x - s(34.0), r.center().y);
                if icon_button(ui, pc, s(44.0), &format!("snip-run-{}", sn.id), Icon::Play, GREEN, CARD).on_hover_text("Run").clicked() {
                    run = Some(sn.script.clone());
                } else if resp.clicked() {
                    open = Some(sn.id);
                }
                resp.context_menu(|ui| {
                    if ui.button("Run").clicked() {
                        run = Some(sn.script.clone());
                        ui.close();
                    }
                    if ui.button("Remove").clicked() {
                        remove = Some(sn.id);
                        ui.close();
                    }
                });
            }
            let end = rects.last().map(|r| r.max.y).unwrap_or(base) + s(40.0);
            ui.allocate_space(vec2(ui.available_width(), end - base));
        });
        if let Some(id) = open {
            self.close_panel();
            self.panel = Panel::Snippet(id);
        }
        if let Some(sc) = run {
            self.run_snippet(sc, &ctx);
        }
        if let Some(id) = remove {
            self.vault.snippets.retain(|sn| sn.id != id);
            if self.panel == Panel::Snippet(id) {
                self.panel = Panel::None;
            }
            self.save();
        }
    }

    fn known_hosts_page(&mut self, ui: &mut Ui, area: Rect) {
        if self.known.is_empty() {
            empty_screen(ui, area, Icon::Fingerprint, "No trusted servers yet", "Server fingerprints you have accepted are listed here.", 0.0);
            return;
        }
        let q = self.search.to_lowercase();
        let list: Vec<(usize, KnownHost)> = self.known.iter().cloned().enumerate().filter(|(_, k)| q.is_empty() || k.host.to_lowercase().contains(&q)).collect();
        let mut remove = None;
        egui::ScrollArea::vertical().id_salt("kh-scroll").auto_shrink([false, false]).show(ui, |ui| {
            let base = ui.max_rect().min.y;
            Self::section_title(ui, pos2(area.min.x + s(46.0), base + s(43.0)), "Known Hosts");
            let rects = self.card_rects(area, list.len(), base + s(81.0));
            for ((i, k), r) in list.iter().zip(rects.iter()) {
                let resp = Self::card(ui, *r, ("kh", *i), Icon::Fingerprint, BUTTON, &k.host, &k.key_type, false);
                let pc = pos2(r.max.x - s(34.0), r.center().y);
                let near = ui.rect_contains_pointer(Rect::from_center_size(pc, Vec2::splat(s(44.0))));
                if (resp.hovered() || near) && icon_button(ui, pc, s(44.0), &format!("kh-del-{i}"), Icon::Trash, GREY, CARD_HOVER).on_hover_text("Remove").clicked() {
                    remove = Some(*i);
                }
            }
            let end = rects.last().map(|r| r.max.y).unwrap_or(base) + s(40.0);
            ui.allocate_space(vec2(ui.available_width(), end - base));
        });
        if let Some(i) = remove {
            self.known.remove(i);
            write_known_hosts(&self.known);
        }
    }

    fn logs_page(&mut self, ui: &mut Ui, area: Rect) {
        if self.vault.logs.is_empty() {
            empty_screen(ui, area, Icon::Clock, "No sessions yet", "Each SSH, serial or local session you open is recorded here.", 0.0);
            return;
        }
        let mut clear = false;
        egui::ScrollArea::vertical().id_salt("logs-scroll").auto_shrink([false, false]).show(ui, |ui| {
            let base = ui.max_rect().min.y;
            Self::section_title(ui, pos2(area.min.x + s(46.0), base + s(43.0)), "Logs");
            let cb = rect_xywh(area.max.x - s(46.0) - s(110.0), base + s(22.0), s(110.0), s(40.0));
            if button(ui, cb, "logs-clear", "Clear", None, BUTTON, BUTTON_HOVER, TEXT, semi(s(18.0))).clicked() {
                clear = true;
            }
            let mut y = base + s(81.0);
            for l in self.vault.logs.iter().rev() {
                let r = rect_xywh(area.min.x + s(46.0), y, area.width() - s(92.0), s(76.0));
                ui.painter().rect_filled(r, s(12.0), CARD);
                let ib = Rect::from_center_size(pos2(r.min.x + s(42.0), r.center().y), Vec2::splat(s(50.0)));
                ui.painter().rect_filled(ib, s(10.0), BUTTON);
                draw_icon(ui.painter(), Icon::Clock, ib.center(), s(24.0), TEXT, BUTTON);
                let who = if l.user.is_empty() { l.address.clone() } else { format!("{}@{}", l.user, l.address) };
                text_fit(ui, pos2(r.min.x + s(84.0), r.center().y - s(11.0)), Align2::LEFT_CENTER, &l.host, semi(s(20.0)), TEXT, r.width() * 0.45);
                text(ui.painter(), pos2(r.min.x + s(84.0), r.center().y + s(14.0)), Align2::LEFT_CENTER, &format!("{} · {}", l.protocol, who), regular(s(16.0)), GREY);
                let dur = match l.ended {
                    Some(e) => {
                        let d = e.saturating_sub(l.started);
                        format!("{}m {}s", d / 60, d % 60)
                    }
                    None => "active".into(),
                };
                text(ui.painter(), pos2(r.max.x - s(24.0), r.center().y - s(11.0)), Align2::RIGHT_CENTER, &format_time(l.started), regular(s(17.0)), TEXT);
                text(ui.painter(), pos2(r.max.x - s(24.0), r.center().y + s(14.0)), Align2::RIGHT_CENTER, &dur, regular(s(16.0)), GREY);
                y += s(88.0);
            }
            ui.allocate_space(vec2(ui.available_width(), y - base + s(20.0)));
        });
        if clear {
            self.vault.logs.clear();
            for sess in self.sessions.iter_mut() {
                sess.log = None;
            }
            self.save();
        }
    }

    // ------------------------------------------------------------------ side panel

    fn side_panel(&mut self, ui: &mut Ui, r: Rect) {
        let ctx = ui.ctx().clone();
        ui.painter().rect_filled(r, 0.0, SIDEBAR_BG);
        ui.painter().line_segment([pos2(r.min.x + 0.5, r.min.y), pos2(r.min.x + 0.5, r.max.y)], Stroke::new(1.0, BORDER));
        let title = match self.panel {
            Panel::Host(id) => {
                if self.vault.host(id).is_some_and(|h| h.created + 2 < now() && (!h.address.is_empty() || !h.label.is_empty())) { "Edit Host" } else { "New Host" }
            }
            Panel::Key(_) => "Key",
            Panel::Forward(_) => "Tunnels",
            Panel::Snippet(_) => "Snippet",
            Panel::Generate => "Generate Key",
            Panel::None => "",
        };
        let hy = r.min.y + s(42.0);
        text(ui.painter(), pos2(r.min.x + s(23.0), hy), Align2::LEFT_CENTER, title, bold(s(21.0)), TEXT);
        if icon_button(ui, pos2(r.max.x - s(30.0), hy), s(44.0), "panel-close", Icon::Collapse, TEXT, SIDEBAR_BG).on_hover_text("Close").clicked() {
            self.close_panel();
            return;
        }
        if self.panel != Panel::Generate && icon_button(ui, pos2(r.max.x - s(83.0), hy), s(44.0), "panel-more", Icon::More, TEXT, SIDEBAR_BG).clicked() {
            self.open_popup(Popup::PanelMore, pos2(r.max.x - s(300.0), hy + s(30.0)));
        }
        let body = Rect::from_min_max(pos2(r.min.x, r.min.y + s(85.0)), pos2(r.max.x, r.max.y - s(100.0)));
        let foot = Rect::from_min_max(pos2(r.min.x + s(23.0), r.max.y - s(83.0)), pos2(r.max.x - s(23.0), r.max.y - s(30.0)));
        let mut changed = false;
        let panel = self.panel;
        ui.scope_builder(UiBuilder::new().max_rect(body).id_salt("panel"), |ui| {
            egui::ScrollArea::vertical().id_salt(("panel-scroll", panel_key(&panel))).auto_shrink([false, false]).show(ui, |ui| {
                let m = s(23.0) as i8;
                egui::Frame::new().inner_margin(egui::Margin { left: m, right: m, top: 0, bottom: m }).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = s(23.0);
                    match panel {
                        Panel::Host(id) => changed = self.host_form(ui, id),
                        Panel::Key(id) => changed = self.key_form(ui, id),
                        Panel::Forward(id) => changed = self.forward_form(ui, id),
                        Panel::Snippet(id) => changed = self.snippet_form(ui, id),
                        Panel::Generate => self.generate_form(ui),
                        Panel::None => {}
                    }
                });
            });
        });
        let (label, enabled) = match self.panel {
            Panel::Host(id) => ("Connect", self.vault.host(id).is_some_and(|h| !h.address.trim().is_empty())),
            Panel::Snippet(id) => ("Run", self.vault.snippet(id).is_some_and(|s| !s.script.trim().is_empty())),
            Panel::Forward(id) => (if self.forwards.get(&id).is_some_and(|t| !t.exited) { "Stop" } else { "Start" }, true),
            Panel::Generate => (if self.gen_job.is_some() { "Generating…" } else { "Generate & Save" }, self.gen_job.is_none()),
            Panel::Key(_) => ("Done", true),
            Panel::None => ("", false),
        };
        let (fill, hover, col) = if enabled { (ACCENT, ACCENT_HOVER, TEXT) } else { (BUTTON, BUTTON, DIM) };
        let clicked = button(ui, foot, "panel-foot", label, None, fill, hover, col, semi(s(21.0))).clicked() && enabled;
        if changed {
            self.save();
        }
        if !clicked {
            return;
        }
        match self.panel {
            Panel::Host(id) => {
                if let Some(h) = self.vault.host(id).cloned() {
                    self.connect_host(h, &ctx);
                }
            }
            Panel::Snippet(id) => {
                if let Some(sn) = self.vault.snippet(id).cloned() {
                    self.run_snippet(sn.script, &ctx);
                }
            }
            Panel::Forward(id) => self.toggle_forward(id, &ctx),
            Panel::Generate => self.generate_key(&ctx),
            Panel::Key(_) => self.close_panel(),
            Panel::None => {}
        }
    }

    fn close_panel(&mut self) {
        // Drop items that were created but left empty.
        match self.panel {
            Panel::Host(id) => {
                if self.vault.host(id).is_some_and(|h| h.address.trim().is_empty() && h.label.trim().is_empty()) {
                    self.vault.hosts.retain(|h| h.id != id);
                }
            }
            Panel::Key(id) => {
                if self.vault.key(id).is_some_and(|k| k.private_key.trim().is_empty() && k.label.trim().is_empty() && k.certificate.trim().is_empty()) {
                    self.vault.keys.retain(|k| k.id != id);
                }
            }
            Panel::Snippet(id)
                if self.vault.snippet(id).is_some_and(|sn| sn.script.trim().is_empty() && sn.label.trim().is_empty()) => {
                    self.vault.snippets.retain(|sn| sn.id != id);
                }
            _ => {}
        }
        self.panel = Panel::None;
        self.save();
    }

    fn delete_panel_item(&mut self) {
        match self.panel {
            Panel::Host(id) => self.vault.hosts.retain(|h| h.id != id),
            Panel::Key(id) => self.vault.keys.retain(|k| k.id != id),
            Panel::Forward(id) => {
                if let Some(mut t) = self.forwards.remove(&id) {
                    t.kill();
                }
                self.vault.forwards.retain(|f| f.id != id)
            }
            Panel::Snippet(id) => self.vault.snippets.retain(|sn| sn.id != id),
            _ => {}
        }
        self.panel = Panel::None;
        self.save();
    }

    fn duplicate_panel_item(&mut self) {
        let nid = self.vault.new_id();
        match self.panel {
            Panel::Host(id) => {
                if let Some(mut h) = self.vault.host(id).cloned() {
                    h.id = nid;
                    h.label = format!("{} (copy)", h.display_name());
                    self.vault.hosts.push(h);
                    self.panel = Panel::Host(nid);
                }
            }
            Panel::Snippet(id) => {
                if let Some(mut sn) = self.vault.snippet(id).cloned() {
                    sn.id = nid;
                    sn.label = format!("{} (copy)", sn.label);
                    self.vault.snippets.push(sn);
                    self.panel = Panel::Snippet(nid);
                }
            }
            Panel::Forward(id) => {
                if let Some(mut f) = self.vault.forwards.iter().find(|f| f.id == id).cloned() {
                    f.id = nid;
                    f.label = format!("{} (copy)", f.label);
                    self.vault.forwards.push(f);
                    self.panel = Panel::Forward(nid);
                }
            }
            Panel::Key(id) => {
                if let Some(mut k) = self.vault.key(id).cloned() {
                    k.id = nid;
                    k.label = format!("{} (copy)", k.label);
                    self.vault.keys.push(k);
                    self.panel = Panel::Key(nid);
                }
            }
            _ => {}
        }
        self.save();
    }

    fn host_form(&mut self, ui: &mut Ui, id: u64) -> bool {
        let keys: Vec<(u64, String)> = self.vault.keys.iter().map(|k| (k.id, if k.label.is_empty() { "Untitled key".into() } else { k.label.clone() })).collect();
        let snippets: Vec<(u64, String)> = self.vault.snippets.iter().map(|sn| (sn.id, if sn.label.is_empty() { sn.script.clone() } else { sn.label.clone() })).collect();
        let show_pw = &mut self.show_password;
        let Some(h) = self.vault.hosts.iter_mut().find(|h| h.id == id) else { return false };
        let mut changed = false;
        vault_card(ui);
        section(ui, Some("Address"), |ui| {
            let w = ui.available_width();
            let (r, _) = ui.allocate_exact_size(vec2(w, s(54.0)), Sense::hover());
            let ib = Rect::from_min_size(r.min, Vec2::splat(s(54.0)));
            ui.painter().rect_filled(ib, s(9.0), HOST_ICON);
            draw_icon(ui.painter(), Icon::Hosts, ib.center(), s(26.0), TEXT, HOST_ICON);
            let fr = Rect::from_min_max(pos2(ib.max.x + s(15.0), r.min.y), r.max);
            changed |= field(ui, fr, "host-address", &mut h.address, "Server address", SECTION_BG, Some(FIELD_BORDER), false, regular(s(20.0))).changed();
        });
        section(ui, Some("General"), |ui| {
            changed |= form_field(ui, "host-label", &mut h.label, "Label", None, false);
            changed |= form_field(ui, "host-group", &mut h.group, "Parent Group", Some(Icon::Group), false);
            let mut tags = h.tags.join(", ");
            if form_field(ui, "host-tags", &mut tags, "Tags", Some(Icon::Tag), false) {
                h.tags = tags.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
                changed = true;
            }
            let w = ui.available_width();
            let (r, resp) = ui.allocate_exact_size(vec2(w, s(52.0)), Sense::click());
            ui.painter().rect_stroke(r, s(9.0), Stroke::new(1.0, FIELD_BORDER), StrokeKind::Inside);
            draw_icon(ui.painter(), Icon::Backspace, pos2(r.min.x + s(26.0), r.center().y), s(20.0), GREY, SECTION_BG);
            text(ui.painter(), pos2(r.min.x + s(44.0), r.center().y), Align2::LEFT_CENTER, "Backspace", regular(s(20.0)), GREY);
            let cur = if h.backspace == "ctrl-h" { "Control-H" } else { "Default" };
            text(ui.painter(), pos2(r.max.x - s(15.0), r.center().y), Align2::RIGHT_CENTER, cur, regular(s(20.0)), GREY);
            if resp.on_hover_cursor(egui::CursorIcon::PointingHand).on_hover_text("Click to switch").clicked() {
                h.backspace = if h.backspace == "ctrl-h" { "default".into() } else { "ctrl-h".into() };
                changed = true;
            }
        });
        section(ui, None, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("SSH on").font(bold(s(20.0))).color(TEXT));
                let (r, _) = ui.allocate_exact_size(vec2(s(118.0), s(42.0)), Sense::hover());
                changed |= field(ui, r, "host-port", &mut h.port, "22", SECTION_BG, Some(FIELD_BORDER), false, regular(s(19.0))).changed();
                ui.label(egui::RichText::new("port").font(bold(s(20.0))).color(TEXT));
            });
            ui.separator();
            ui.label(egui::RichText::new("Credentials").font(bold(s(20.0))).color(TEXT));
            changed |= form_field(ui, "host-user", &mut h.username, "Username", Some(Icon::User), false);
            let w = ui.available_width();
            let (r, _) = ui.allocate_exact_size(vec2(w, s(52.0)), Sense::hover());
            draw_icon(ui.painter(), Icon::Lock, pos2(r.min.x + s(26.0), r.center().y), s(20.0), GREY, SECTION_BG);
            ui.painter().rect_stroke(r, s(9.0), Stroke::new(1.0, FIELD_BORDER), StrokeKind::Inside);
            let inner = Rect::from_min_max(pos2(r.min.x + s(30.0), r.min.y), pos2(r.max.x - s(44.0), r.max.y));
            changed |= field(ui, inner, "host-pass", &mut h.password, "Password", Color32::TRANSPARENT, None, !*show_pw, regular(s(20.0))).changed();
            if icon_button(ui, pos2(r.max.x - s(26.0), r.center().y), s(36.0), "host-eye", Icon::Eye, GREY, SECTION_BG).on_hover_text("Show password").clicked() {
                *show_pw = !*show_pw;
            }
            let cur = h.key_id.and_then(|k| keys.iter().find(|(i, _)| *i == k)).map(|(_, l)| l.clone()).unwrap_or_else(|| "No key".into());
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Key").font(regular(s(19.0))).color(GREY));
                egui::ComboBox::from_id_salt("host-key").selected_text(cur).width(ui.available_width() - 8.0).show_ui(ui, |ui| {
                    changed |= ui.selectable_value(&mut h.key_id, None, "No key").changed();
                    for (kid, label) in &keys {
                        changed |= ui.selectable_value(&mut h.key_id, Some(*kid), label).changed();
                    }
                });
            });
            let cur = h.startup_snippet.and_then(|k| snippets.iter().find(|(i, _)| *i == k)).map(|(_, l)| l.clone()).unwrap_or_else(|| "None".into());
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Startup snippet").font(regular(s(19.0))).color(GREY));
                egui::ComboBox::from_id_salt("host-snippet").selected_text(cur).width(ui.available_width() - 8.0).show_ui(ui, |ui| {
                    changed |= ui.selectable_value(&mut h.startup_snippet, None, "None").changed();
                    for (sid, label) in &snippets {
                        changed |= ui.selectable_value(&mut h.startup_snippet, Some(*sid), label).changed();
                    }
                });
            });
            changed |= ui.checkbox(&mut h.agent_forwarding, egui::RichText::new("Agent forwarding").font(regular(s(19.0)))).changed();
        });
        changed
    }

    fn key_form(&mut self, ui: &mut Ui, id: u64) -> bool {
        let Some(k) = self.vault.keys.iter_mut().find(|k| k.id == id) else { return false };
        let mut changed = false;
        vault_card(ui);
        section(ui, Some("General"), |ui| {
            changed |= form_field(ui, "key-label", &mut k.label, "Label", None, false);
            changed |= form_field(ui, "key-pass", &mut k.passphrase, "Passphrase", Some(Icon::Lock), true);
        });
        section(ui, Some("Private key"), |ui| {
            let w = ui.available_width();
            let (r, _) = ui.allocate_exact_size(vec2(w, s(200.0)), Sense::hover());
            changed |= area(ui, r, "key-private", &mut k.private_key, "Paste your private key here", true).changed();
        });
        section(ui, Some("Public key"), |ui| {
            let w = ui.available_width();
            let (r, _) = ui.allocate_exact_size(vec2(w, s(130.0)), Sense::hover());
            changed |= area(ui, r, "key-public", &mut k.public_key, "Public key", true).changed();
            if !k.public_key.is_empty() && ui.button("Copy public key").clicked() {
                ui.ctx().copy_text(k.public_key.clone());
            }
        });
        section(ui, Some("Certificate"), |ui| {
            let w = ui.available_width();
            let (r, _) = ui.allocate_exact_size(vec2(w, s(110.0)), Sense::hover());
            changed |= area(ui, r, "key-cert", &mut k.certificate, "Paste an OpenSSH certificate (optional)", true).changed();
        });
        changed
    }

    fn forward_form(&mut self, ui: &mut Ui, id: u64) -> bool {
        let hosts: Vec<(u64, String)> = self.vault.hosts.iter().map(|h| (h.id, h.display_name())).collect();
        let Some(f) = self.vault.forwards.iter_mut().find(|f| f.id == id) else { return false };
        let mut changed = false;
        vault_card(ui);
        section(ui, None, |ui| {
            ui.horizontal(|ui| {
                let bw = (ui.available_width() - 16.0) / 3.0;
                for k in [FwKind::Local, FwKind::Remote, FwKind::Dynamic] {
                    let b = egui::Button::new(egui::RichText::new(k.name()).font(semi(s(19.0))).color(TEXT))
                        .fill(if f.kind == k { ACCENT } else { BUTTON })
                        .min_size(vec2(bw, s(42.0)));
                    if ui.add(b).clicked() {
                        f.kind = k;
                        changed = true;
                    }
                }
            });
            ui.label(egui::RichText::new(f.kind.help()).font(regular(s(17.0))).color(GREY));
            changed |= form_field(ui, "fw-label", &mut f.label, "Label", None, false);
            let host_label = if f.kind == FwKind::Remote { "Remote host" } else { "Intermediate host" };
            let cur = f.host_id.and_then(|h| hosts.iter().find(|(i, _)| *i == h)).map(|(_, l)| l.clone()).unwrap_or_else(|| "Select a host".into());
            ui.label(egui::RichText::new(host_label).font(regular(s(18.0))).color(GREY));
            egui::ComboBox::from_id_salt("fw-host").selected_text(cur).width(ui.available_width() - 8.0).show_ui(ui, |ui| {
                if hosts.is_empty() {
                    ui.label("Create a host first");
                }
                for (hid, label) in &hosts {
                    changed |= ui.selectable_value(&mut f.host_id, Some(*hid), label).changed();
                }
            });
            let port_hint = if f.kind == FwKind::Remote { "Remote port number" } else { "Local port number" };
            changed |= form_field(ui, "fw-port", &mut f.port, port_hint, None, false);
            changed |= form_field(ui, "fw-bind", &mut f.bind_address, "Listen address (default 127.0.0.1)", None, false);
            if f.kind != FwKind::Dynamic {
                changed |= form_field(ui, "fw-dest", &mut f.dest_address, "Destination address", None, false);
                changed |= form_field(ui, "fw-dport", &mut f.dest_port, "Destination port number", None, false);
            }
        });
        changed
    }

    fn snippet_form(&mut self, ui: &mut Ui, id: u64) -> bool {
        let Some(sn) = self.vault.snippets.iter_mut().find(|sn| sn.id == id) else { return false };
        let mut changed = false;
        vault_card(ui);
        section(ui, None, |ui| {
            changed |= form_field(ui, "snip-label", &mut sn.label, "Label", None, false);
            let w = ui.available_width();
            let (r, _) = ui.allocate_exact_size(vec2(w, s(260.0)), Sense::hover());
            changed |= area(ui, r, "snip-script", &mut sn.script, "Script", true).changed();
            ui.label(egui::RichText::new("Runs in the open terminal tab, or in a new local terminal.").font(regular(s(16.0))).color(GREY));
        });
        changed
    }

    fn generate_form(&mut self, ui: &mut Ui) {
        let f = &mut self.gen_form;
        vault_card(ui);
        section(ui, None, |ui| {
            form_field(ui, "gen-label", &mut f.label, "Label", None, false);
            ui.horizontal(|ui| {
                let bw = (ui.available_width() - 16.0) / 3.0;
                for k in ["ED25519", "ECDSA", "RSA"] {
                    let b = egui::Button::new(egui::RichText::new(k).font(semi(s(19.0))).color(TEXT))
                        .fill(if f.kind == k { ACCENT } else { BUTTON })
                        .min_size(vec2(bw, s(42.0)));
                    if ui.add(b).clicked() {
                        f.kind = k.into();
                    }
                }
            });
            match f.kind.as_str() {
                "RSA" => {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Key size").color(GREY));
                        for b in [2048u32, 3072, 4096] {
                            ui.selectable_value(&mut f.rsa_bits, b, b.to_string());
                        }
                    });
                }
                "ECDSA" => {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Curve size").color(GREY));
                        for b in [256u32, 384, 521] {
                            ui.selectable_value(&mut f.ecdsa_bits, b, b.to_string());
                        }
                    });
                }
                _ => {}
            }
            form_field(ui, "gen-pass", &mut f.passphrase, "Passphrase (optional)", Some(Icon::Lock), true);
            ui.label(egui::RichText::new("Keys are made with Windows' built-in ssh-keygen.").font(regular(s(16.0))).color(GREY));
        });
    }

    // ------------------------------------------------------------------ SFTP

    fn open_pane_local(&mut self, i: usize) {
        let path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("C:\\"));
        let entries = sftp::list_local(&path).unwrap_or_default();
        let p = &mut self.panes[i];
        p.state = PaneState::Local { path, entries };
        p.selected = None;
        p.status.clear();
        p.busy = false;
    }

    fn open_pane_remote(&mut self, i: usize, h: &Host, ctx: &egui::Context) {
        let key = h.key_id.and_then(|k| self.vault.key(k)).map(|k| (k.private_key.clone(), k.passphrase.clone()));
        let info = sftp::ConnectInfo {
            address: h.address.trim().to_string(),
            port: h.port_number(),
            user: h.username.trim().to_string(),
            password: h.password.clone(),
            private_key: key.filter(|(p, _)| !p.trim().is_empty()),
            keepalive_secs: self.vault.settings.keepalive_interval,
        };
        let remote = sftp::connect(info, ctx);
        let p = &mut self.panes[i];
        p.state = PaneState::Remote { remote, title: h.display_name(), path: String::new(), entries: Vec::new() };
        p.busy = true;
        p.selected = None;
        p.status = "Connecting…".into();
    }

    fn poll_panes(&mut self) {
        let mut follow_up: Vec<(usize, Req)> = Vec::new();
        let mut local_refresh = Vec::new();
        for i in 0..2 {
            let p = &mut self.panes[i];
            let PaneState::Remote { remote, path, entries, .. } = &mut p.state else { continue };
            let mut disconnected = None;
            while let Ok(resp) = remote.rx.try_recv() {
                match resp {
                    Resp::Connected { home } => {
                        *path = home.clone();
                        remote.send(Req::List(home));
                        p.status = "Connected".into();
                    }
                    Resp::Listing { path: lp, entries: e } => {
                        *path = lp;
                        *entries = e;
                        p.busy = false;
                    }
                    Resp::Done(msg) => {
                        p.status = msg;
                        remote.send(Req::List(path.clone()));
                        if let Some((target, local, remote_dir, is_dir)) = self.pending_copy.take() {
                            follow_up.push((target, Req::Upload { local, remote: remote_dir, is_dir }));
                        }
                        if let Some(t) = self.refresh_local_after.take() {
                            local_refresh.push(t);
                        }
                    }
                    Resp::Error(e) => {
                        p.status = e;
                        p.busy = false;
                    }
                    Resp::Disconnected(e) => disconnected = Some(e),
                }
            }
            if let Some(e) = disconnected {
                p.state = PaneState::Empty;
                p.status = e;
                p.busy = false;
            }
        }
        for (i, req) in follow_up {
            if let PaneState::Remote { remote, .. } = &self.panes[i].state {
                remote.send(req);
                self.panes[i].busy = true;
            }
        }
        for i in local_refresh {
            self.pane_refresh(i);
        }
    }

    fn sftp_view(&mut self, ui: &mut Ui, r: Rect) {
        ui.painter().rect_filled(r, 0.0, CONTENT_BG);
        let mid = r.center().x.round();
        let left = Rect::from_min_max(r.min, pos2(mid - 0.5, r.max.y));
        let right = Rect::from_min_max(pos2(mid + 0.5, r.min.y), r.max);
        self.pane_ui(ui, 0, left);
        self.pane_ui(ui, 1, right);
        ui.painter().line_segment([pos2(mid, r.min.y), pos2(mid, r.max.y)], Stroke::new(1.0, BORDER));
    }

    fn pane_ui(&mut self, ui: &mut Ui, i: usize, r: Rect) {
        let ctx = ui.ctx().clone();
        let other = 1 - i;
        if matches!(self.panes[i].state, PaneState::Empty) {
            let y = empty_screen(ui, r, Icon::Folder, "Open a location", "Pick a saved host or this computer to browse files.", s(80.0));
            let br = Rect::from_center_size(pos2(r.center().x, y + s(48.0)), vec2(s(200.0), s(50.0)));
            if button(ui, br, &format!("sftp-select-{i}"), "Choose…", None, ACCENT, ACCENT_HOVER, TEXT, semi(s(20.0))).clicked() {
                self.modal = Some(Modal::PickSftpHost(i));
            }
            if !self.panes[i].status.is_empty() {
                text_fit(ui, pos2(r.center().x, br.max.y + s(30.0)), Align2::CENTER_CENTER, &self.panes[i].status, regular(s(17.0)), RED, r.width() - s(40.0));
            }
            return;
        }
        let hr = Rect::from_min_max(r.min, pos2(r.max.x, r.min.y + s(70.0)));
        ui.painter().rect_filled(hr, 0.0, SIDEBAR_BG);
        let (title, path_s) = match &self.panes[i].state {
            PaneState::Local { path, .. } => ("Local".to_string(), path.display().to_string()),
            PaneState::Remote { title, path, .. } => (title.clone(), path.clone()),
            PaneState::Empty => (String::new(), String::new()),
        };
        let cy = hr.center().y;
        let tb = rect_xywh(hr.min.x + s(14.0), cy - s(21.0), s(200.0), s(42.0));
        let rt = hit(ui, tb, ("pane-title", i));
        let tfill = if rt.hovered() { BUTTON_HOVER } else { BUTTON };
        ui.painter().rect_filled(tb, s(8.0), tfill);
        draw_icon(ui.painter(), if title == "Local" { Icon::Folder } else { Icon::Hosts }, pos2(tb.min.x + s(22.0), cy), s(18.0), TEXT, tfill);
        text_fit(ui, pos2(tb.min.x + s(42.0), cy), Align2::LEFT_CENTER, &title, semi(s(19.0)), TEXT, s(120.0));
        draw_icon(ui.painter(), Icon::ChevronDown, pos2(tb.max.x - s(18.0), cy), s(14.0), TEXT, tfill);
        if rt.clicked() {
            self.modal = Some(Modal::PickSftpHost(i));
        }
        let mut nav: Option<String> = None;
        let mut upr = false;
        let bx = hr.max.x;
        if icon_button(ui, pos2(bx - s(30.0), cy), s(42.0), &format!("p-close-{i}"), Icon::Close, GREY, SIDEBAR_BG).on_hover_text("Disconnect").clicked() {
            self.panes[i] = Pane::new();
            return;
        }
        if icon_button(ui, pos2(bx - s(78.0), cy), s(42.0), &format!("p-refresh-{i}"), Icon::Refresh, TEXT, SIDEBAR_BG).on_hover_text("Refresh").clicked() {
            nav = Some(path_s.clone());
        }
        if icon_button(ui, pos2(bx - s(126.0), cy), s(42.0), &format!("p-mkdir-{i}"), Icon::Plus, TEXT, SIDEBAR_BG).on_hover_text("New folder").clicked() {
            self.panes[i].new_folder = Some(String::new());
        }
        if icon_button(ui, pos2(tb.max.x + s(30.0), cy), s(42.0), &format!("p-up-{i}"), Icon::Up, TEXT, SIDEBAR_BG).on_hover_text("Up").clicked() {
            upr = true;
        }
        text_fit(ui, pos2(tb.max.x + s(60.0), cy), Align2::LEFT_CENTER, &path_s, regular(s(18.0)), GREY, ((bx - s(150.0)) - (tb.max.x + s(60.0))).max(10.0));
        // Action row
        let ar = Rect::from_min_max(pos2(r.min.x, hr.max.y), pos2(r.max.x, hr.max.y + s(54.0)));
        let sel = self.panes[i].selected.clone();
        let other_ready = !matches!(self.panes[other].state, PaneState::Empty);
        let mut do_copy = false;
        let mut do_delete = false;
        let mut do_rename = false;
        {
            let b1 = rect_xywh(ar.min.x + s(14.0), ar.min.y + s(8.0), s(170.0), s(38.0));
            let can = sel.is_some() && other_ready;
            let (f, c) = if can { (ACCENT, TEXT) } else { (BUTTON, DIM) };
            let lbl = if i == 0 { "Copy to right →" } else { "← Copy to left" };
            if button(ui, b1, &format!("p-copy-{i}"), lbl, None, f, if can { ACCENT_HOVER } else { f }, c, semi(s(17.0))).clicked() && can {
                do_copy = true;
            }
            let b2 = rect_xywh(b1.max.x + s(10.0), b1.min.y, s(110.0), s(38.0));
            let c2 = if sel.is_some() { TEXT } else { DIM };
            if button(ui, b2, &format!("p-ren-{i}"), "Rename", None, BUTTON, BUTTON_HOVER, c2, semi(s(17.0))).clicked() && sel.is_some() {
                do_rename = true;
            }
            let b3 = rect_xywh(b2.max.x + s(10.0), b1.min.y, s(100.0), s(38.0));
            if button(ui, b3, &format!("p-del-{i}"), "Delete", None, BUTTON, BUTTON_HOVER, if sel.is_some() { RED } else { DIM }, semi(s(17.0))).clicked() && sel.is_some() {
                do_delete = true;
            }
            let st = if self.panes[i].busy { "Working…".to_string() } else { self.panes[i].status.clone() };
            text_fit(ui, pos2(b3.max.x + s(16.0), b1.center().y), Align2::LEFT_CENTER, &st, regular(s(16.0)), GREY, (ar.max.x - b3.max.x - s(30.0)).max(10.0));
        }
        // New folder / rename inline field
        let mut table_top = ar.max.y;
        if self.panes[i].new_folder.is_some() || self.panes[i].rename.is_some() {
            let fr = rect_xywh(r.min.x + s(14.0), table_top + s(4.0), r.width() - s(140.0), s(44.0));
            let okr = rect_xywh(fr.max.x + s(8.0), fr.min.y, s(104.0), s(44.0));
            let is_new = self.panes[i].new_folder.is_some();
            let mut val = if is_new { self.panes[i].new_folder.clone().unwrap_or_default() } else { self.panes[i].rename.as_ref().map(|r| r.1.clone()).unwrap_or_default() };
            let resp = field(ui, fr, &format!("p-name-{i}"), &mut val, if is_new { "Folder name" } else { "New name" }, FIELD_BG, None, false, regular(s(18.0)));
            if is_new {
                self.panes[i].new_folder = Some(val.clone());
            } else if let Some(rn) = self.panes[i].rename.as_mut() {
                rn.1 = val.clone();
            }
            let ok = button(ui, okr, &format!("p-ok-{i}"), "Save", None, ACCENT, ACCENT_HOVER, TEXT, semi(s(17.0))).clicked()
                || (resp.lost_focus() && ui.input(|inp| inp.key_pressed(egui::Key::Enter)));
            let cancel = ui.input(|inp| inp.key_pressed(egui::Key::Escape));
            if ok && !val.trim().is_empty() {
                let new_folder = self.panes[i].new_folder.take();
                let rename = self.panes[i].rename.take();
                self.pane_name_action(i, new_folder.map(|_| val.trim().to_string()), rename.map(|(from, _)| (from, val.trim().to_string())));
            } else if cancel {
                self.panes[i].new_folder = None;
                self.panes[i].rename = None;
            }
            table_top = fr.max.y + s(6.0);
        }
        // Table
        let tr = Rect::from_min_max(pos2(r.min.x, table_top), r.max);
        let cols = [("Name", 0.0f32), ("Modified", 0.46), ("Size", 0.72), ("Type", 0.86)];
        let head = Rect::from_min_max(tr.min, pos2(tr.max.x, tr.min.y + s(40.0)));
        ui.painter().line_segment([pos2(head.min.x, head.max.y), pos2(head.max.x, head.max.y)], Stroke::new(1.0, BORDER));
        let inner_w = tr.width() - s(28.0);
        for (name, f) in cols {
            let x = tr.min.x + s(14.0) + inner_w * f + if f == 0.0 { s(42.0) } else { s(8.0) };
            text(ui.painter(), pos2(x, head.center().y), Align2::LEFT_CENTER, name, semi(s(16.0)), GREY);
        }
        let entries: Vec<FileEntry> = match &self.panes[i].state {
            PaneState::Local { entries, .. } | PaneState::Remote { entries, .. } => entries.clone(),
            _ => Vec::new(),
        };
        let body = Rect::from_min_max(pos2(tr.min.x, head.max.y + 2.0), tr.max);
        let mut open_dir = None;
        ui.scope_builder(UiBuilder::new().max_rect(body).id_salt(("pane-body", i)), |ui| {
            egui::ScrollArea::vertical().id_salt(("pane-scroll", i)).auto_shrink([false, false]).show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                let row_h = s(44.0);
                for e in &entries {
                    let (rr, resp) = ui.allocate_exact_size(vec2(ui.available_width(), row_h), Sense::click());
                    let is_sel = self.panes[i].selected.as_deref() == Some(e.name.as_str());
                    let bg = if is_sel { SELECTED } else if resp.hovered() { HOVER } else { CONTENT_BG };
                    if bg != CONTENT_BG {
                        ui.painter().rect_filled(rr.shrink2(vec2(s(8.0), 1.0)), s(8.0), bg);
                    }
                    let x0 = rr.min.x + s(14.0);
                    let cy = rr.center().y;
                    let iw = rr.width() - s(28.0);
                    draw_icon(ui.painter(), if e.is_dir { Icon::Folder } else { Icon::File }, pos2(x0 + s(20.0), cy), s(18.0), if e.is_dir { ACCENT } else { GREY }, bg);
                    text_fit(ui, pos2(x0 + s(42.0), cy), Align2::LEFT_CENTER, &e.name, regular(s(18.0)), TEXT, (iw * 0.46 - s(46.0)).max(10.0));
                    if e.modified > 0 {
                        text(ui.painter(), pos2(x0 + iw * 0.46 + s(8.0), cy), Align2::LEFT_CENTER, &format_time(e.modified), regular(s(16.0)), GREY);
                    }
                    let size = if e.is_dir { "--".to_string() } else { format_size(e.size) };
                    text(ui.painter(), pos2(x0 + iw * 0.72 + s(8.0), cy), Align2::LEFT_CENTER, &size, regular(s(16.0)), GREY);
                    text(ui.painter(), pos2(x0 + iw * 0.86 + s(8.0), cy), Align2::LEFT_CENTER, &e.kind(), regular(s(16.0)), GREY);
                    if resp.double_clicked() && e.is_dir {
                        open_dir = Some(e.name.clone());
                    } else if resp.clicked() {
                        self.panes[i].selected = Some(e.name.clone());
                    }
                }
                if entries.is_empty() {
                    ui.add_space(s(30.0));
                    let msg = if self.panes[i].busy { "Loading…" } else { "This folder is empty" };
                    ui.vertical_centered(|ui| ui.label(egui::RichText::new(msg).color(GREY)));
                }
            });
        });
        if let Some(d) = open_dir {
            nav = Some(match &self.panes[i].state {
                PaneState::Local { path, .. } => path.join(d).display().to_string(),
                PaneState::Remote { path, .. } => sftp::join_remote(path, &d),
                _ => String::new(),
            });
        }
        if upr {
            nav = Some(match &self.panes[i].state {
                PaneState::Local { path, .. } => path.parent().map(|p| p.display().to_string()).unwrap_or_else(|| path.display().to_string()),
                PaneState::Remote { path, .. } => sftp::parent_remote(path),
                _ => String::new(),
            });
        }
        if let Some(target) = nav {
            self.pane_navigate(i, target);
        }
        if do_copy
            && let Some(name) = sel.clone() {
                self.pane_copy(i, &name, &ctx);
            }
        if do_rename
            && let Some(name) = sel.clone() {
                self.panes[i].rename = Some((name.clone(), name));
            }
        if do_delete
            && let Some(name) = sel {
                self.pane_delete(i, &name, &entries);
            }
    }

    fn pane_navigate(&mut self, i: usize, target: String) {
        let p = &mut self.panes[i];
        p.selected = None;
        match &mut p.state {
            PaneState::Local { path, entries } => match sftp::list_local(std::path::Path::new(&target)) {
                Ok(e) => {
                    *path = PathBuf::from(&target);
                    *entries = e;
                }
                Err(e) => p.status = e,
            },
            PaneState::Remote { remote, .. } => {
                remote.send(Req::List(target));
                p.busy = true;
            }
            PaneState::Empty => {}
        }
    }

    fn pane_refresh(&mut self, i: usize) {
        let target = match &self.panes[i].state {
            PaneState::Local { path, .. } => path.display().to_string(),
            PaneState::Remote { path, .. } => path.clone(),
            PaneState::Empty => return,
        };
        let sel = self.panes[i].selected.clone();
        self.pane_navigate(i, target);
        self.panes[i].selected = sel;
    }

    fn pane_name_action(&mut self, i: usize, new_folder: Option<String>, rename: Option<(String, String)>) {
        let p = &mut self.panes[i];
        match &mut p.state {
            PaneState::Local { path, .. } => {
                let res = if let Some(n) = new_folder {
                    std::fs::create_dir(path.join(n))
                } else if let Some((from, to)) = rename {
                    std::fs::rename(path.join(from), path.join(to))
                } else {
                    Ok(())
                };
                p.status = match res {
                    Ok(()) => "Done".into(),
                    Err(e) => e.to_string(),
                };
                self.pane_refresh(i);
            }
            PaneState::Remote { remote, path, .. } => {
                if let Some(n) = new_folder {
                    remote.send(Req::Mkdir(sftp::join_remote(path, &n)));
                } else if let Some((from, to)) = rename {
                    remote.send(Req::Rename { from: sftp::join_remote(path, &from), to: sftp::join_remote(path, &to) });
                }
                p.busy = true;
            }
            PaneState::Empty => {}
        }
    }

    fn pane_delete(&mut self, i: usize, name: &str, entries: &[FileEntry]) {
        let is_dir = entries.iter().find(|e| e.name == name).is_some_and(|e| e.is_dir);
        let p = &mut self.panes[i];
        match &mut p.state {
            PaneState::Local { path, .. } => {
                let target = path.join(name);
                let res = if is_dir { std::fs::remove_dir_all(&target) } else { std::fs::remove_file(&target) };
                p.status = match res {
                    Ok(()) => "Deleted".into(),
                    Err(e) => e.to_string(),
                };
                p.selected = None;
                self.pane_refresh(i);
            }
            PaneState::Remote { remote, path, .. } => {
                remote.send(Req::Delete { path: sftp::join_remote(path, name), is_dir });
                p.busy = true;
                p.selected = None;
            }
            PaneState::Empty => {}
        }
    }

    fn pane_copy(&mut self, from: usize, name: &str, ctx: &egui::Context) {
        let to = 1 - from;
        let is_dir = match &self.panes[from].state {
            PaneState::Local { entries, .. } | PaneState::Remote { entries, .. } => entries.iter().find(|e| e.name == name).is_some_and(|e| e.is_dir),
            _ => false,
        };
        let src_local = matches!(self.panes[from].state, PaneState::Local { .. });
        let dst_local = matches!(self.panes[to].state, PaneState::Local { .. });
        match (src_local, dst_local) {
            (true, true) => {
                let (PaneState::Local { path: a, .. }, PaneState::Local { path: b, .. }) = (&self.panes[from].state, &self.panes[to].state) else { return };
                let res = sftp::copy_local(&a.join(name), b);
                self.panes[to].status = match res {
                    Ok(()) => format!("Copied {name}"),
                    Err(e) => e.to_string(),
                };
                self.pane_refresh(to);
            }
            (true, false) => {
                let PaneState::Local { path: a, .. } = &self.panes[from].state else { return };
                let local = a.join(name);
                if let PaneState::Remote { remote, path, .. } = &self.panes[to].state {
                    remote.send(Req::Upload { local, remote: path.clone(), is_dir });
                    self.panes[to].busy = true;
                }
            }
            (false, true) => {
                let PaneState::Local { path: b, .. } = &self.panes[to].state else { return };
                let local_dir = b.clone();
                if let PaneState::Remote { remote, path, .. } = &self.panes[from].state {
                    remote.send(Req::Download { remote: sftp::join_remote(path, name), local: local_dir, is_dir });
                    self.panes[from].busy = true;
                    self.refresh_local_after = Some(to);
                }
            }
            (false, false) => {
                // Server to server: download to a temporary folder, then upload.
                let tmp = std::env::temp_dir().join(format!("freeterm-sftp-{}", now()));
                let _ = std::fs::create_dir_all(&tmp);
                let dst_dir = match &self.panes[to].state {
                    PaneState::Remote { path, .. } => path.clone(),
                    _ => return,
                };
                if let PaneState::Remote { remote, path, .. } = &self.panes[from].state {
                    remote.send(Req::Download { remote: sftp::join_remote(path, name), local: tmp.clone(), is_dir });
                    self.panes[from].busy = true;
                    self.pending_copy = Some((to, tmp.join(name), dst_dir, is_dir));
                }
                self.toast(ctx, "Copying through this computer…");
            }
        }
    }

    // ------------------------------------------------------------------ overlays

    fn popups(&mut self, ctx: &egui::Context) {
        let Some((p, pos)) = self.popup else { return };
        let mut close = false;
        let width = match p {
            Popup::Notifications => s(420.0),
            Popup::MainMenu => s(300.0),
            _ => s(260.0),
        };
        let area = egui::Area::new(Id::unique("popup")).order(egui::Order::Foreground).fixed_pos(pos).show(ctx, |ui| {
            egui::Frame::new()
                .fill(SIDEBAR_BG)
                .stroke(Stroke::new(1.0, BORDER))
                .corner_radius(10.0)
                .inner_margin(s(8.0))
                .shadow(egui::Shadow { offset: [0, 6], blur: 18, spread: 0, color: Color32::from_black_alpha(120) })
                .show(ui, |ui| {
                    ui.set_width(width);
                    ui.spacing_mut().item_spacing.y = 2.0;
                    match p {
                        Popup::MainMenu => {
                            if menu_item(ui, "New terminal", Icon::Terminal) {
                                self.open_local_terminal(ctx);
                                close = true;
                            }
                            if menu_item(ui, "Settings", Icon::Settings) {
                                self.modal = Some(Modal::Settings);
                                close = true;
                            }
                            if menu_item(ui, "Open data folder", Icon::Folder) {
                                let _ = std::fs::create_dir_all(data_dir());
                                let _ = std::process::Command::new("explorer.exe").arg(data_dir()).spawn();
                                close = true;
                            }
                            if menu_item(ui, "Quit", Icon::Close) {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                close = true;
                            }
                        }
                        Popup::Vaults => {
                            ui.label(egui::RichText::new("Home").font(semi(s(16.0))).color(GREY));
                            if menu_item(ui, "Local  ✓", Icon::Vault) {
                                self.tab = TabSel::Vaults;
                                close = true;
                            }
                            ui.label(egui::RichText::new("Everything is stored on this computer.").font(regular(s(15.0))).color(GREY));
                        }
                        Popup::NewHost => {
                            if menu_item(ui, "New host", Icon::Hosts) {
                                self.new_item(None, ctx);
                                close = true;
                            }
                            if menu_item(ui, "New local terminal", Icon::Terminal) {
                                self.open_local_terminal(ctx);
                                close = true;
                            }
                        }
                        Popup::NewKey => {
                            if menu_item(ui, "Import key", Icon::Key) {
                                self.new_item(None, ctx);
                                close = true;
                            }
                            if menu_item(ui, "Generate key", Icon::Plus) {
                                self.new_item(Some("generate"), ctx);
                                close = true;
                            }
                        }
                        Popup::NewForward => {
                            for k in ["Local", "Remote", "Dynamic"] {
                                if menu_item(ui, &format!("{k} forwarding"), Icon::Forward) {
                                    self.new_item(Some(k), ctx);
                                    close = true;
                                }
                            }
                        }
                        Popup::NewSnippet => {
                            if menu_item(ui, "New snippet", Icon::Braces) {
                                self.new_item(None, ctx);
                                close = true;
                            }
                            if menu_item(ui, "From shell history", Icon::Clock) {
                                self.show_history = true;
                                close = true;
                            }
                        }
                        Popup::Sort => {
                            for (sv, label) in [(Sort::AZ, "A-z"), (Sort::ZA, "Z-a"), (Sort::Newest, "Newest to oldest"), (Sort::Oldest, "Oldest to newest")] {
                                let l = if self.sort == sv { format!("{label}  ✓") } else { label.to_string() };
                                if menu_item(ui, &l, Icon::Calendar) {
                                    self.sort = sv;
                                    close = true;
                                }
                            }
                        }
                        Popup::Tags => {
                            let mut tags: Vec<String> = self.vault.hosts.iter().flat_map(|h| h.tags.clone()).collect();
                            tags.sort();
                            tags.dedup();
                            if tags.is_empty() {
                                ui.label(egui::RichText::new("No tags yet. Add tags to a host.").color(GREY));
                            }
                            if self.tag_filter.is_some() && menu_item(ui, "Show all", Icon::Tag) {
                                self.tag_filter = None;
                                close = true;
                            }
                            for t in tags {
                                let l = if self.tag_filter.as_ref() == Some(&t) { format!("{t}  ✓") } else { t.clone() };
                                if menu_item(ui, &l, Icon::Tag) {
                                    self.tag_filter = Some(t);
                                    close = true;
                                }
                            }
                        }
                        Popup::Notifications => {
                            ui.label(egui::RichText::new("Notifications").font(bold(s(19.0))));
                            ui.add_space(6.0);
                            let running = self.forwards.values().filter(|t| !t.exited).count();
                            let open = self.sessions.iter().filter(|s| !s.term.exited).count();
                            ui.label(egui::RichText::new(format!("{open} open session(s), {running} active port forwarding rule(s).")).color(GREY));
                        }
                        Popup::NewTab => {
                            if menu_item(ui, "Local terminal", Icon::Terminal) {
                                self.open_local_terminal(ctx);
                                close = true;
                            }
                            let hosts: Vec<Host> = self.vault.hosts.iter().filter(|h| !h.address.is_empty()).cloned().collect();
                            if !hosts.is_empty() {
                                ui.separator();
                            }
                            for h in hosts {
                                if menu_item(ui, &h.display_name(), Icon::Hosts) {
                                    self.connect_host(h, ctx);
                                    close = true;
                                }
                            }
                        }
                        Popup::PanelMore => {
                            if menu_item(ui, "Duplicate", Icon::Plus) {
                                self.duplicate_panel_item();
                                close = true;
                            }
                            if menu_item(ui, "Delete", Icon::Trash) {
                                self.delete_panel_item();
                                close = true;
                            }
                        }
                    }
                });
        });
        let clicked_outside = ctx.input(|i| i.pointer.any_pressed())
            && self.frame_no > self.popup_frame + 1
            && !ctx.input(|i| i.pointer.interact_pos()).is_some_and(|p| area.response.rect.contains(p));
        if close || clicked_outside || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.popup = None;
        }
    }

    fn modals(&mut self, ctx: &egui::Context) {
        let Some(m) = self.modal.take() else { return };
        let mut keep = true;
        let mut next: Option<Modal> = None;
        match m {
            Modal::Settings => {
                let r = egui::Modal::new(Id::unique("settings")).frame(modal_frame()).show(ctx, |ui| {
                    ui.set_width(s(460.0));
                    ui.label(egui::RichText::new("Settings").font(bold(s(22.0))));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Terminal font size");
                        // Font size range.
                        if ui.add(egui::Slider::new(&mut self.vault.settings.font_size, 4.0..=40.0).step_by(1.0)).changed() {
                            self.save();
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Keep-alive interval (seconds, 0 = off)");
                        if ui.add(egui::DragValue::new(&mut self.vault.settings.keepalive_interval).range(0..=3600)).changed() {
                            self.save();
                        }
                    });
                    if ui.checkbox(&mut self.vault.settings.autoreconnect, "Reconnect automatically when a connection drops").changed() {
                        self.save();
                    }
                    if ui.checkbox(&mut self.vault.settings.brighten_bold, "Brighten bold text").changed() {
                        self.save();
                    }
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(format!("Your data is saved in {}", data_dir().display())).color(GREY));
                    ui.add_space(10.0);
                    if ui.add(egui::Button::new("Close").fill(ACCENT).min_size(vec2(s(120.0), s(40.0)))).clicked() {
                        keep = false;
                    }
                });
                if r.should_close() {
                    keep = false;
                }
                if keep {
                    next = Some(Modal::Settings);
                }
            }
            Modal::Serial { mut port, mut baud, ports } => {
                let mut connect = false;
                let r = egui::Modal::new(Id::unique("serial")).frame(modal_frame()).show(ctx, |ui| {
                    ui.set_width(s(460.0));
                    ui.label(egui::RichText::new("Serial").font(bold(s(22.0))));
                    ui.add_space(8.0);
                    if ports.is_empty() {
                        ui.label(egui::RichText::new("No serial ports found. Type the port name (for example COM3).").color(GREY));
                        ui.text_edit_singleline(&mut port);
                    } else {
                        egui::ComboBox::from_label("Port").selected_text(port.clone()).show_ui(ui, |ui| {
                            for p in &ports {
                                ui.selectable_value(&mut port, p.clone(), p);
                            }
                        });
                    }
                    // Standard baud rates.
                    egui::ComboBox::from_label("Baud rate").selected_text(baud.to_string()).show_ui(ui, |ui| {
                        for b in [50u32, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600, 115200] {
                            ui.selectable_value(&mut baud, b, b.to_string());
                        }
                    });
                    ui.label(egui::RichText::new("8 data bits, 1 stop bit, no parity, no flow control").color(GREY));
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add_enabled(!port.trim().is_empty(), egui::Button::new("Connect").fill(ACCENT).min_size(vec2(s(130.0), s(40.0)))).clicked() {
                            connect = true;
                        }
                        if ui.add(egui::Button::new("Cancel").min_size(vec2(s(110.0), s(40.0)))).clicked() {
                            keep = false;
                        }
                    });
                });
                if r.should_close() {
                    keep = false;
                }
                if connect {
                    match Term::serial(port.trim(), baud, ctx) {
                        Ok(t) => self.new_session(format!("{} · {}", port.trim(), baud), SessionKind::Serial, t, None, ctx),
                        Err(e) => self.toast(ctx, format!("Could not open {}: {e}", port.trim())),
                    }
                } else if keep {
                    next = Some(Modal::Serial { port, baud, ports });
                }
            }
            Modal::PickSftpHost(i) => {
                let mut pick: Option<Option<Host>> = None;
                let r = egui::Modal::new(Id::unique("pick-host")).frame(modal_frame()).show(ctx, |ui| {
                    ui.set_width(s(520.0));
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Choose a location").font(bold(s(22.0))));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(egui::Button::new(egui::RichText::new("Local").color(TEXT)).fill(ACCENT)).clicked() {
                                pick = Some(None);
                            }
                        });
                    });
                    ui.add_space(8.0);
                    let hosts: Vec<Host> = self.vault.hosts.iter().filter(|h| !h.address.is_empty()).cloned().collect();
                    if hosts.is_empty() {
                        ui.label(egui::RichText::new("No hosts. Save your connection details as hosts to connect via SFTP.").color(GREY));
                    }
                    egui::ScrollArea::vertical().max_height(s(500.0)).show(ui, |ui| {
                        for h in hosts {
                            let label = if h.username.is_empty() { h.display_name() } else { format!("{}   ({})", h.display_name(), h.username) };
                            if ui.add(egui::Button::new(label).min_size(vec2(ui.available_width(), s(46.0))).fill(CARD)).clicked() {
                                pick = Some(Some(h));
                            }
                        }
                    });
                    ui.add_space(8.0);
                    if ui.button("Cancel").clicked() {
                        keep = false;
                    }
                });
                if r.should_close() {
                    keep = false;
                }
                match pick {
                    Some(None) => {
                        self.open_pane_local(i);
                        keep = false;
                    }
                    Some(Some(h)) => {
                        self.open_pane_remote(i, &h, ctx);
                        keep = false;
                    }
                    None => {}
                }
                if keep {
                    next = Some(Modal::PickSftpHost(i));
                }
            }
        }
        if self.modal.is_none() {
            self.modal = next;
        }
    }

    fn toast_ui(&mut self, ctx: &egui::Context, full: Rect) {
        let Some((msg, until)) = self.toast.clone() else { return };
        if ctx.input(|i| i.time) > until {
            self.toast = None;
            return;
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
        egui::Area::new(Id::unique("toast")).order(egui::Order::Tooltip).anchor(Align2::CENTER_BOTTOM, vec2(0.0, -s(40.0))).show(ctx, |ui| {
            egui::Frame::new().fill(SELECTED).corner_radius(10.0).inner_margin(egui::Margin::symmetric(18, 12)).show(ui, |ui| {
                ui.set_max_width(full.width() * 0.6);
                ui.label(egui::RichText::new(msg).font(regular(s(18.0))).color(TEXT));
            });
        });
    }

    fn edge_resize(&self, ui: &mut Ui, full: Rect) {
        use egui::ResizeDirection as D;
        let ctx = ui.ctx().clone();
        if ctx.input(|i| i.viewport().maximized.unwrap_or(false)) {
            return;
        }
        let m = 5.0;
        let edges = [
            (Rect::from_min_max(full.min, pos2(full.max.x, full.min.y + m)), D::North, egui::CursorIcon::ResizeVertical),
            (Rect::from_min_max(pos2(full.min.x, full.max.y - m), full.max), D::South, egui::CursorIcon::ResizeVertical),
            (Rect::from_min_max(full.min, pos2(full.min.x + m, full.max.y)), D::West, egui::CursorIcon::ResizeHorizontal),
            (Rect::from_min_max(pos2(full.max.x - m, full.min.y), full.max), D::East, egui::CursorIcon::ResizeHorizontal),
            (Rect::from_min_size(pos2(full.max.x - 2.0 * m, full.max.y - 2.0 * m), Vec2::splat(2.0 * m)), D::SouthEast, egui::CursorIcon::ResizeNwSe),
        ];
        for (k, (r, d, c)) in edges.into_iter().enumerate() {
            let resp = ui.interact(r, Id::unique(("edge", k)), Sense::drag());
            if resp.hovered() {
                ctx.set_cursor_icon(c);
            }
            if resp.drag_started() {
                ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(d));
            }
        }
    }

    fn page_body(&mut self, ui: &mut Ui, r: Rect) {
        ui.scope_builder(UiBuilder::new().max_rect(r).id_salt("page-body"), |ui| {
            ui.set_clip_rect(r);
            match self.page {
                Page::Hosts => self.hosts_page(ui, r),
                Page::Keychain => self.keychain_page(ui, r),
                Page::PortForwarding => self.forwarding_page(ui, r),
                Page::Snippets => self.snippets_page(ui, r),
                Page::KnownHosts => self.known_hosts_page(ui, r),
                Page::Logs => self.logs_page(ui, r),
            }
        });
    }
}

impl eframe::App for App {
    fn clear_color(&self, _v: &egui::Visuals) -> [f32; 4] {
        CONTENT_BG.to_normalized_gamma_f32()
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.frame_no += 1;
        self.poll(&ctx);
        let full = ui.max_rect();
        ui.painter().rect_filled(full, 0.0, CONTENT_BG);

        let tb = Rect::from_min_max(full.min, pos2(full.max.x, full.min.y + s(67.0)));
        let below = Rect::from_min_max(pos2(full.min.x, tb.max.y), full.max);

        match self.tab {
            TabSel::Vaults => {
                let side = Rect::from_min_max(below.min, pos2(below.min.x + s(271.0), below.max.y));
                self.sidebar(ui, side);
                let mut content = Rect::from_min_max(pos2(side.max.x, below.min.y), below.max);
                let panel_rect = if self.panel != Panel::None {
                    let pw = s(507.0);
                    let pr = Rect::from_min_max(pos2(content.max.x - pw, content.min.y), content.max);
                    content.max.x = pr.min.x;
                    Some(pr)
                } else {
                    None
                };
                let inner = self.header(ui, content);
                self.page_body(ui, inner);
                if let Some(pr) = panel_rect
                    && self.panel != Panel::None {
                        self.side_panel(ui, pr);
                    }
            }
            TabSel::Sftp => self.sftp_view(ui, below),
            TabSel::Session(id) => {
                let font = self.vault.settings.font_size;
                let focus = std::mem::take(&mut self.focus_term)
                    || (self.popup.is_none() && self.modal.is_none() && ctx.memory(|m| m.focused().is_none()));
                if let Some(sess) = self.sessions.iter_mut().find(|s| s.id == id) {
                    sess.term.show(ui, below, font, Id::unique(("term", id)), focus);
                } else {
                    self.tab = TabSel::Vaults;
                }
            }
        }
        self.title_bar(ui, tb);
        ui.painter().line_segment([pos2(full.min.x, tb.max.y - 0.5), pos2(full.max.x, tb.max.y - 0.5)], Stroke::new(1.0, BORDER));
        self.edge_resize(ui, full);
        self.popups(&ctx);
        self.modals(&ctx);
        self.toast_ui(&ctx, full);

        // Keep sessions flowing even when their tab is hidden.
        if !self.sessions.is_empty() || !self.forwards.is_empty() || self.gen_job.is_some() || self.panes.iter().any(|p| p.busy) {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }

        // --screenshot: draw ~120 frames, save the picture, exit.
        if let Some(path) = self.shot.clone() {
            ctx.request_repaint();
            if self.frame_no >= 120 && !self.shot_sent {
                self.shot_sent = true;
                let done = self.shot_done.clone();
                let ctx2 = ctx.clone();
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::ScreenshotCallback::new(move |img| {
                    if let Some(parent) = path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let [w, h] = img.size;
                    let mut buf = Vec::with_capacity(w * h * 4);
                    for p in &img.pixels {
                        buf.extend_from_slice(&[p.r(), p.g(), p.b(), 255]);
                    }
                    if let Some(im) = image::RgbaImage::from_raw(w as u32, h as u32, buf) {
                        let _ = im.save(&path);
                    }
                    done.store(true, Ordering::SeqCst);
                    ctx2.request_repaint();
                })));
            }
            if self.shot_done.load(Ordering::SeqCst) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            if self.frame_no > 900 {
                std::process::exit(1);
            }
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        for s in self.sessions.iter_mut() {
            s.term.kill();
            if let Some(li) = s.log
                && let Some(l) = self.vault.logs.get_mut(li)
                    && l.ended.is_none() {
                        l.ended = Some(now());
                    }
        }
        for f in self.forwards.values_mut() {
            f.kill();
        }
        if self.persist {
            let _ = self.vault.save();
        }
        crate::model::clear_key_files();
    }
}

fn panel_key(p: &Panel) -> (u8, u64) {
    match p {
        Panel::None => (0, 0),
        Panel::Host(i) => (1, *i),
        Panel::Key(i) => (2, *i),
        Panel::Forward(i) => (3, *i),
        Panel::Snippet(i) => (4, *i),
        Panel::Generate => (5, 0),
    }
}

fn key_type_of(public: &str) -> String {
    match public.split_whitespace().next() {
        Some("ssh-ed25519") => "ED25519".into(),
        Some("ssh-rsa") => "RSA".into(),
        Some(t) if t.starts_with("ecdsa") => "ECDSA".into(),
        Some(t) if t.starts_with("sk-") => "Security key".into(),
        _ => "Key".into(),
    }
}

fn modal_frame() -> egui::Frame {
    egui::Frame::new().fill(SIDEBAR_BG).stroke(Stroke::new(1.0, BORDER)).corner_radius(12.0).inner_margin(s(28.0))
}

fn menu_item(ui: &mut Ui, label: &str, icon: Icon) -> bool {
    let (r, resp) = ui.allocate_exact_size(vec2(ui.available_width(), s(46.0)), Sense::click());
    let bg = if resp.hovered() { HOVER } else { SIDEBAR_BG };
    if resp.hovered() {
        ui.painter().rect_filled(r, s(8.0), HOVER);
    }
    draw_icon(ui.painter(), icon, pos2(r.min.x + s(22.0), r.center().y), s(18.0), TEXT, bg);
    text(ui.painter(), pos2(r.min.x + s(46.0), r.center().y), Align2::LEFT_CENTER, label, semi(s(19.0)), TEXT);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked()
}

/// A rounded card section inside the side panel.
fn section(ui: &mut Ui, title: Option<&str>, add: impl FnOnce(&mut Ui)) {
    egui::Frame::new().fill(SECTION_BG).corner_radius(s(12.0)).inner_margin(s(30.0)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.spacing_mut().item_spacing.y = s(16.0);
        if let Some(t) = title {
            ui.label(egui::RichText::new(t).font(bold(s(20.0))).color(TEXT));
        }
        add(ui);
    });
}

fn vault_card(ui: &mut Ui) {
    let w = ui.available_width();
    let (r, _) = ui.allocate_exact_size(vec2(w, s(77.0)), Sense::hover());
    ui.painter().rect_filled(r, s(12.0), SECTION_BG);
    draw_icon(ui.painter(), Icon::Vault, pos2(r.min.x + s(41.0), r.center().y), s(22.0), TEXT, SECTION_BG);
    text(ui.painter(), pos2(r.min.x + s(68.0), r.center().y), Align2::LEFT_CENTER, "Local", semi(s(20.0)), TEXT);
    draw_icon(ui.painter(), Icon::ChevronDown, pos2(r.max.x - s(38.0), r.center().y), s(16.0), TEXT, SECTION_BG);
}

/// Outlined form field with optional leading icon; returns true when edited.
fn form_field(ui: &mut Ui, id: &str, value: &mut String, hint: &str, icon: Option<Icon>, password: bool) -> bool {
    let w = ui.available_width();
    let (r, _) = ui.allocate_exact_size(vec2(w, s(52.0)), Sense::hover());
    let fr = if let Some(ic) = icon {
        draw_icon(ui.painter(), ic, pos2(r.min.x + s(26.0), r.center().y), s(20.0), GREY, SECTION_BG);
        ui.painter().rect_stroke(r, s(9.0), Stroke::new(1.0, FIELD_BORDER), StrokeKind::Inside);
        Rect::from_min_max(pos2(r.min.x + s(30.0), r.min.y), r.max)
    } else {
        r
    };
    let border = if icon.is_some() { None } else { Some(FIELD_BORDER) };
    field(ui, fr, id, value, hint, Color32::TRANSPARENT, border, password, regular(s(20.0))).changed()
}
