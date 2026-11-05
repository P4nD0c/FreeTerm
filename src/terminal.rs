//! A terminal session: a program (shell, ssh.exe) in a pseudo-terminal or a serial
//! port, decoded with vt100 and drawn with egui.

use eframe::egui::{
    self, Color32, EventFilter, FontId, Id, Key, Modifiers, Pos2, Rect, Sense, Stroke, Vec2,
    text::{LayoutJob, TextFormat},
};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::io::{Read, Write};
use std::num::NonZeroU16;
use std::sync::mpsc::{Receiver, channel};

// FreeTerm "Graphite" colour scheme.
pub const TERM_BG: Color32 = Color32::from_rgb(0x0f, 0x11, 0x15);
pub const TERM_FG: Color32 = Color32::from_rgb(0xd8, 0xde, 0xe9);
pub const TERM_CURSOR: Color32 = Color32::from_rgb(0x2b, 0xb3, 0xa3);
const TERM_SELECTION: Color32 = Color32::from_rgba_premultiplied(0x15, 0x59, 0x51, 0x80);
const PALETTE: [u32; 16] = [
    0x1d2027, 0xe5534b, 0x3ccb7f, 0xe5b454, 0x4a8fe0, 0xb57edc, 0x2bb3a3, 0xd8dee9, 0x5b616d,
    0xff7a72, 0x6fe0a0, 0xf5cf7a, 0x79adf0, 0xcf9df0, 0x5fd6c7, 0xffffff,
];

/// Terminal size before the first resize.
pub const DEFAULT_COLS: u16 = 80;
pub const DEFAULT_ROWS: u16 = 24;
/// Scrollback lines kept per terminal.
pub const SCROLLBACK_LINES: usize = 40000;
/// Terminal type sent to servers.
pub const TERM_TYPE: &str = "xterm-256color";

fn hex(c: u32) -> Color32 {
    Color32::from_rgb((c >> 16) as u8, (c >> 8) as u8, c as u8)
}

fn idx_color(i: u8) -> Color32 {
    match i {
        0..=15 => hex(PALETTE[i as usize]),
        16..=231 => {
            let i = i - 16;
            const L: [u8; 6] = [0, 95, 135, 175, 215, 255];
            Color32::from_rgb(L[(i / 36) as usize], L[((i / 6) % 6) as usize], L[(i % 6) as usize])
        }
        _ => {
            let g = 8 + 10 * (i - 232);
            Color32::from_rgb(g, g, g)
        }
    }
}

fn to_color(c: vt100::Color, fg: bool, bold: bool) -> Color32 {
    match c {
        vt100::Color::Default => {
            if fg { TERM_FG } else { TERM_BG }
        }
        // `bold` is only true here when the "brighten bold" setting is on.
        vt100::Color::Idx(i) => idx_color(if fg && bold && i < 8 { i + 8 } else { i }),
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
    }
}

/// A saved secret typed automatically when OpenSSH asks for it during login.
struct Secret {
    kind: SecretKind,
    value: String,
    sent: bool,
}

#[derive(Clone, Copy)]
enum SecretKind {
    Password,
    Passphrase,
}

/// Saved secrets are only typed during the first moments of a session, while
/// OpenSSH is logging in; after that, prompts on screen come from the server.
const SECRET_WINDOW: std::time::Duration = std::time::Duration::from_secs(90);

/// True when the line the cursor sits on is an OpenSSH login prompt for `kind`.
fn is_login_prompt(line: &str, kind: SecretKind) -> bool {
    let l = line.trim().to_lowercase();
    match kind {
        // "user@host's password:" (OpenSSH) or a bare "Password:" (keyboard-interactive).
        SecretKind::Password => l.ends_with("'s password:") || l == "password:",
        // "Enter passphrase for key 'C:\...\key-1':"
        SecretKind::Passphrase => l.starts_with("enter passphrase for key") && l.ends_with(':'),
    }
}

pub struct Term {
    parser: vt100::Parser,
    rx: Receiver<Vec<u8>>,
    writer: Box<dyn Write + Send>,
    master: Option<Box<dyn MasterPty + Send>>,
    child: Option<Box<dyn Child + Send + Sync>>,
    rows: u16,
    cols: u16,
    pub exited: bool,
    /// Exit code of the program (255 from ssh.exe means the connection failed or dropped).
    pub exit_code: Option<u32>,
    /// brightenBoldText setting (default off).
    pub bright_bold: bool,
    pub ctrl_h: bool,
    secrets: Vec<Secret>,
    secrets_until: std::time::Instant,
    line: String,
    /// Commands typed since the app last looked (for Shell History).
    pub typed_commands: Vec<String>,
    sel_start: Option<(u16, u16)>,
    sel_end: Option<(u16, u16)>,
    pub has_output: bool,
}

impl Term {
    pub fn spawn(cmd: CommandBuilder, ctx: &egui::Context) -> Result<Term, String> {
        let pty = native_pty_system();
        let pair = pty
            .openpty(PtySize { rows: DEFAULT_ROWS, cols: DEFAULT_COLS, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| e.to_string())?;
        let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 16384];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                        ctx.request_repaint();
                    }
                }
            }
            ctx.request_repaint();
        });
        Ok(Term::new(rx, writer, Some(pair.master), Some(child)))
    }

    pub fn serial(path: &str, baud: u32, ctx: &egui::Context) -> Result<Term, String> {
        let port = serialport::new(path, baud)
            .data_bits(serialport::DataBits::Eight)
            .stop_bits(serialport::StopBits::One)
            .parity(serialport::Parity::None)
            .flow_control(serialport::FlowControl::None)
            .timeout(std::time::Duration::from_millis(50))
            .open()
            .map_err(|e| e.to_string())?;
        let mut reader = port.try_clone().map_err(|e| e.to_string())?;
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {}
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                        ctx.request_repaint();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => break,
                }
            }
            ctx.request_repaint();
        });
        let mut t = Term::new(rx, Box::new(port), None, None);
        t.parser.process(format!("Connected to {} at {} baud.\r\n", path, baud).as_bytes());
        Ok(t)
    }

    fn new(
        rx: Receiver<Vec<u8>>,
        writer: Box<dyn Write + Send>,
        master: Option<Box<dyn MasterPty + Send>>,
        child: Option<Box<dyn Child + Send + Sync>>,
    ) -> Term {
        Term {
            parser: vt100::Parser::new(nz(DEFAULT_ROWS), nz(DEFAULT_COLS), SCROLLBACK_LINES),
            rx,
            writer,
            master,
            child,
            rows: DEFAULT_ROWS,
            cols: DEFAULT_COLS,
            exited: false,
            exit_code: None,
            bright_bold: false,
            ctrl_h: false,
            secrets: Vec::new(),
            secrets_until: std::time::Instant::now() + SECRET_WINDOW,
            line: String::new(),
            typed_commands: Vec::new(),
            sel_start: None,
            sel_end: None,
            has_output: false,
        }
    }

    pub fn auto_password(&mut self, password: &str) {
        if !password.is_empty() {
            self.secrets.push(Secret { kind: SecretKind::Password, value: password.to_string(), sent: false });
        }
    }
    pub fn auto_passphrase(&mut self, passphrase: &str) {
        if !passphrase.is_empty() {
            self.secrets.push(Secret { kind: SecretKind::Passphrase, value: passphrase.to_string(), sent: false });
        }
    }

    /// Shows a message in the terminal (not sent to the program).
    pub fn print(&mut self, text: &str) {
        self.parser.process(text.as_bytes());
    }

    pub fn write(&mut self, bytes: &[u8]) {
        let _ = self.writer.write_all(bytes);
        let _ = self.writer.flush();
    }

    /// Types a command (snippet) followed by Enter.
    pub fn run_command(&mut self, script: &str) {
        for line in script.replace("\r\n", "\n").lines() {
            self.write(line.as_bytes());
            self.write(b"\r");
        }
    }

    pub fn kill(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
        }
        self.exited = true;
    }

    /// Reads new output; call once per frame even when the tab is hidden.
    pub fn poll(&mut self) {
        let mut got = false;
        while let Ok(bytes) = self.rx.try_recv() {
            self.parser.process(&bytes);
            self.answer_queries(&bytes);
            got = true;
        }
        if got {
            self.has_output = true;
            self.check_secrets();
        }
        if let Some(c) = self.child.as_mut() {
            if let Ok(Some(status)) = c.try_wait() {
                self.exit_code = Some(status.exit_code());
                if !self.exited {
                    // Drain whatever is left.
                    while let Ok(bytes) = self.rx.try_recv() {
                        self.parser.process(&bytes);
                    }
                    self.parser.process(b"\r\n\x1b[90m[Session ended]\x1b[0m\r\n");
                }
                self.exited = true;
            }
        } else if self.master.is_none() && self.rx_closed() {
            self.exited = true;
        }
    }

    /// Replies to terminal queries (cursor position, device attributes);
    /// Windows' pseudo-console waits for the cursor reply before it starts.
    fn answer_queries(&mut self, bytes: &[u8]) {
        let find = |pat: &[u8]| bytes.windows(pat.len()).any(|w| w == pat);
        if find(b"\x1b[6n") {
            let (r, c) = self.parser.screen().cursor_position();
            let reply = format!("\x1b[{};{}R", r + 1, c + 1);
            self.write(reply.as_bytes());
        }
        if find(b"\x1b[c") || find(b"\x1b[0c") {
            self.write(b"\x1b[?1;2c");
        }
    }

    fn rx_closed(&self) -> bool {
        matches!(self.rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Disconnected))
    }

    fn check_secrets(&mut self) {
        if self.secrets.is_empty() {
            return;
        }
        if std::time::Instant::now() > self.secrets_until {
            // Login is over: forget the secrets so nothing can trigger them later.
            self.secrets.clear();
            return;
        }
        let screen = self.parser.screen();
        let (row, col) = screen.cursor_position();
        let mut line = String::new();
        for c in 0..col.min(self.cols) {
            if let Some(cell) = screen.cell(row, c) {
                line.push_str(cell.contents());
            }
        }
        let mut to_send = Vec::new();
        for s in self.secrets.iter_mut() {
            if !s.sent && is_login_prompt(&line, s.kind) {
                s.sent = true;
                to_send.push(s.value.clone());
            }
        }
        for v in to_send {
            self.write(v.as_bytes());
            self.write(b"\r");
        }
    }

    pub fn screen_text(&self) -> String {
        self.parser.screen().contents()
    }

    fn resize(&mut self, rows: u16, cols: u16) {
        if rows == self.rows && cols == self.cols {
            return;
        }
        self.rows = rows;
        self.cols = cols;
        self.parser.set_size(nz(rows), nz(cols));
        if let Some(m) = self.master.as_ref() {
            let _ = m.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
        }
    }

    /// Draws the terminal into `rect` and handles keyboard/mouse input.
    pub fn show(&mut self, ui: &mut egui::Ui, rect: Rect, font_size: f32, id: Id, want_focus: bool) {
        let font = FontId::monospace(font_size);
        let (cw, ch) = ui.ctx().fonts_mut(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));
        let inner = rect.shrink2(Vec2::new(14.0, 10.0));
        let cols = ((inner.width() / cw).floor() as u16).clamp(2, 1000);
        let rows = ((inner.height() / ch).floor() as u16).clamp(2, 500);
        self.resize(rows, cols);

        let resp = ui.interact(rect, id, Sense::click_and_drag());
        if want_focus || resp.clicked() || resp.drag_started() {
            resp.request_focus();
        }
        let cell_at = |p: Pos2| -> (u16, u16) {
            let c = ((p.x - inner.min.x) / cw).floor().clamp(0.0, (cols - 1) as f32) as u16;
            let r = ((p.y - inner.min.y) / ch).floor().clamp(0.0, (rows - 1) as f32) as u16;
            (r, c)
        };
        if resp.drag_started() {
            if let Some(p) = resp.interact_pointer_pos() {
                self.sel_start = Some(cell_at(p));
                self.sel_end = self.sel_start;
            }
        } else if resp.dragged() {
            if let Some(p) = resp.interact_pointer_pos() {
                self.sel_end = Some(cell_at(p));
            }
        } else if resp.clicked() {
            self.sel_start = None;
            self.sel_end = None;
        }

        // Context menu: copy / paste.
        let selection = self.selection_text();
        let mut paste_req = false;
        resp.context_menu(|ui| {
            if ui.add_enabled(selection.is_some(), egui::Button::new("Copy")).clicked() {
                if let Some(s) = &selection {
                    ui.ctx().copy_text(s.clone());
                }
                ui.close();
            }
            if ui.button("Paste").clicked() {
                paste_req = true;
                ui.close();
            }
        });
        if paste_req {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestPaste);
            resp.request_focus();
        }

        if resp.hovered() {
            let dy = ui.input(|i| i.smooth_scroll_delta.y);
            if dy != 0.0 {
                let screen = self.parser.screen_mut();
                let cur = screen.scrollback();
                let lines = (dy.abs() / ch).ceil().max(1.0) as usize * 3;
                let new = if dy > 0.0 { cur + lines } else { cur.saturating_sub(lines) };
                screen.set_scrollback(new);
            }
        }

        if resp.has_focus() {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(
                    id,
                    EventFilter { tab: true, horizontal_arrows: true, vertical_arrows: true, escape: true },
                )
            });
            self.handle_input(ui, selection);
        }

        self.paint(ui, rect, inner, &font, cw, ch, resp.has_focus());
    }

    fn selection_range(&self) -> Option<((u16, u16), (u16, u16))> {
        let (a, b) = (self.sel_start?, self.sel_end?);
        if a == b {
            return None;
        }
        Some(if a <= b { (a, b) } else { (b, a) })
    }

    fn selection_text(&self) -> Option<String> {
        let (a, b) = self.selection_range()?;
        Some(self.parser.screen().contents_between(a.0, a.1, b.0, b.1 + 1))
    }

    fn handle_input(&mut self, ui: &mut egui::Ui, selection: Option<String>) {
        let events = ui.input(|i| i.events.clone());
        let app_cursor = self.parser.screen().application_cursor();
        let bracketed = self.parser.screen().bracketed_paste();
        let mut out: Vec<u8> = Vec::new();
        for ev in events {
            match ev {
                egui::Event::Text(t) => {
                    out.extend_from_slice(t.as_bytes());
                    self.line.push_str(&t);
                }
                egui::Event::Paste(t) => {
                    let t = t.replace("\r\n", "\r").replace('\n', "\r");
                    if bracketed {
                        out.extend_from_slice(b"\x1b[200~");
                    }
                    out.extend_from_slice(t.as_bytes());
                    if bracketed {
                        out.extend_from_slice(b"\x1b[201~");
                    }
                }
                egui::Event::Copy => {
                    if let Some(s) = &selection {
                        ui.ctx().copy_text(s.clone());
                        self.sel_start = None;
                        self.sel_end = None;
                    } else {
                        out.push(0x03);
                        self.line.clear();
                    }
                }
                egui::Event::Cut => out.push(0x18),
                egui::Event::Key { key, pressed: true, modifiers, .. } => {
                    if let Some(b) = key_bytes(key, modifiers, app_cursor, self.ctrl_h) {
                        out.extend_from_slice(&b);
                    }
                    match key {
                        Key::Enter => {
                            let cmd = self.line.trim().to_string();
                            if !cmd.is_empty() {
                                self.typed_commands.push(cmd);
                            }
                            self.line.clear();
                        }
                        Key::Backspace => {
                            self.line.pop();
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        if !out.is_empty() {
            self.parser.screen_mut().set_scrollback(0);
            self.write(&out);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn paint(&self, ui: &egui::Ui, rect: Rect, inner: Rect, font: &FontId, cw: f32, ch: f32, focused: bool) {
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, TERM_BG);
        let screen = self.parser.screen();
        let sel = self.selection_range();
        let in_sel = |r: u16, c: u16| match sel {
            Some((a, b)) => (r, c) >= a && (r, c) <= b,
            None => false,
        };
        for r in 0..self.rows {
            let y = inner.min.y + r as f32 * ch;
            let mut job = LayoutJob::default();
            job.wrap.max_width = f32::INFINITY;
            let mut run_start_col: Option<u16> = None;
            let mut c = 0u16;
            let flush = |job: &mut LayoutJob, start: &mut Option<u16>| {
                if let Some(s) = start.take() {
                    let j = std::mem::take(job);
                    let galley = ui.ctx().fonts_mut(|f| f.layout_job(j));
                    painter.galley(Pos2::new(inner.min.x + s as f32 * cw, y), galley, TERM_FG);
                    job.wrap.max_width = f32::INFINITY;
                }
            };
            while c < self.cols {
                let Some(cell) = screen.cell(r, c) else { break };
                if cell.is_wide_continuation() {
                    c += 1;
                    continue;
                }
                let w = if cell.is_wide() { 2 } else { 1 };
                let mut fg = to_color(cell.fgcolor(), true, cell.bold() && self.bright_bold);
                let mut bg = to_color(cell.bgcolor(), false, false);
                if cell.inverse() {
                    std::mem::swap(&mut fg, &mut bg);
                }
                if cell.dim() {
                    fg = fg.gamma_multiply(0.6);
                }
                let x = inner.min.x + c as f32 * cw;
                let cell_rect = Rect::from_min_size(Pos2::new(x, y), Vec2::new(cw * w as f32, ch));
                if bg != TERM_BG {
                    painter.rect_filled(cell_rect, 0.0, bg);
                }
                if in_sel(r, c) {
                    painter.rect_filled(cell_rect, 0.0, TERM_SELECTION);
                }
                let text = cell.contents();
                let text = if text.is_empty() { " " } else { text };
                let ascii = text.len() == 1 && text.as_bytes()[0].is_ascii_graphic() || text == " ";
                let fmt = TextFormat {
                    font_id: font.clone(),
                    color: fg,
                    underline: if cell.underline() { Stroke::new(1.0, fg) } else { Stroke::NONE },
                    italics: cell.italic(),
                    ..Default::default()
                };
                if ascii && w == 1 {
                    if run_start_col.is_none() {
                        run_start_col = Some(c);
                    }
                    job.append(text, 0.0, fmt);
                } else {
                    flush(&mut job, &mut run_start_col);
                    painter.text(Pos2::new(x, y), egui::Align2::LEFT_TOP, text, font.clone(), fg);
                }
                c += w;
            }
            flush(&mut job, &mut run_start_col);
        }
        // Cursor
        if screen.scrollback() == 0 && !screen.hide_cursor() {
            let (cr, cc) = screen.cursor_position();
            if cr < self.rows && cc < self.cols {
                let p = Pos2::new(inner.min.x + cc as f32 * cw, inner.min.y + cr as f32 * ch);
                let r = Rect::from_min_size(p, Vec2::new(cw, ch));
                if focused {
                    painter.rect_filled(r, 0.0, TERM_CURSOR);
                    if let Some(cell) = screen.cell(cr, cc) {
                        let t = cell.contents();
                        if !t.is_empty() {
                            painter.text(p, egui::Align2::LEFT_TOP, t, font.clone(), TERM_BG);
                        }
                    }
                } else {
                    painter.rect_stroke(r, 0.0, Stroke::new(1.0, TERM_CURSOR), egui::StrokeKind::Inside);
                }
            }
        }
    }
}

fn nz(v: u16) -> NonZeroU16 {
    NonZeroU16::new(v.max(1)).unwrap_or(NonZeroU16::MIN)
}

fn key_bytes(key: Key, m: Modifiers, app_cursor: bool, ctrl_h: bool) -> Option<Vec<u8>> {
    let arrow = |c: u8| -> Vec<u8> {
        if m.ctrl {
            vec![0x1b, b'[', b'1', b';', b'5', c]
        } else if app_cursor {
            vec![0x1b, b'O', c]
        } else {
            vec![0x1b, b'[', c]
        }
    };
    let s: Vec<u8> = match key {
        Key::Enter => b"\r".to_vec(),
        Key::Tab => if m.shift { b"\x1b[Z".to_vec() } else { b"\t".to_vec() },
        Key::Backspace => if ctrl_h { vec![0x08] } else { vec![0x7f] },
        Key::Escape => vec![0x1b],
        Key::ArrowUp => arrow(b'A'),
        Key::ArrowDown => arrow(b'B'),
        Key::ArrowRight => arrow(b'C'),
        Key::ArrowLeft => arrow(b'D'),
        Key::Home => b"\x1b[H".to_vec(),
        Key::End => b"\x1b[F".to_vec(),
        Key::PageUp => b"\x1b[5~".to_vec(),
        Key::PageDown => b"\x1b[6~".to_vec(),
        Key::Delete => b"\x1b[3~".to_vec(),
        Key::Insert => b"\x1b[2~".to_vec(),
        Key::F1 => b"\x1bOP".to_vec(),
        Key::F2 => b"\x1bOQ".to_vec(),
        Key::F3 => b"\x1bOR".to_vec(),
        Key::F4 => b"\x1bOS".to_vec(),
        Key::F5 => b"\x1b[15~".to_vec(),
        Key::F6 => b"\x1b[17~".to_vec(),
        Key::F7 => b"\x1b[18~".to_vec(),
        Key::F8 => b"\x1b[19~".to_vec(),
        Key::F9 => b"\x1b[20~".to_vec(),
        Key::F10 => b"\x1b[21~".to_vec(),
        Key::F11 => b"\x1b[23~".to_vec(),
        Key::F12 => b"\x1b[24~".to_vec(),
        _ => {
            if m.ctrl && !m.alt {
                let name = key.name();
                let b = name.as_bytes();
                if b.len() == 1 && b[0].is_ascii_alphabetic() {
                    return Some(vec![b[0].to_ascii_uppercase() - b'A' + 1]);
                }
                return match key {
                    Key::Space => Some(vec![0]),
                    Key::OpenBracket => Some(vec![0x1b]),
                    Key::Backslash => Some(vec![0x1c]),
                    Key::CloseBracket => Some(vec![0x1d]),
                    _ => None,
                };
            }
            return None;
        }
    };
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn login_prompts() {
        assert!(is_login_prompt("root@10.0.0.1's password: ", SecretKind::Password));
        assert!(is_login_prompt("Password:", SecretKind::Password));
        assert!(!is_login_prompt("[sudo] password for root:", SecretKind::Password));
        assert!(!is_login_prompt("$ echo password:", SecretKind::Password));
        assert!(is_login_prompt(r"Enter passphrase for key 'C:\k\key-1': ", SecretKind::Passphrase));
    }
    #[test]
    fn shell_output_arrives() {
        let ctx = egui::Context::default();
        let mut c = CommandBuilder::new("cmd.exe");
        c.arg("/c");
        c.arg("echo hello-from-pty");
        let mut t = Term::spawn(c, &ctx).expect("spawn");
        let start = std::time::Instant::now();
        while start.elapsed().as_secs() < 10 {
            t.poll();
            if t.screen_text().contains("hello-from-pty") {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("no output: {:?}", t.screen_text());
    }
}
