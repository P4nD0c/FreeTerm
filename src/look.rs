//! Colours, fonts, icons and small drawn widgets.
//! Layout sizes are written at 125 % scale and converted with `s()`.

use eframe::egui::{
    self, Align2, Color32, CornerRadius, FontFamily, FontId, Painter, Pos2, Rect, Response, Sense,
    Shape, Stroke, StrokeKind, Ui, Vec2, pos2, vec2,
};

/// Design pixels (125 % scale) to points.
pub fn s(v: f32) -> f32 {
    v * 0.8
}

pub const TITLE_BG: Color32 = Color32::from_rgb(0x0F, 0x11, 0x15);
pub const SIDEBAR_BG: Color32 = Color32::from_rgb(0x17, 0x1A, 0x20);
pub const CONTENT_BG: Color32 = Color32::from_rgb(0x1D, 0x20, 0x27);
pub const SELECTED: Color32 = Color32::from_rgb(0x2D, 0x32, 0x3C);
pub const HOVER: Color32 = Color32::from_rgb(0x25, 0x29, 0x30);
pub const FIELD_BG: Color32 = Color32::from_rgb(0x2A, 0x2E, 0x37);
pub const BUTTON: Color32 = Color32::from_rgb(0x2B, 0x30, 0x39);
pub const BUTTON_HOVER: Color32 = Color32::from_rgb(0x37, 0x3D, 0x48);
pub const VAULT_BTN: Color32 = Color32::from_rgb(0x1F, 0x23, 0x2A);
pub const ACCENT: Color32 = Color32::from_rgb(0x2B, 0xB3, 0xA3);
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(0x46, 0xC6, 0xB7);
pub const TEXT: Color32 = Color32::from_rgb(0xEC, 0xEE, 0xF2);
pub const GREY: Color32 = Color32::from_rgb(0x91, 0x98, 0xA4);
pub const DIM: Color32 = Color32::from_rgb(0x5B, 0x61, 0x6D);
pub const BORDER: Color32 = Color32::from_rgb(0x2A, 0x2F, 0x38);
pub const FIELD_BORDER: Color32 = Color32::from_rgb(0x36, 0x3C, 0x47);
pub const ICON_BOX: Color32 = Color32::from_rgb(0x22, 0x26, 0x2E);
pub const CARD: Color32 = Color32::from_rgb(0x22, 0x26, 0x2E);
pub const CARD_HOVER: Color32 = Color32::from_rgb(0x2A, 0x2F, 0x38);
pub const SECTION_BG: Color32 = Color32::from_rgb(0x23, 0x27, 0x2F);
pub const HOST_ICON: Color32 = Color32::from_rgb(0x1E, 0x6E, 0x66);
pub const PINK: Color32 = Color32::from_rgb(0xE0, 0x60, 0x7E);
pub const GREEN: Color32 = Color32::from_rgb(0x3C, 0xCB, 0x7F);
pub const RED: Color32 = Color32::from_rgb(0xE5, 0x53, 0x4B);

pub fn semi(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("semi".into()))
}
pub fn bold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("bold".into()))
}
pub fn regular(size: f32) -> FontId {
    FontId::new(size, FontFamily::Proportional)
}

/// Loads Windows' own UI and console fonts when present (not bundled).
pub fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let win = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let load = |name: &str| std::fs::read(format!("{}\\Fonts\\{}", win, name)).ok();
    let mut add = |key: &str, file: &str| -> bool {
        if let Some(bytes) = load(file) {
            fonts.font_data.insert(key.into(), std::sync::Arc::new(egui::FontData::from_owned(bytes)));
            true
        } else {
            false
        }
    };
    let has_regular = add("ui-regular", "segoeui.ttf");
    let has_semi = add("ui-semi", "seguisb.ttf");
    let has_bold = add("ui-bold", "segoeuib.ttf");
    let has_mono = add("ui-mono", "consola.ttf");
    let has_symbols = add("ui-symbols", "seguisym.ttf");
    let base: Vec<String> = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    let mut prop = Vec::new();
    if has_regular {
        prop.push("ui-regular".to_string());
    }
    prop.extend(base.iter().cloned());
    if has_symbols {
        prop.push("ui-symbols".into());
    }
    let mut semi_f = Vec::new();
    if has_semi {
        semi_f.push("ui-semi".to_string());
    }
    semi_f.extend(prop.iter().cloned());
    let mut bold_f = Vec::new();
    if has_bold {
        bold_f.push("ui-bold".to_string());
    } else if has_semi {
        bold_f.push("ui-semi".to_string());
    }
    bold_f.extend(prop.iter().cloned());
    let mut mono: Vec<String> = fonts.families.get(&FontFamily::Monospace).cloned().unwrap_or_default();
    if has_mono {
        mono.insert(0, "ui-mono".into());
    }
    if has_symbols {
        mono.push("ui-symbols".into());
    }
    fonts.families.insert(FontFamily::Proportional, prop);
    fonts.families.insert(FontFamily::Name("semi".into()), semi_f);
    fonts.families.insert(FontFamily::Name("bold".into()), bold_f);
    fonts.families.insert(FontFamily::Monospace, mono);
    ctx.set_fonts(fonts);
}

pub fn style(ctx: &egui::Context) {
    ctx.all_styles_mut(|st| {
        let v = &mut st.visuals;
        *v = egui::Visuals::dark();
        v.panel_fill = CONTENT_BG;
        v.window_fill = SIDEBAR_BG;
        v.window_stroke = Stroke::new(1.0, BORDER);
        v.extreme_bg_color = CONTENT_BG;
        v.faint_bg_color = SIDEBAR_BG;
        v.override_text_color = Some(TEXT);
        v.selection.bg_fill = ACCENT.gamma_multiply(0.6);
        v.selection.stroke = Stroke::new(1.0, TEXT);
        v.text_cursor.stroke = Stroke::new(1.5, ACCENT);
        v.widgets.noninteractive.bg_fill = SIDEBAR_BG;
        v.widgets.inactive.bg_fill = BUTTON;
        v.widgets.inactive.weak_bg_fill = BUTTON;
        v.widgets.hovered.bg_fill = BUTTON_HOVER;
        v.widgets.hovered.weak_bg_fill = BUTTON_HOVER;
        v.widgets.active.bg_fill = SELECTED;
        v.widgets.active.weak_bg_fill = SELECTED;
        for w in [&mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active, &mut v.widgets.open] {
            w.corner_radius = CornerRadius::same(6);
        }
        v.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
        v.widgets.hovered.bg_stroke = Stroke::NONE;
        v.menu_corner_radius = CornerRadius::same(8);
        v.window_corner_radius = CornerRadius::same(10);
        st.spacing.button_padding = vec2(10.0, 6.0);
        st.spacing.item_spacing = vec2(8.0, 8.0);
        st.spacing.menu_margin = egui::Margin::same(6);
        st.text_styles.insert(egui::TextStyle::Body, regular(14.0));
        st.text_styles.insert(egui::TextStyle::Button, semi(14.0));
        st.text_styles.insert(egui::TextStyle::Small, regular(12.0));
        st.text_styles.insert(egui::TextStyle::Heading, bold(18.0));
        st.text_styles.insert(egui::TextStyle::Monospace, FontId::monospace(13.0));
    });
}

pub fn text(p: &Painter, pos: Pos2, anchor: Align2, t: &str, font: FontId, color: Color32) -> Rect {
    p.text(pos, anchor, t, font, color)
}

/// Text cut with "…" to fit `max_w`.
pub fn text_fit(ui: &Ui, pos: Pos2, anchor: Align2, t: &str, font: FontId, color: Color32, max_w: f32) {
    let mut s = t.to_string();
    let width = |ui: &Ui, s: &str| ui.ctx().fonts_mut(|f| f.layout_no_wrap(s.to_string(), font.clone(), color).size().x);
    if width(ui, &s) > max_w {
        while !s.is_empty() && width(ui, &(s.clone() + "…")) > max_w {
            s.pop();
        }
        s.push('…');
    }
    ui.painter().text(pos, anchor, s, font, color);
}

/// A clickable area with a hover background.
pub fn hit(ui: &mut Ui, rect: Rect, id: impl std::hash::Hash + std::fmt::Debug) -> Response {
    let id = ui.scope_id().with(id);
    ui.interact(rect, id, Sense::click())
}

pub fn fill_hover(ui: &Ui, resp: &Response, rect: Rect, base: Color32, hover: Color32, r: f32) {
    let c = if resp.hovered() { hover } else { base };
    if c != Color32::TRANSPARENT {
        ui.painter().rect_filled(rect, r, c);
    }
}

/// A filled button with an optional icon and a label; returns the click response.
#[allow(clippy::too_many_arguments)]
pub fn button(
    ui: &mut Ui,
    rect: Rect,
    id: &str,
    label: &str,
    icon: Option<Icon>,
    fill: Color32,
    hover: Color32,
    text_color: Color32,
    font: FontId,
) -> Response {
    let resp = hit(ui, rect, id);
    fill_hover(ui, &resp, rect, fill, hover, s(8.0));
    let p = ui.painter();
    if let Some(ic) = icon {
        let galley_w = ui.ctx().fonts_mut(|f| f.layout_no_wrap(label.to_string(), font.clone(), text_color).size().x);
        let total = 16.0 + 8.0 + galley_w;
        let x0 = rect.center().x - total / 2.0;
        draw_icon(p, ic, pos2(x0 + 8.0, rect.center().y), 16.0, text_color, fill);
        p.text(pos2(x0 + 24.0, rect.center().y), Align2::LEFT_CENTER, label, font, text_color);
    } else {
        p.text(rect.center(), Align2::CENTER_CENTER, label, font, text_color);
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Ghost (no background until hovered) toolbar button: icon + label, left aligned.
pub fn ghost(ui: &mut Ui, pos: Pos2, h: f32, id: &str, label: &str, icon: Icon) -> (Response, f32) {
    let font = semi(s(21.0));
    let w = ui.ctx().fonts_mut(|f| f.layout_no_wrap(label.to_string(), font.clone(), TEXT).size().x) + s(28.0) + s(48.0);
    let rect = Rect::from_min_size(pos, vec2(w, h));
    let resp = hit(ui, rect, id);
    fill_hover(ui, &resp, rect, Color32::TRANSPARENT, HOVER, s(8.0));
    let p = ui.painter();
    draw_icon(p, icon, pos2(rect.min.x + s(24.0), rect.center().y), s(22.0), TEXT, if resp.hovered() { HOVER } else { SIDEBAR_BG });
    p.text(pos2(rect.min.x + s(50.0), rect.center().y), Align2::LEFT_CENTER, label, font, TEXT);
    (resp.on_hover_cursor(egui::CursorIcon::PointingHand), w)
}

/// Square icon button (toolbar right side, title bar).
pub fn icon_button(ui: &mut Ui, center: Pos2, size: f32, id: &str, icon: Icon, color: Color32, bg: Color32) -> Response {
    let rect = Rect::from_center_size(center, Vec2::splat(size));
    let resp = hit(ui, rect, id);
    fill_hover(ui, &resp, rect, Color32::TRANSPARENT, HOVER, s(8.0));
    draw_icon(ui.painter(), icon, center, size * 0.55, color, if resp.hovered() { HOVER } else { bg });
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A text field: rounded box, grey placeholder.
#[allow(clippy::too_many_arguments)]
pub fn field(
    ui: &mut Ui,
    rect: Rect,
    id: &str,
    value: &mut String,
    hint: &str,
    fill: Color32,
    border: Option<Color32>,
    password: bool,
    font: FontId,
) -> Response {
    let p = ui.painter();
    p.rect_filled(rect, s(9.0), fill);
    let inner = rect.shrink2(vec2(s(15.0), 0.0));
    let te = egui::TextEdit::singleline(value)
        .id_salt(id)
        .hint_text(egui::RichText::new(hint).color(GREY).font(font.clone()))
        .font(font)
        .text_color(TEXT)
        .frame(egui::Frame::NONE)
        .password(password)
        .align(Align2::LEFT_CENTER)
        .desired_width(inner.width());
    let resp = ui.put(inner, te);
    let stroke = if resp.has_focus() { Some(ACCENT) } else { border };
    if let Some(c) = stroke {
        ui.painter().rect_stroke(rect, s(9.0), Stroke::new(1.0, c), StrokeKind::Inside);
    }
    resp
}

/// A multi-line field (keys, scripts).
pub fn area(ui: &mut Ui, rect: Rect, id: &str, value: &mut String, hint: &str, mono: bool) -> Response {
    ui.painter().rect_filled(rect, s(9.0), FIELD_BG);
    let font = if mono { FontId::monospace(12.0) } else { regular(14.0) };
    let mut out = None;
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect.shrink(s(12.0))), |ui| {
        egui::ScrollArea::vertical().id_salt(id).show(ui, |ui| {
            let te = egui::TextEdit::multiline(value)
                .id_salt(id)
                .hint_text(egui::RichText::new(hint).color(GREY))
                .font(font)
                .text_color(TEXT)
                .frame(egui::Frame::NONE)
                .desired_width(ui.available_width())
                .desired_rows(4);
            out = Some(ui.add(te));
        });
    });
    let resp = out.expect("text area shown");
    if resp.has_focus() {
        ui.painter().rect_stroke(rect, s(9.0), Stroke::new(1.0, ACCENT), StrokeKind::Inside);
    }
    resp
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icon {
    Menu,
    Vault,
    Folder,
    File,
    Plus,
    Bell,
    Minimize,
    Maximize,
    Close,
    Hosts,
    Key,
    Forward,
    Braces,
    Fingerprint,
    Clock,
    ChevronDown,
    ChevronLeft,
    Terminal,
    Serial,
    Grid,
    List,
    Tag,
    Calendar,
    Search,
    More,
    Collapse,
    Certificate,
    Face,
    Fido,
    User,
    Lock,
    Eye,
    Backspace,
    Group,
    Play,
    Stop,
    Trash,
    Refresh,
    Up,
    Settings,
}

/// Simple vector icons drawn with egui shapes.
pub fn draw_icon(p: &Painter, icon: Icon, c: Pos2, size: f32, color: Color32, bg: Color32) {
    let u = size / 16.0; // icon grid unit
    let at = |x: f32, y: f32| pos2(c.x + x * u, c.y + y * u);
    let st = Stroke::new((1.6 * u).max(1.0), color);
    let rect = |x0: f32, y0: f32, x1: f32, y1: f32| Rect::from_min_max(at(x0, y0), at(x1, y1));
    match icon {
        Icon::Menu => {
            for y in [-5.0, 0.0, 5.0] {
                p.line_segment([at(-7.0, y), at(7.0, y)], st);
            }
        }
        Icon::Vault => {
            p.rect_filled(rect(-7.5, -6.0, 7.5, 6.0), 3.0 * u, color);
            p.circle_filled(at(0.5, 0.0), 3.3 * u, TITLE_BG);
            p.circle_filled(at(0.5, 0.0), 1.6 * u, color);
            p.circle_filled(at(-4.8, 0.0), 1.0 * u, TITLE_BG);
        }
        Icon::Folder => {
            p.rect_filled(rect(-7.0, -5.5, -1.0, -2.0), 1.5 * u, color);
            p.rect_filled(rect(-7.0, -3.5, 7.0, 5.5), 1.5 * u, color);
        }
        Icon::File => {
            p.rect_stroke(rect(-5.0, -7.0, 5.0, 7.0), 1.5 * u, st, StrokeKind::Middle);
            p.line_segment([at(-2.5, -2.0), at(2.5, -2.0)], st);
            p.line_segment([at(-2.5, 1.5), at(2.5, 1.5)], st);
        }
        Icon::Plus => {
            p.line_segment([at(-6.5, 0.0), at(6.5, 0.0)], st);
            p.line_segment([at(0.0, -6.5), at(0.0, 6.5)], st);
        }
        Icon::Bell => {
            let pts = vec![at(-5.5, 4.0), at(-4.5, 2.5), at(-4.5, -2.0), at(-2.5, -5.5), at(0.0, -6.5), at(2.5, -5.5), at(4.5, -2.0), at(4.5, 2.5), at(5.5, 4.0), at(-5.5, 4.0)];
            p.add(Shape::line(pts, st));
            p.line_segment([at(-1.5, 6.5), at(1.5, 6.5)], st);
        }
        Icon::Minimize => {
            p.line_segment([at(-6.0, 0.0), at(6.0, 0.0)], st);
        }
        Icon::Maximize => {
            p.rect_stroke(rect(-5.5, -5.5, 5.5, 5.5), 1.5 * u, st, StrokeKind::Middle);
        }
        Icon::Close => {
            p.line_segment([at(-5.5, -5.5), at(5.5, 5.5)], st);
            p.line_segment([at(5.5, -5.5), at(-5.5, 5.5)], st);
        }
        Icon::Hosts => {
            for (y0, y1) in [(-7.0, -0.8), (0.8, 7.0)] {
                p.rect_filled(rect(-8.0, y0, 8.0, y1), 1.8 * u, color);
                for i in 0..3 {
                    let x = -5.5 + i as f32 * 2.2;
                    p.rect_filled(rect(x, y0 + 2.0, x + 1.1, y1 - 2.0), 0.0, bg);
                }
                p.circle_filled(at(4.8, (y0 + y1) / 2.0), 1.3 * u, bg);
            }
        }
        Icon::Key => {
            p.circle_filled(at(0.0, -3.5), 3.6 * u, color);
            p.circle_filled(at(0.0, -3.5), 1.3 * u, bg);
            p.rect_filled(rect(-1.1, -1.0, 1.1, 7.5), 0.8 * u, color);
            p.rect_filled(rect(1.0, 3.0, 3.0, 4.6), 0.0, color);
        }
        Icon::Forward => {
            let pts = vec![at(-7.5, 4.5), at(-3.5, -2.0), at(1.0, -2.0), at(1.0, -6.0), at(8.0, 0.5), at(1.0, 6.5), at(1.0, 3.0), at(-2.0, 3.0)];
            p.add(Shape::convex_polygon(pts, color, Stroke::NONE));
            p.add(Shape::convex_polygon(vec![at(-8.0, 6.0), at(-6.0, 1.0), at(-3.5, 1.0), at(-5.5, 6.0)], color, Stroke::NONE));
        }
        Icon::Braces => {
            p.text(c, Align2::CENTER_CENTER, "{ }", bold(size * 1.05), color);
        }
        Icon::Fingerprint => {
            for (i, r) in [2.0f32, 4.3, 6.6].iter().enumerate() {
                let n = 14;
                let start = std::f32::consts::PI * (1.05 + 0.03 * i as f32);
                let end = std::f32::consts::PI * (2.0 - 0.03 * i as f32) + 0.5;
                let pts: Vec<Pos2> = (0..=n)
                    .map(|k| {
                        let a = start + (end - start) * k as f32 / n as f32;
                        at(r * a.cos(), 1.0 + r * a.sin())
                    })
                    .collect();
                p.add(Shape::line(pts, st));
            }
            p.line_segment([at(0.0, 1.0), at(0.0, 7.0)], st);
            p.line_segment([at(-4.3, 1.5), at(-4.3, 6.0)], st);
            p.line_segment([at(4.3, 1.5), at(4.3, 6.5)], st);
        }
        Icon::Clock => {
            p.circle_filled(c, 7.5 * u, color);

            p.line_segment([at(0.0, -4.5), at(0.0, 0.5)], Stroke::new(1.8 * u, bg));
            p.line_segment([at(0.0, 0.5), at(-3.0, 0.5)], Stroke::new(1.8 * u, bg));
        }
        Icon::ChevronDown => {
            p.add(Shape::line(vec![at(-5.5, -2.5), at(0.0, 3.0), at(5.5, -2.5)], Stroke::new(2.0 * u, color)));
        }
        Icon::ChevronLeft => {
            p.add(Shape::line(vec![at(2.5, -5.5), at(-3.0, 0.0), at(2.5, 5.5)], Stroke::new(2.0 * u, color)));
        }
        Icon::Up => {
            p.add(Shape::line(vec![at(-5.5, 2.5), at(0.0, -3.0), at(5.5, 2.5)], Stroke::new(2.0 * u, color)));
        }
        Icon::Terminal => {
            p.add(Shape::convex_polygon(vec![at(-7.0, -2.0), at(1.0, -7.5), at(7.0, -4.0), at(7.0, 7.0), at(-7.0, 7.0)], color, Stroke::NONE));

            p.add(Shape::line(vec![at(-4.0, 0.5), at(-1.5, 2.5), at(-4.0, 4.5)], Stroke::new(1.3 * u, bg)));
            p.line_segment([at(0.0, 4.5), at(3.0, 4.5)], Stroke::new(1.3 * u, bg));
        }
        Icon::Serial => {
            p.add(Shape::convex_polygon(vec![at(-8.0, -5.0), at(8.0, -5.0), at(6.0, 5.0), at(-6.0, 5.0)], color, Stroke::NONE));

            for x in [-4.5, -1.5, 1.5, 4.5] {
                p.circle_filled(at(x, -1.5), 1.0 * u, bg);
            }
            for x in [-3.0, 0.0, 3.0] {
                p.circle_filled(at(x, 1.8), 1.0 * u, bg);
            }
        }
        Icon::Grid => {
            for (x, y) in [(-7.0, -7.0), (1.0, -7.0), (-7.0, 1.0), (1.0, 1.0)] {
                p.rect_filled(rect(x, y, x + 6.0, y + 6.0), 1.0 * u, color);
            }
        }
        Icon::List => {
            for y in [-6.0, -1.0, 4.0] {
                p.rect_filled(rect(-7.0, y, 7.0, y + 3.0), 1.0 * u, color);
            }
        }
        Icon::Tag => {
            let pts = vec![at(-7.0, -7.0), at(0.5, -7.0), at(7.5, 0.0), at(0.0, 7.5), at(-7.0, 0.5)];
            p.add(Shape::convex_polygon(pts, color, Stroke::NONE));
            p.circle_filled(at(-3.5, -3.5), 1.4 * u, bg);
        }
        Icon::Calendar => {
            p.rect_stroke(rect(-7.0, -6.0, 7.0, 7.0), 1.8 * u, st, StrokeKind::Middle);
            p.line_segment([at(-7.0, -2.5), at(7.0, -2.5)], st);
            for row in 0..2 {
                for col in 0..4 {
                    p.circle_filled(at(-4.2 + col as f32 * 2.8, 0.7 + row as f32 * 3.0), 0.75 * u, color);
                }
            }
        }
        Icon::Search => {
            p.circle_stroke(at(-1.5, -1.5), 5.0 * u, Stroke::new(2.0 * u, color));
            p.line_segment([at(2.3, 2.3), at(7.0, 7.0)], Stroke::new(2.4 * u, color));
        }
        Icon::More => {
            for x in [-5.5, 0.0, 5.5] {
                p.circle_filled(at(x, 0.0), 1.6 * u, color);
            }
        }
        Icon::Collapse => {
            p.line_segment([at(-7.0, 0.0), at(4.0, 0.0)], Stroke::new(2.0 * u, color));
            p.add(Shape::line(vec![at(0.0, -4.5), at(4.5, 0.0), at(0.0, 4.5)], Stroke::new(2.0 * u, color)));
            p.line_segment([at(7.5, -6.5), at(7.5, 6.5)], Stroke::new(2.0 * u, color));
        }
        Icon::Certificate => {
            p.add(Shape::convex_polygon(vec![at(-5.5, -7.5), at(2.5, -7.5), at(5.5, -4.5), at(5.5, 7.5), at(-5.5, 7.5)], color, Stroke::NONE));
            p.circle_filled(at(0.0, 2.0), 2.6 * u, bg);
            p.circle_filled(at(0.0, 2.0), 1.3 * u, color);
        }
        Icon::Face => {
            p.circle_filled(at(-3.0, -2.5), 1.3 * u, color);
            p.circle_filled(at(3.0, -2.5), 1.3 * u, color);
            let pts: Vec<Pos2> = (0..=10).map(|k| {
                let a = std::f32::consts::PI * (0.15 + 0.7 * k as f32 / 10.0);
                at(4.0 * a.cos(), 1.0 + 3.5 * a.sin())
            }).collect();
            p.add(Shape::line(pts, st));
        }
        Icon::Fido => {
            p.rect_filled(rect(-8.0, -3.5, 4.0, 3.5), 1.8 * u, color);
            p.rect_filled(rect(4.0, -2.0, 8.0, 2.0), 0.5 * u, color);
            p.circle_filled(at(-2.0, 0.0), 1.6 * u, bg);
        }
        Icon::User => {
            p.circle_filled(at(0.0, -3.5), 3.2 * u, color);
            p.rect_filled(rect(-5.5, 1.5, 5.5, 7.0), 3.0 * u, color);
        }
        Icon::Lock => {
            p.rect_filled(rect(-7.0, -4.0, 7.0, 6.0), 2.0 * u, color);

            for x in [-3.5, 0.0, 3.5] {
                p.circle_filled(at(x, 1.0), 1.1 * u, bg);
            }
        }
        Icon::Eye => {
            let pts: Vec<Pos2> = (0..=16).map(|k| {
                let a = std::f32::consts::TAU * k as f32 / 16.0;
                at(7.0 * a.cos(), 4.0 * a.sin())
            }).collect();
            p.add(Shape::line(pts, st));
            p.circle_filled(c, 2.0 * u, color);
        }
        Icon::Backspace => {
            p.add(Shape::convex_polygon(vec![at(-8.0, 0.0), at(-3.5, -6.0), at(7.5, -6.0), at(7.5, 6.0), at(-3.5, 6.0)], color, Stroke::NONE));

            p.line_segment([at(-0.5, -2.5), at(4.5, 2.5)], Stroke::new(1.5 * u, bg));
            p.line_segment([at(4.5, -2.5), at(-0.5, 2.5)], Stroke::new(1.5 * u, bg));
        }
        Icon::Group => {
            p.rect_filled(rect(-7.5, -7.5, -0.5, -0.5), 1.0 * u, color);
            p.rect_filled(rect(0.5, -7.5, 7.5, -0.5), 1.0 * u, color.gamma_multiply(0.6));
            p.rect_filled(rect(-7.5, 0.5, -0.5, 7.5), 1.0 * u, color.gamma_multiply(0.6));
            p.rect_filled(rect(0.5, 0.5, 7.5, 7.5), 1.0 * u, color);
        }
        Icon::Play => {
            p.add(Shape::convex_polygon(vec![at(-4.5, -6.5), at(6.5, 0.0), at(-4.5, 6.5)], color, Stroke::NONE));
        }
        Icon::Stop => {
            p.rect_filled(rect(-5.5, -5.5, 5.5, 5.5), 1.5 * u, color);
        }
        Icon::Trash => {
            p.line_segment([at(-6.5, -4.5), at(6.5, -4.5)], st);
            p.rect_stroke(rect(-4.5, -4.5, 4.5, 7.0), 1.5 * u, st, StrokeKind::Middle);
            p.line_segment([at(-2.0, -7.0), at(2.0, -7.0)], st);
        }
        Icon::Refresh => {
            let pts: Vec<Pos2> = (0..=14).map(|k| {
                let a = std::f32::consts::PI * (-0.35 + 1.6 * k as f32 / 14.0);
                at(5.5 * a.cos(), 5.5 * a.sin())
            }).collect();
            let end = *pts.first().unwrap_or(&c);
            p.add(Shape::line(pts, st));
            p.add(Shape::convex_polygon(vec![end + vec2(-3.0 * u, -2.0 * u), end + vec2(2.5 * u, -3.5 * u), end + vec2(1.0 * u, 2.0 * u)], color, Stroke::NONE));
        }
        Icon::Settings => {
            p.circle_stroke(c, 5.0 * u, Stroke::new(2.4 * u, color));
            for k in 0..8 {
                let a = std::f32::consts::TAU * k as f32 / 8.0;
                p.line_segment([at(5.5 * a.cos(), 5.5 * a.sin()), at(7.8 * a.cos(), 7.8 * a.sin())], Stroke::new(2.2 * u, color));
            }
        }
    }
}

/// The rounded icon tile used on the empty screens.
pub fn icon_tile(p: &Painter, center: Pos2, icon: Icon) {
    let r = Rect::from_center_size(center, Vec2::splat(s(90.0)));
    p.rect_filled(r, s(18.0), ICON_BOX);
    p.rect_stroke(r, s(18.0), Stroke::new(1.0, BORDER), StrokeKind::Inside);
    draw_icon(p, icon, center, s(32.0), TEXT, ICON_BOX);
}
/// Empty screen: icon tile, bold title and grey description centred in `area`.
/// Returns the y just below the description.
pub fn empty_screen(ui: &Ui, area: Rect, icon: Icon, title: &str, desc: &str, extra_h: f32) -> f32 {
    let group_h = s(90.0) + s(64.0) + s(48.0) + s(12.0) + extra_h;
    let top = area.center().y - group_h / 2.0;
    let cx = area.center().x;
    let p = ui.painter();
    icon_tile(p, pos2(cx, top + s(45.0)), icon);
    let ty = top + s(90.0) + s(64.0);
    p.text(pos2(cx, ty), Align2::CENTER_CENTER, title, bold(s(26.0)), TEXT);
    p.text(pos2(cx, ty + s(48.0)), Align2::CENTER_CENTER, desc, regular(s(19.5)), GREY);
    ty + s(48.0) + s(12.0)
}

pub fn rect_xywh(x: f32, y: f32, w: f32, h: f32) -> Rect {
    Rect::from_min_size(pos2(x, y), vec2(w, h))
}
