//! Obsidian/Emerald/Gold visual theme, procedural Double-Bar V (`∀`) window icon,
//! native `egui::Painter` QR code renderer, and live balance sparkline chart.

use credit_sdk::QrCode;
use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Pos2, Rect, Stroke, StrokeKind, TextStyle,
    Vec2,
};

pub const BG_OBSIDIAN: Color32 = Color32::from_rgb(11, 16, 27);
pub const BG_CARD: Color32 = Color32::from_rgb(19, 27, 46);
pub const BG_INPUT: Color32 = Color32::from_rgb(14, 21, 37);
pub const BORDER_SUBTLE: Color32 = Color32::from_rgb(38, 52, 82);
pub const ACCENT_EMERALD: Color32 = Color32::from_rgb(16, 185, 129);
pub const ACCENT_GOLD: Color32 = Color32::from_rgb(245, 158, 11);
pub const ACCENT_BLUE: Color32 = Color32::from_rgb(59, 130, 246);
pub const DANGER_RED: Color32 = Color32::from_rgb(239, 68, 68);
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(241, 245, 249);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(148, 163, 184);

/// Applies a calm, modern consumer dark theme with generous typography and rounded cards.
pub fn apply_credits_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(10.0, 10.0);
    style.spacing.button_padding = Vec2::new(14.0, 9.0);
    style.spacing.window_margin = egui::Margin::same(18);

    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(23.0, FontFamily::Proportional),
    );
    style
        .text_styles
        .insert(TextStyle::Body, FontId::new(15.0, FontFamily::Proportional));
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(14.5, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new(13.5, FontFamily::Monospace),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new(12.5, FontFamily::Proportional),
    );

    let mut vis = egui::Visuals::dark();
    vis.panel_fill = BG_OBSIDIAN;
    vis.window_fill = BG_CARD;
    vis.extreme_bg_color = BG_INPUT;
    vis.faint_bg_color = BG_CARD;
    vis.override_text_color = Some(TEXT_PRIMARY);
    vis.widgets.noninteractive.bg_fill = BG_CARD;
    vis.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER_SUBTLE);
    vis.widgets.noninteractive.corner_radius = CornerRadius::same(10);
    vis.widgets.inactive.bg_fill = Color32::from_rgb(28, 39, 64);
    vis.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER_SUBTLE);
    vis.widgets.inactive.corner_radius = CornerRadius::same(8);
    vis.widgets.hovered.bg_fill = Color32::from_rgb(38, 54, 88);
    vis.widgets.hovered.bg_stroke = Stroke::new(1.2_f32, ACCENT_EMERALD);
    vis.widgets.hovered.corner_radius = CornerRadius::same(8);
    vis.widgets.active.bg_fill = ACCENT_EMERALD;
    vis.widgets.active.corner_radius = CornerRadius::same(8);
    vis.selection.bg_fill = Color32::from_rgba_unmultiplied(16, 185, 129, 65);
    vis.selection.stroke = Stroke::new(1.2_f32, ACCENT_EMERALD);

    style.visuals = vis;
    ctx.set_style(style);
}

/// Procedurally renders a 64x64 RGBA window icon featuring the Credits Double-Bar V (`∀`) crest.
pub fn build_app_icon() -> egui::IconData {
    let w = 64usize;
    let h = 64usize;
    let mut rgba = vec![0u8; w * h * 4];

    for y in 0..h {
        for x in 0..w {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let idx = (y * w + x) * 4;

            // Rounded-square SDF (center 32,32, half-extents 29, corner radius 13):
            let dx = (fx - 32.0).abs() - 16.0;
            let dy = (fy - 32.0).abs() - 16.0;
            let out_d =
                (dx.max(0.0).powi(2) + dy.max(0.0).powi(2)).sqrt() + dx.max(dy).min(0.0) - 13.0;
            if out_d > 0.6 {
                continue;
            }

            // Distance to the `V` strokes (`(16,14)->(32,51)` and `(48,14)->(32,51)`)
            // and the two horizontal bars (`y=26` and `y=34`):
            let d_left = dist_to_segment(fx, fy, 16.5, 14.0, 32.0, 50.0);
            let d_right = dist_to_segment(fx, fy, 47.5, 14.0, 32.0, 50.0);
            let d_bar1 = dist_to_segment(fx, fy, 18.0, 25.5, 46.0, 25.5);
            let d_bar2 = dist_to_segment(fx, fy, 21.0, 33.5, 43.0, 33.5);
            let glyph_d = d_left.min(d_right).min(d_bar1).min(d_bar2);

            if glyph_d <= 2.4 {
                // Crisp Emerald-to-Gold gradient on the Double-Bar V glyph:
                let t = (fy / 64.0).clamp(0.0, 1.0);
                rgba[idx] = (16.0 * (1.0 - t) + 245.0 * t) as u8;
                rgba[idx + 1] = (210.0 * (1.0 - t) + 175.0 * t) as u8;
                rgba[idx + 2] = (145.0 * (1.0 - t) + 35.0 * t) as u8;
                rgba[idx + 3] = 255;
            } else {
                // Deep obsidian badge background:
                rgba[idx] = 14;
                rgba[idx + 1] = 21;
                rgba[idx + 2] = 38;
                rgba[idx + 3] = if out_d > -0.6 { 180 } else { 255 };
            }
        }
    }

    egui::IconData {
        rgba,
        width: w as u32,
        height: h as u32,
    }
}

fn dist_to_segment(px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32) -> f32 {
    let vx = bx - ax;
    let vy = by - ay;
    let wx = px - ax;
    let wy = py - ay;
    let len_sq = vx * vx + vy * vy;
    let t = if len_sq > 0.0 {
        ((wx * vx + wy * vy) / len_sq).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let cx = ax + t * vx;
    let cy = ay + t * vy;
    ((px - cx).powi(2) + (py - cy).powi(2)).sqrt()
}

/// Paints a crisp scannable ISO-18004 QR code directly onto an `egui` canvas (`0` external image deps).
pub fn draw_qr_canvas(ui: &mut egui::Ui, payload: &str, box_px: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(box_px), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(10), Color32::WHITE);

    let Ok(qr) = QrCode::encode_str(payload) else {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "QR ready",
            FontId::proportional(13.0),
            Color32::BLACK,
        );
        return;
    };

    let n = qr.size();
    let quiet = 3usize;
    let total_cells = (n + quiet * 2) as f32;
    let cell = box_px / total_cells;

    for y in 0..n {
        for x in 0..n {
            if qr.is_dark(y, x) {
                let min = Pos2::new(
                    rect.min.x + (x + quiet) as f32 * cell,
                    rect.min.y + (y + quiet) as f32 * cell,
                );
                let max = Pos2::new(min.x + cell + 0.35, min.y + cell + 0.35);
                painter.rect_filled(
                    Rect::from_min_max(min, max),
                    CornerRadius::ZERO,
                    Color32::BLACK,
                );
            }
        }
    }
}

/// Draws a live emerald sparkline of recent wallet balance samples.
pub fn draw_earnings_sparkline(ui: &mut egui::Ui, points: &[f64], height: f32) {
    let width = ui.available_width().max(180.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(8), BG_INPUT);
    painter.rect_stroke(
        rect,
        CornerRadius::same(8),
        Stroke::new(1.0_f32, BORDER_SUBTLE),
        StrokeKind::Inside,
    );

    if points.len() < 2 {
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "Live earnings chart updates automatically every 60s epoch...",
            FontId::proportional(12.5),
            TEXT_MUTED,
        );
        return;
    }

    let min_v = points.iter().copied().fold(f64::INFINITY, f64::min);
    let max_v = points.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let span = (max_v - min_v).max(0.01);
    let pad = 10.0f32;
    let inner_w = (rect.width() - pad * 2.0).max(10.0);
    let inner_h = (rect.height() - pad * 2.0).max(10.0);

    let coords: Vec<Pos2> = points
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let tx = i as f32 / (points.len() - 1) as f32;
            let ty = ((v - min_v) / span) as f32;
            Pos2::new(
                rect.min.x + pad + tx * inner_w,
                rect.max.y - pad - ty * inner_h,
            )
        })
        .collect();

    for win in coords.windows(2) {
        painter.line_segment([win[0], win[1]], Stroke::new(2.2_f32, ACCENT_EMERALD));
    }
    if let Some(&last) = coords.last() {
        painter.circle_filled(last, 4.0, ACCENT_GOLD);
    }
}
