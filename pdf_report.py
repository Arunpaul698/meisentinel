"""
SSA Agent — PDF Report Generator
Produces a professional single-page assessment report using ReportLab.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from reportlab.platypus import Table, TableStyle
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ── Palette (matches portal) ─────────────────────────────────────────────────
C_BG       = colors.HexColor("#0a0c0f")
C_SURFACE  = colors.HexColor("#111418")
C_BORDER   = colors.HexColor("#1e242c")
C_BORDER2  = colors.HexColor("#2a3340")
C_TEXT     = colors.HexColor("#c8d0da")
C_MUTED    = colors.HexColor("#5a6672")
C_ACCENT   = colors.HexColor("#00d4ff")
C_SAFE     = colors.HexColor("#00c96e")
C_WARN     = colors.HexColor("#ff9500")
C_DANGER   = colors.HexColor("#ff3b30")
C_WHITE    = colors.HexColor("#ffffff")

W, H = A4          # 595 x 842 pt
PAD  = 20 * mm


def risk_color(score: int):
    if score >= 70:
        return C_DANGER
    elif score >= 35:
        return C_WARN
    return C_SAFE


def risk_label(score: int) -> str:
    if score >= 70:
        return "HIGH RISK"
    elif score >= 35:
        return "MEDIUM RISK"
    return "LOW RISK"


def draw_rect(c, x, y, w, h, fill=None, stroke=None, radius=0):
    """Helper: draw a filled/stroked rectangle."""
    c.saveState()
    if fill:
        c.setFillColor(fill)
    if stroke:
        c.setStrokeColor(stroke)
        c.setLineWidth(0.5)
    else:
        c.setStrokeColor(colors.transparent)
    if radius:
        c.roundRect(x, y, w, h, radius, fill=1 if fill else 0, stroke=1 if stroke else 0)
    else:
        c.rect(x, y, w, h, fill=1 if fill else 0, stroke=1 if stroke else 0)
    c.restoreState()


def draw_hline(c, x, y, w, color=None, thickness=0.5):
    c.saveState()
    c.setStrokeColor(color or C_BORDER)
    c.setLineWidth(thickness)
    c.line(x, y, x + w, y)
    c.restoreState()


def draw_vline(c, x, y, h, color=None, thickness=0.5):
    c.saveState()
    c.setStrokeColor(color or C_BORDER)
    c.setLineWidth(thickness)
    c.line(x, y, x, y + h)
    c.restoreState()


def mono(c, text, x, y, size=8, color=None, align="left"):
    c.saveState()
    c.setFont("Courier-Bold", size)
    c.setFillColor(color or C_TEXT)
    if align == "right":
        c.drawRightString(x, y, text)
    elif align == "center":
        c.drawCentredString(x, y, text)
    else:
        c.drawString(x, y, text)
    c.restoreState()


def sans(c, text, x, y, size=9, color=None, align="left", bold=False):
    c.saveState()
    font = "Helvetica-Bold" if bold else "Helvetica"
    c.setFont(font, size)
    c.setFillColor(color or C_TEXT)
    if align == "right":
        c.drawRightString(x, y, text)
    elif align == "center":
        c.drawCentredString(x, y, text)
    else:
        c.drawString(x, y, text)
    c.restoreState()


def wrapped_text(c, text: str, x: float, y: float, max_width: float,
                 size=9, color=None, line_height=13, font="Helvetica") -> float:
    """
    Draw wrapped text. Returns the Y position after the last line.
    """
    c.saveState()
    c.setFont(font, size)
    c.setFillColor(color or C_TEXT)

    words = text.split()
    lines = []
    current = ""
    for word in words:
        test = (current + " " + word).strip()
        if c.stringWidth(test, font, size) <= max_width:
            current = test
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)

    for line in lines:
        c.drawString(x, y, line)
        y -= line_height

    c.restoreState()
    return y


def generate_pdf(scan_data: dict) -> bytes:
    """
    Build a PDF report from scan_data dict.
    Returns raw PDF bytes.
    """
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setTitle("SSA Agent — Security Assessment Report")

    score   = scan_data.get("risk_score", 0)
    label   = risk_label(score)
    rcolor  = risk_color(score)
    target  = scan_data.get("target", "Unknown")
    stype   = scan_data.get("type", "file").upper()
    summary = scan_data.get("summary", "No summary available.")
    sha256  = scan_data.get("sha256", "")
    stats   = scan_data.get("vt_stats", {})
    now     = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # ── full dark background ─────────────────────────────────────────────────
    draw_rect(c, 0, 0, W, H, fill=C_BG)

    # ── scanline texture (subtle) ────────────────────────────────────────────
    c.saveState()
    c.setStrokeColor(colors.HexColor("#0d1014"))
    c.setLineWidth(0.3)
    for i in range(0, int(H), 4):
        c.line(0, i, W, i)
    c.restoreState()

    # ════════════════════════════════════════════════════════════════════════
    # HEADER BAR
    # ════════════════════════════════════════════════════════════════════════
    header_h = 22 * mm
    draw_rect(c, 0, H - header_h, W, header_h, fill=C_SURFACE)
    draw_hline(c, 0, H - header_h, W, color=C_ACCENT, thickness=1.5)

    # Logo mark box
    box_x, box_y = PAD, H - header_h + 4 * mm
    box_s = 14 * mm
    draw_rect(c, box_x, box_y, box_s, box_s, stroke=C_ACCENT)
    mono(c, "SSA", box_x + box_s / 2, box_y + 4.5 * mm, size=9,
         color=C_ACCENT, align="center")

    mono(c, "SOFTWARE SECURITY ASSESSMENT REPORT",
         box_x + box_s + 4 * mm, box_y + 7 * mm, size=9, color=C_TEXT)
    mono(c, "AGENT MVP v0.1",
         box_x + box_s + 4 * mm, box_y + 3 * mm, size=7, color=C_MUTED)

    mono(c, now, W - PAD, box_y + 5 * mm, size=7, color=C_MUTED, align="right")

    # ════════════════════════════════════════════════════════════════════════
    # RISK SCORE HERO BLOCK
    # ════════════════════════════════════════════════════════════════════════
    hero_top  = H - header_h - 2 * mm
    hero_h    = 44 * mm
    hero_bot  = hero_top - hero_h

    draw_rect(c, 0, hero_bot, W, hero_h, fill=C_SURFACE)
    draw_hline(c, 0, hero_bot, W, color=C_BORDER)
    # accent left bar
    draw_rect(c, 0, hero_bot, 2.5, hero_h, fill=rcolor)

    # Score number
    score_x = PAD + 30 * mm
    score_y = hero_bot + 20 * mm
    c.saveState()
    c.setFont("Courier-Bold", 52)
    c.setFillColor(rcolor)
    c.drawCentredString(score_x, score_y, str(score))
    c.restoreState()
    mono(c, "/ 100", score_x + 22 * mm, score_y + 4 * mm, size=10, color=C_MUTED)
    mono(c, "RISK SCORE", score_x, hero_bot + 9 * mm, size=7,
         color=C_MUTED, align="center")

    # Risk label badge
    badge_x = score_x + 38 * mm
    badge_y = hero_bot + 20 * mm
    badge_w = 36 * mm
    badge_h = 10 * mm
    draw_rect(c, badge_x, badge_y, badge_w, badge_h,
              fill=colors.HexColor(
                  "#1a0a0a" if score >= 70 else "#1a1000" if score >= 35 else "#001a0f"
              ),
              stroke=rcolor)
    mono(c, label, badge_x + badge_w / 2, badge_y + 3.2 * mm,
         size=9, color=rcolor, align="center")

    # Score bar
    bar_x = badge_x
    bar_y = hero_bot + 16 * mm
    bar_w = 95 * mm
    bar_h = 3 * mm
    draw_rect(c, bar_x, bar_y, bar_w, bar_h, fill=C_BORDER2)
    fill_w = bar_w * score / 100
    draw_rect(c, bar_x, bar_y, fill_w, bar_h, fill=rcolor)
    mono(c, "0", bar_x, bar_y - 4, size=6, color=C_MUTED)
    mono(c, "50", bar_x + bar_w / 2, bar_y - 4, size=6, color=C_MUTED, align="center")
    mono(c, "100", bar_x + bar_w, bar_y - 4, size=6, color=C_MUTED, align="right")

    # Target info
    target_x = badge_x
    target_y  = hero_bot + 32 * mm
    mono(c, "ASSESSED TARGET", target_x, target_y, size=6.5, color=C_MUTED)

    # truncate long targets
    display_target = target if len(target) <= 62 else target[:59] + "..."
    mono(c, display_target, target_x, target_y - 5 * mm, size=9, color=C_TEXT)
    mono(c, f"TYPE: {stype}", target_x, target_y - 9 * mm, size=7, color=C_MUTED)

    # ════════════════════════════════════════════════════════════════════════
    # STAT BOXES
    # ════════════════════════════════════════════════════════════════════════
    stat_top = hero_bot - 3 * mm
    stat_h   = 24 * mm
    stat_bot = stat_top - stat_h

    stat_items = [
        ("MALICIOUS",  stats.get("malicious",  0), C_DANGER),
        ("SUSPICIOUS", stats.get("suspicious", 0), C_WARN),
        ("CLEAN",      stats.get("harmless",   0), C_SAFE),
        ("UNDETECTED", stats.get("undetected", 0), C_MUTED),
    ]

    box_w = (W - 2 * PAD) / 4
    for i, (key, val, col) in enumerate(stat_items):
        bx = PAD + i * box_w
        draw_rect(c, bx, stat_bot, box_w, stat_h, fill=C_SURFACE, stroke=C_BORDER)
        # value
        c.saveState()
        c.setFont("Courier-Bold", 26)
        c.setFillColor(col)
        c.drawCentredString(bx + box_w / 2, stat_bot + 10 * mm, str(val))
        c.restoreState()
        mono(c, key, bx + box_w / 2, stat_bot + 5 * mm,
             size=6.5, color=C_MUTED, align="center")

    # ════════════════════════════════════════════════════════════════════════
    # AI SUMMARY SECTION
    # ════════════════════════════════════════════════════════════════════════
    sec_top = stat_bot - 6 * mm
    content_w = W - 2 * PAD

    mono(c, "AI ASSESSMENT SUMMARY", PAD, sec_top, size=7, color=C_MUTED)
    mono(c, "────────────────────────────────────────────────────────────────────────",
         PAD, sec_top - 3 * mm, size=5, color=C_BORDER2)

    draw_rect(c, PAD, sec_top - 4 * mm - 28 * mm, content_w, 28 * mm,
              fill=C_SURFACE, stroke=C_BORDER)
    # accent left stripe
    draw_rect(c, PAD, sec_top - 4 * mm - 28 * mm, 2, 28 * mm, fill=C_ACCENT)

    text_y = wrapped_text(
        c, summary,
        PAD + 5 * mm, sec_top - 8 * mm,
        max_width=content_w - 10 * mm,
        size=9, color=C_TEXT, line_height=12
    )

    # ════════════════════════════════════════════════════════════════════════
    # PIPELINE STATUS BLOCK
    # ════════════════════════════════════════════════════════════════════════
    pipe_top = sec_top - 38 * mm
    mono(c, "ASSESSMENT PIPELINE", PAD, pipe_top, size=7, color=C_MUTED)

    tiers = [
        ("T-1", "Hash Registry",        "SHA-256 checked against known-file registry",       True),
        ("T-2", "VirusTotal Scan",       "70+ AV engines — file & URL analysis completed",    True),
        ("T-3", "AI Agent Analysis",     "LLM report and confidence score generated",          True),
        ("T-4", "Analyst Review",        "Pending score-based routing decision",               score < 85),
    ]

    tier_h = 9 * mm
    tier_w = content_w
    for i, (num, name, desc, active) in enumerate(tiers):
        ty = pipe_top - 4 * mm - (i * (tier_h + 1))
        draw_rect(c, PAD, ty, tier_w, tier_h, fill=C_SURFACE, stroke=C_BORDER)

        # tier number badge
        badge_col = C_ACCENT if active else C_MUTED
        draw_rect(c, PAD + 2 * mm, ty + 2 * mm, 10 * mm, 5 * mm,
                  fill=colors.HexColor("#001a22" if active else "#111418"),
                  stroke=badge_col)
        mono(c, num, PAD + 7 * mm, ty + 3.2 * mm, size=6.5,
             color=badge_col, align="center")

        mono(c, name, PAD + 15 * mm, ty + 5.5 * mm, size=8,
             color=C_TEXT if active else C_MUTED)
        mono(c, desc, PAD + 15 * mm, ty + 2 * mm, size=6.5, color=C_MUTED)

        # status dot
        dot_x = PAD + tier_w - 8 * mm
        dot_y = ty + tier_h / 2
        c.saveState()
        c.setFillColor(C_SAFE if active else C_BORDER2)
        c.circle(dot_x, dot_y, 2, fill=1, stroke=0)
        c.restoreState()

    # ════════════════════════════════════════════════════════════════════════
    # SHA-256 / METADATA
    # ════════════════════════════════════════════════════════════════════════
    meta_top = pipe_top - (len(tiers) * (tier_h + 1)) - 10 * mm

    if sha256:
        draw_rect(c, PAD, meta_top - 8 * mm, content_w, 8 * mm,
                  fill=C_SURFACE, stroke=C_BORDER)
        mono(c, "SHA-256", PAD + 3 * mm, meta_top - 3.5 * mm, size=6.5, color=C_MUTED)
        mono(c, sha256, PAD + 22 * mm, meta_top - 3.5 * mm, size=6.5,
             color=colors.HexColor("#0099bb"))
        meta_top -= 12 * mm

    # ════════════════════════════════════════════════════════════════════════
    # ROUTING VERDICT
    # ════════════════════════════════════════════════════════════════════════
    verdict_top = meta_top - 2 * mm

    if score >= 85:
        verdict_text  = "AUTO-RESOLVED"
        verdict_desc  = "File cleared. Ticket closed automatically. Hash added to registry."
        verdict_color = C_SAFE
    elif score >= 50:
        verdict_text  = "ASSIGNED FOR ANALYST REVIEW"
        verdict_desc  = "Draft report sent to Tier 4 team. Awaiting human sign-off."
        verdict_color = C_WARN
    else:
        verdict_text  = "HIGH-RISK — ESCALATED"
        verdict_desc  = "Flagged immediately. Specialist team notified. Manual deep-dive required."
        verdict_color = C_DANGER

    vbox_h = 16 * mm
    draw_rect(c, PAD, verdict_top - vbox_h, content_w, vbox_h,
              fill=colors.HexColor(
                  "#001a0f" if score >= 85 else "#1a1000" if score >= 50 else "#1a0a0a"
              ),
              stroke=verdict_color)
    draw_rect(c, PAD, verdict_top - vbox_h, 3, vbox_h, fill=verdict_color)

    mono(c, "ROUTING VERDICT", PAD + 6 * mm, verdict_top - 4 * mm,
         size=6.5, color=C_MUTED)
    mono(c, verdict_text, PAD + 6 * mm, verdict_top - 8 * mm,
         size=10, color=verdict_color)
    mono(c, verdict_desc, PAD + 6 * mm, verdict_top - 12.5 * mm,
         size=7, color=C_TEXT)

    # ════════════════════════════════════════════════════════════════════════
    # FOOTER
    # ════════════════════════════════════════════════════════════════════════
    footer_h = 10 * mm
    draw_rect(c, 0, 0, W, footer_h, fill=C_SURFACE)
    draw_hline(c, 0, footer_h, W, color=C_BORDER)

    mono(c, "SSA AGENT MVP · CONFIDENTIAL SECURITY REPORT",
         PAD, 3.5 * mm, size=6.5, color=C_MUTED)
    mono(c, f"GENERATED {now}",
         W - PAD, 3.5 * mm, size=6.5, color=C_MUTED, align="right")

    c.save()
    buf.seek(0)
    return buf.read()
