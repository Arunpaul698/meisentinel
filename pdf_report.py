"""
Meisentis — PDF Report Generator
Produces a professional single-page assessment report using ReportLab.
"""

import io
import re
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

# ── Palette ──────────────────────────────────────────────────────────────────
C_BG      = colors.HexColor("#0a0c0f")
C_SURFACE = colors.HexColor("#111418")
C_BORDER  = colors.HexColor("#1e242c")
C_BORDER2 = colors.HexColor("#2a3340")
C_TEXT    = colors.HexColor("#c8d0da")
C_MUTED   = colors.HexColor("#5a6672")
C_ACCENT  = colors.HexColor("#00d4ff")
C_SAFE    = colors.HexColor("#00c96e")
C_WARN    = colors.HexColor("#ff9500")
C_DANGER  = colors.HexColor("#ff3b30")

W, H = A4       # 595 × 842 pt
PAD  = 20 * mm


# ── Helpers ───────────────────────────────────────────────────────────────────

def risk_color(score: int):
    if score >= 70:  return C_DANGER
    if score >= 35:  return C_WARN
    return C_SAFE


def risk_label(score: int) -> str:
    if score >= 70:  return "HIGH RISK"
    if score >= 35:  return "MEDIUM RISK"
    return "LOW RISK"


def strip_markup(text: str) -> str:
    text = re.sub(r'<[^>]+>', '', text)           # strip XML-like tags
    text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text) # **bold**
    text = re.sub(r'\*([^*]+)\*', r'\1', text)     # *italic*
    text = re.sub(r'__([^_]+)__', r'\1', text)     # __bold__
    text = re.sub(r'^#+\s+', '', text, flags=re.M) # headings
    return ' '.join(text.split())                   # collapse whitespace


def draw_rect(c, x, y, w, h, fill=None, stroke=None, radius=0):
    c.saveState()
    if fill:   c.setFillColor(fill)
    if stroke: c.setStrokeColor(stroke); c.setLineWidth(0.5)
    else:      c.setStrokeColor(colors.transparent)
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


def mono(c, text, x, y, size=8, color=None, align="left"):
    c.saveState()
    c.setFont("Courier-Bold", size)
    c.setFillColor(color or C_TEXT)
    if align == "right":   c.drawRightString(x, y, text)
    elif align == "center": c.drawCentredString(x, y, text)
    else:                   c.drawString(x, y, text)
    c.restoreState()


def wrapped_text(c, text, x, y, max_width, size=9, color=None, line_height=13) -> float:
    c.saveState()
    font = "Helvetica"
    c.setFont(font, size)
    c.setFillColor(color or C_TEXT)
    words = text.split()
    lines, current = [], ""
    for word in words:
        test = (current + " " + word).strip()
        if c.stringWidth(test, font, size) <= max_width:
            current = test
        else:
            if current: lines.append(current)
            current = word
    if current: lines.append(current)
    for line in lines:
        c.drawString(x, y, line)
        y -= line_height
    c.restoreState()
    return y


def _dim_status(data, dtype: str):
    """Return (status_text, status_color) for a dimension dict."""
    if data is None:
        return "SKIPPED", C_MUTED

    if dtype == "vt":
        total = sum(data.values()) or 1
        mal   = data.get("malicious",  0)
        sus   = data.get("suspicious", 0)
        if not data:
            return "NOT SUBMITTED", C_MUTED
        if mal > 0:
            return f"{mal}/{total} MALICIOUS", C_DANGER
        if sus > 0:
            return f"{sus}/{total} SUSPICIOUS", C_WARN
        return f"0/{total} FLAGGED — CLEAN", C_SAFE

    if dtype == "signing":
        if data.get("applicable") is False:
            return "N/A (non-PE)", C_MUTED
        if not data.get("signed"):
            return "UNSIGNED", C_MUTED
        if data.get("verified") is True:
            signer = (data.get("signer") or "unknown publisher")[:24]
            return f"VALID — {signer}", C_SAFE
        if data.get("verified") is False:
            return "INVALID SIGNATURE", C_DANGER
        return "UNVERIFIED", C_WARN

    applicable = data.get("applicable")
    if applicable is False:
        return "N/A", C_MUTED

    findings = data.get("findings") or []
    if not findings:
        if dtype == "sca":
            pkg = data.get("packages_scanned", 0)
            return f"CLEAN ({pkg} pkgs scanned)", C_SAFE
        return "CLEAN", C_SAFE

    highs = sum(1 for f in findings if f.get("severity") == "high")
    meds  = sum(1 for f in findings if f.get("severity") == "medium")
    lows  = sum(1 for f in findings if f.get("severity") == "low")

    if dtype == "sca":
        pkg = data.get("packages_scanned", 0)
        label = f"{len(findings)} CVE(S) / {pkg} PKG(S)"
        return label, C_DANGER if highs else C_WARN

    parts = []
    if highs: parts.append(f"{highs} HIGH")
    if meds:  parts.append(f"{meds} MED")
    if lows:  parts.append(f"{lows} LOW")
    return " · ".join(parts), C_DANGER if highs else C_WARN if meds else C_MUTED


def _dim_score(data, dtype: str, vt_stats: dict) -> int:
    """Return the blended score contribution for display."""
    if dtype == "vt":
        if not vt_stats:
            return 0
        total = sum(vt_stats.values()) or 1
        mal   = vt_stats.get("malicious",  0)
        sus   = vt_stats.get("suspicious", 0)
        raw   = min(100, round(((mal / total * 80) + (sus / total * 20)) * 100))
        return round(raw * 0.50)
    if data is None:
        return 0
    return data.get("score_contribution", 0)


# ── Main generator ────────────────────────────────────────────────────────────

def generate_pdf(scan_data: dict) -> bytes:
    buf = io.BytesIO()
    c   = canvas.Canvas(buf, pagesize=A4)
    c.setTitle("Meisentis — Security Assessment Report")

    score   = scan_data.get("risk_score",  0)
    label   = risk_label(score)
    rcolor  = risk_color(score)
    target  = scan_data.get("target", "Unknown")
    stype   = scan_data.get("type",   "file").upper()
    summary = strip_markup(scan_data.get("summary", "No summary available."))
    sha256  = scan_data.get("sha256", "")
    stats   = scan_data.get("vt_stats",        {}) or {}
    static  = scan_data.get("static_analysis")
    threat  = scan_data.get("threat_intel")    or {}
    signing = scan_data.get("code_signing")
    sca     = scan_data.get("sca")
    now     = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    cw      = W - 2 * PAD   # content width

    # ── Background + scanlines ────────────────────────────────────────────────
    draw_rect(c, 0, 0, W, H, fill=C_BG)
    c.saveState()
    c.setStrokeColor(colors.HexColor("#0d1014"))
    c.setLineWidth(0.3)
    for i in range(0, int(H), 4):
        c.line(0, i, W, i)
    c.restoreState()

    # ════════════════════════════════════════════════════════════════════════
    # HEADER
    # ════════════════════════════════════════════════════════════════════════
    hdr_h = 22 * mm
    draw_rect(c, 0, H - hdr_h, W, hdr_h, fill=C_SURFACE)
    draw_hline(c, 0, H - hdr_h, W, color=C_ACCENT, thickness=1.5)

    bx, by, bs = PAD, H - hdr_h + 4 * mm, 14 * mm
    draw_rect(c, bx, by, bs, bs, stroke=C_ACCENT)
    mono(c, "SSA", bx + bs / 2, by + 4.5 * mm, size=9, color=C_ACCENT, align="center")
    mono(c, "MEISENTIS — SECURITY ASSESSMENT REPORT",
         bx + bs + 4 * mm, by + 7 * mm, size=9, color=C_TEXT)
    mono(c, "CONFIDENTIAL · NOT FOR DISTRIBUTION",
         bx + bs + 4 * mm, by + 3 * mm, size=7, color=C_MUTED)
    mono(c, now, W - PAD, by + 5 * mm, size=7, color=C_MUTED, align="right")

    # ════════════════════════════════════════════════════════════════════════
    # RISK SCORE HERO
    # ════════════════════════════════════════════════════════════════════════
    hero_top = H - hdr_h - 2 * mm
    hero_h   = 44 * mm
    hero_bot = hero_top - hero_h

    draw_rect(c, 0, hero_bot, W, hero_h, fill=C_SURFACE)
    draw_hline(c, 0, hero_bot, W, color=C_BORDER)
    draw_rect(c, 0, hero_bot, 2.5, hero_h, fill=rcolor)

    sx = PAD + 30 * mm
    sy = hero_bot + 20 * mm
    c.saveState()
    c.setFont("Courier-Bold", 52)
    c.setFillColor(rcolor)
    c.drawCentredString(sx, sy, str(score))
    c.restoreState()
    mono(c, "/ 100", sx + 22 * mm, sy + 4 * mm, size=10, color=C_MUTED)
    mono(c, "RISK SCORE", sx, hero_bot + 9 * mm, size=7, color=C_MUTED, align="center")

    bdg_x, bdg_y = sx + 38 * mm, hero_bot + 20 * mm
    bdg_w, bdg_h = 36 * mm, 10 * mm
    draw_rect(c, bdg_x, bdg_y, bdg_w, bdg_h,
              fill=colors.HexColor("#1a0a0a" if score >= 70 else "#1a1000" if score >= 35 else "#001a0f"),
              stroke=rcolor)
    mono(c, label, bdg_x + bdg_w / 2, bdg_y + 3.2 * mm, size=9, color=rcolor, align="center")

    bar_x, bar_y = bdg_x, hero_bot + 16 * mm
    bar_w, bar_h = 95 * mm, 3 * mm
    draw_rect(c, bar_x, bar_y, bar_w, bar_h, fill=C_BORDER2)
    draw_rect(c, bar_x, bar_y, bar_w * score / 100, bar_h, fill=rcolor)
    mono(c, "0",   bar_x,              bar_y - 4, size=6, color=C_MUTED)
    mono(c, "50",  bar_x + bar_w / 2,  bar_y - 4, size=6, color=C_MUTED, align="center")
    mono(c, "100", bar_x + bar_w,      bar_y - 4, size=6, color=C_MUTED, align="right")

    tgt_x, tgt_y = bdg_x, hero_bot + 32 * mm
    mono(c, "ASSESSED TARGET", tgt_x, tgt_y, size=6.5, color=C_MUTED)
    display_target = target if len(target) <= 60 else target[:57] + "..."
    mono(c, display_target, tgt_x, tgt_y - 5 * mm, size=9, color=C_TEXT)
    mono(c, f"TYPE: {stype}", tgt_x, tgt_y - 9 * mm, size=7, color=C_MUTED)

    # ════════════════════════════════════════════════════════════════════════
    # VT STAT BOXES
    # ════════════════════════════════════════════════════════════════════════
    stat_top = hero_bot - 3 * mm
    stat_h   = 22 * mm
    stat_bot = stat_top - stat_h

    stat_items = [
        ("MALICIOUS",  stats.get("malicious",  0), C_DANGER),
        ("SUSPICIOUS", stats.get("suspicious", 0), C_WARN),
        ("CLEAN",      stats.get("harmless",   0), C_SAFE),
        ("UNDETECTED", stats.get("undetected", 0), C_MUTED),
    ]
    box_w = cw / 4
    for i, (key, val, col) in enumerate(stat_items):
        bx2 = PAD + i * box_w
        draw_rect(c, bx2, stat_bot, box_w, stat_h, fill=C_SURFACE, stroke=C_BORDER)
        c.saveState()
        c.setFont("Courier-Bold", 24)
        c.setFillColor(col)
        c.drawCentredString(bx2 + box_w / 2, stat_bot + 9 * mm, str(val))
        c.restoreState()
        mono(c, key, bx2 + box_w / 2, stat_bot + 4 * mm, size=6, color=C_MUTED, align="center")

    # ════════════════════════════════════════════════════════════════════════
    # AI SUMMARY
    # ════════════════════════════════════════════════════════════════════════
    sec_top = stat_bot - 5 * mm
    mono(c, "AI ASSESSMENT SUMMARY", PAD, sec_top, size=7, color=C_MUTED)
    draw_hline(c, PAD, sec_top - 3 * mm, cw, color=C_BORDER)

    sum_h = 24 * mm
    sum_y = sec_top - 5 * mm - sum_h
    draw_rect(c, PAD, sum_y, cw, sum_h, fill=C_SURFACE, stroke=C_BORDER)
    draw_rect(c, PAD, sum_y, 2, sum_h, fill=C_ACCENT)
    wrapped_text(c, summary, PAD + 5 * mm, sec_top - 9 * mm,
                 cw - 10 * mm, size=8.5, color=C_TEXT, line_height=12)

    # ════════════════════════════════════════════════════════════════════════
    # SECURITY DIMENSIONS
    # ════════════════════════════════════════════════════════════════════════
    dim_top = sum_y - 5 * mm
    mono(c, "SECURITY DIMENSIONS", PAD, dim_top, size=7, color=C_MUTED)
    draw_hline(c, PAD, dim_top - 3 * mm, cw, color=C_BORDER)

    col_status_x = PAD + cw * 0.52
    col_score_x  = PAD + cw * 0.88
    mono(c, "STATUS",      col_status_x, dim_top - 6 * mm, size=6, color=C_MUTED)
    mono(c, "CONTRIB",     col_score_x,  dim_top - 6 * mm, size=6, color=C_MUTED)

    dims = [
        ("1", "VirusTotal",      "72+ AV engines · malware & URL scanning", "vt",      stats),
        ("3", "Static Analysis", "YARA rules + PE header inspection",        "static",  static),
        ("4", "Code Signing",    "Authenticode / osslsigncode validation",   "signing", signing),
        ("5", "SCA / CVE Scan",  "OSV database · package manifest lookup",   "sca",     sca),
        ("6", "Threat Intel",    "MalwareBazaar · ThreatFox · URLhaus",      "threat",  threat),
    ]

    row_h = 8.5 * mm
    for i, (num, name, sub, dtype, data) in enumerate(dims):
        ry = dim_top - 8 * mm - i * (row_h + 1)
        status_txt, status_col = _dim_status(data, dtype)
        sc = _dim_score(data, dtype, stats)

        draw_rect(c, PAD, ry, cw, row_h, fill=C_SURFACE, stroke=C_BORDER)
        # left accent stripe by severity
        stripe = C_DANGER if status_col == C_DANGER else C_WARN if status_col == C_WARN else C_BORDER
        draw_rect(c, PAD, ry, 2, row_h, fill=stripe)

        # Dim badge
        draw_rect(c, PAD + 2 * mm, ry + 1.8 * mm, 8 * mm, 5 * mm,
                  fill=colors.HexColor("#001a22"), stroke=C_ACCENT)
        mono(c, f"D{num}", PAD + 6 * mm, ry + 3 * mm, size=6.5, color=C_ACCENT, align="center")

        mono(c, name, PAD + 14 * mm, ry + 5.2 * mm, size=8,   color=C_TEXT)
        mono(c, sub,  PAD + 14 * mm, ry + 1.8 * mm, size=6,   color=C_MUTED)

        # Truncate long status
        st = status_txt if len(status_txt) <= 32 else status_txt[:29] + "..."
        mono(c, st, col_status_x, ry + 3 * mm, size=7, color=status_col)

        sc_col = C_DANGER if sc >= 30 else C_WARN if sc >= 10 else C_MUTED
        mono(c, f"+{sc}", col_score_x, ry + 3 * mm, size=7, color=sc_col)

    dim_bottom = dim_top - 8 * mm - len(dims) * (row_h + 1) - 3 * mm

    # ════════════════════════════════════════════════════════════════════════
    # SHA-256
    # ════════════════════════════════════════════════════════════════════════
    if sha256:
        draw_rect(c, PAD, dim_bottom - 7 * mm, cw, 7 * mm, fill=C_SURFACE, stroke=C_BORDER)
        mono(c, "SHA-256", PAD + 3 * mm, dim_bottom - 3.5 * mm, size=6, color=C_MUTED)
        mono(c, sha256,    PAD + 20 * mm, dim_bottom - 3.5 * mm, size=6,
             color=colors.HexColor("#0099bb"))
        dim_bottom -= 11 * mm

    # ════════════════════════════════════════════════════════════════════════
    # ROUTING VERDICT  (thresholds: 0-34 GREEN, 35-69 YELLOW, 70+ RED)
    # ════════════════════════════════════════════════════════════════════════
    verdict_top = dim_bottom - 2 * mm

    if score >= 70:
        vtext  = "HIGH-RISK — ESCALATED"
        vdesc  = "Flagged immediately. Specialist team notified. Manual deep-dive required."
        vcol   = C_DANGER
        vfill  = "#1a0a0a"
    elif score >= 35:
        vtext  = "ASSIGNED FOR ANALYST REVIEW"
        vdesc  = "Draft report sent to Tier 4 team. Awaiting human sign-off before action."
        vcol   = C_WARN
        vfill  = "#1a1000"
    else:
        vtext  = "AUTO-RESOLVED — CLEARED"
        vdesc  = "File cleared by automated pipeline. Hash added to safe registry. Ticket closed."
        vcol   = C_SAFE
        vfill  = "#001a0f"

    vbox_h = 16 * mm
    draw_rect(c, PAD, verdict_top - vbox_h, cw, vbox_h,
              fill=colors.HexColor(vfill), stroke=vcol)
    draw_rect(c, PAD, verdict_top - vbox_h, 3, vbox_h, fill=vcol)

    mono(c, "ROUTING VERDICT",  PAD + 6 * mm, verdict_top - 4 * mm,    size=6.5, color=C_MUTED)
    mono(c, vtext,              PAD + 6 * mm, verdict_top - 8 * mm,    size=10,  color=vcol)
    mono(c, vdesc,              PAD + 6 * mm, verdict_top - 12.5 * mm, size=7,   color=C_TEXT)

    # ════════════════════════════════════════════════════════════════════════
    # FOOTER
    # ════════════════════════════════════════════════════════════════════════
    draw_rect(c, 0, 0, W, 10 * mm, fill=C_SURFACE)
    draw_hline(c, 0, 10 * mm, W, color=C_BORDER)
    mono(c, "MEISENTIS · CONFIDENTIAL SECURITY REPORT", PAD, 3.5 * mm, size=6.5, color=C_MUTED)
    mono(c, f"GENERATED {now}", W - PAD, 3.5 * mm, size=6.5, color=C_MUTED, align="right")

    c.save()
    buf.seek(0)
    return buf.read()
