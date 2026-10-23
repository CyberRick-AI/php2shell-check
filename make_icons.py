#!/usr/bin/env python3
"""Regenerates the PWA icons in public/icons/ (needs Pillow: pip install pillow).
Swap in your own artwork any time: keep the same filenames and sizes."""
import os
from PIL import Image, ImageDraw, ImageFont

BG = (11, 16, 32)
CYAN = (0, 229, 255)
GREEN = (46, 204, 113)
BLUE = (59, 130, 246)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public", "icons")
FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "C:\\Windows\\Fonts\\arialbd.ttf",
]


def font(size):
    for p in FONT_PATHS:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default(size)


def draw_icon(size, safe):
    """safe = fraction of the canvas the artwork may use (maskable icons need ~0.7)."""
    S = 1024
    im = Image.new("RGB", (S, S), BG)
    d = ImageDraw.Draw(im)
    c = S / 2
    r = S * safe / 2  # artwork radius
    w = int(S * 0.045)
    # two orbit arcs (horizontal green, vertical blue) drawn as partial ellipses
    d.arc([c - r, c - r * 0.55, c + r, c + r * 0.55], 200, 520, fill=GREEN, width=w)
    d.arc([c - r * 0.55, c - r, c + r * 0.55, c + r], 110, 430, fill=BLUE, width=w)
    # core ring
    cr = r * 0.50
    d.ellipse([c - cr, c - cr, c + cr, c + cr], outline=CYAN, width=w)
    # label
    f = font(int(r * 0.36))
    d.text((c, c), "PHP", font=f, fill=(232, 236, 248), anchor="mm")
    return im.resize((size, size), Image.LANCZOS)


os.makedirs(OUT, exist_ok=True)
draw_icon(192, 0.84).save(os.path.join(OUT, "icon-192.png"))
draw_icon(512, 0.84).save(os.path.join(OUT, "icon-512.png"))
draw_icon(512, 0.62).save(os.path.join(OUT, "icon-maskable-512.png"))  # safe zone for circular masks
draw_icon(180, 0.78).save(os.path.join(OUT, "apple-touch-icon.png"))
print("icons written to", OUT)
