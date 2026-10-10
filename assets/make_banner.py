#!/usr/bin/env python3
"""Generate the red-team themed README banner for the Responder (Rust) project."""
import math
import os

from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H = 1600, 440
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "banner.png")


def _find(*candidates):
    for path in candidates:
        if os.path.exists(path):
            return path
    raise FileNotFoundError(
        "Required font not found. Install: fonts-dejavu, fonts-firacode, fonts-font-awesome.\n"
        f"Tried: {candidates}"
    )


FIRACODE = "/usr/share/fonts/truetype/firacode"
DEJAVU = "/usr/share/fonts/truetype/dejavu"
FA = _find(
    "/usr/share/fonts/truetype/font-awesome/fa-6.7.2-solid-900.ttf",
    "/usr/share/fonts/truetype/font-awesome/fa-solid-900.ttf",
)
FIRACODE_BOLD = _find(f"{FIRACODE}/FiraCode-Bold.ttf")
DEJAVU_REG = _find(f"{DEJAVU}/DejaVuSans.ttf")


def hx(s, a=255):
    s = s.lstrip("#")
    return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16), a)


def font(path, size):
    return ImageFont.truetype(path, size)


def interp(stops, t):
    t = max(0.0, min(1.0, t))
    for i in range(len(stops) - 1):
        t0, c0 = stops[i]
        t1, c1 = stops[i + 1]
        if t0 <= t <= t1:
            f = 0.0 if t1 == t0 else (t - t0) / (t1 - t0)
            return tuple(int(c0[k] + (c1[k] - c0[k]) * f) for k in range(4))
    return stops[-1][1]


def v_gradient(w, h, stops):
    img = Image.new("RGBA", (w, h))
    d = ImageDraw.Draw(img)
    for y in range(h):
        d.line([(0, y), (w, y)], fill=interp(stops, y / (h - 1)))
    return img


def h_gradient_img(w, h, stops):
    img = Image.new("RGBA", (w, h))
    d = ImageDraw.Draw(img)
    for x in range(w):
        d.line([(x, 0), (x, h)], fill=interp(stops, x / (w - 1)))
    return img


def text_gradient(canvas, xy, text, fnt, stops, anchor="ls", span=None):
    mask = Image.new("L", canvas.size, 0)
    ImageDraw.Draw(mask).text(xy, text, font=fnt, fill=255, anchor=anchor)
    bbox = ImageDraw.Draw(canvas).textbbox(xy, text, font=fnt, anchor=anchor)
    x0, x1 = (bbox[0], bbox[2]) if span is None else span
    grad = Image.new("RGBA", canvas.size)
    gd = ImageDraw.Draw(grad)
    span = max(1, x1 - x0)
    for x in range(canvas.size[0]):
        gd.line([(x, 0), (x, canvas.size[1])], fill=interp(stops, (x - x0) / span))
    canvas.paste(grad, (0, 0), mask)


def dashed(canvas, p0, p1, color, width=3, dash=12, gap=9):
    d = ImageDraw.Draw(canvas)
    x0, y0 = p0
    x1, y1 = p1
    dist = math.hypot(x1 - x0, y1 - y0)
    if dist == 0:
        return
    ux, uy = (x1 - x0) / dist, (y1 - y0) / dist
    t = 0.0
    while t < dist:
        t2 = min(t + dash, dist)
        d.line(
            [(x0 + ux * t, y0 + uy * t), (x0 + ux * t2, y0 + uy * t2)],
            fill=color,
            width=width,
        )
        t = t2 + gap


def arrowhead(canvas, tip, tail, size, color):
    d = ImageDraw.Draw(canvas)
    x0, y0 = tip
    x1, y1 = tail
    ang = math.atan2(y0 - y1, x0 - x1)
    bx, by = x0 - math.cos(ang) * size, y0 - math.sin(ang) * size
    px, py = -math.sin(ang), math.cos(ang)
    d.polygon(
        [
            (x0, y0),
            (bx + px * size * 0.55, by + py * size * 0.55),
            (bx - px * size * 0.55, by - py * size * 0.55),
        ],
        fill=color,
    )


# ---------------------------------------------------------------- background
canvas = v_gradient(W, H, [(0.0, hx("#070a10")), (0.55, hx("#0a0f18")), (1.0, hx("#0e141d"))])

# subtle grid
grid = Image.new("RGBA", (W, H), (0, 0, 0, 0))
gd = ImageDraw.Draw(grid)
for x in range(0, W + 1, 40):
    gd.line([(x, 0), (x, H)], fill=hx("#16202c", 60), width=1)
for y in range(0, H + 1, 40):
    gd.line([(0, y), (W, y)], fill=hx("#16202c", 60), width=1)
canvas = Image.alpha_composite(canvas, grid)


def glow(base, center, radius, color, alpha, blur):
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    x, y = center
    d.ellipse([x - radius, y - radius, x + radius, y + radius], fill=(*color, alpha))
    layer = layer.filter(ImageFilter.GaussianBlur(blur))
    base = Image.alpha_composite(base, layer)
    return base


canvas = glow(canvas, (210, 250), 210, (255, 45, 85), 90, 130)
canvas = glow(canvas, (1500, 60), 280, (34, 211, 238), 42, 150)
canvas = glow(canvas, (1100, 430), 220, (255, 122, 24), 34, 150)

# ---------------------------------------------------------------- emblem
C = (215, 235)
NODES = [(215, 84, "LLMNR"), (74, 336, "NBT-NS"), (356, 336, "mDNS")]
OUTER_R = 64
for nx, ny, _ in NODES:
    dx, dy = C[0] - nx, C[1] - ny
    dist = math.hypot(dx, dy)
    ux, uy = dx / dist, dy / dist
    stop = (C[0] - ux * (OUTER_R + 18), C[1] - uy * (OUTER_R + 18))
    dashed(canvas, (nx, ny), stop, color=hx("#2c3e56", 220), width=3, dash=11, gap=9)
    arrowhead(canvas, stop, (nx, ny), 15, hx("#3a5170"))

d = ImageDraw.Draw(canvas)
for r, col, wd in [(64, hx("#ff3b3b", 235), 3), (49, hx("#ff5a5f", 120), 2), (35, hx("#ff7a18", 90), 2)]:
    d.ellipse([C[0] - r, C[1] - r, C[0] + r, C[1] + r], outline=col, width=wd)
# crosshair ticks
for ax, ay in [(1, 0), (-1, 0), (0, 1), (0, -1)]:
    d.line([(C[0] + ax * 64, C[1] + ay * 64), (C[0] + ax * 78, C[1] + ay * 78)], fill=hx("#ff3b3b", 230), width=3)
d.ellipse([C[0] - 15, C[1] - 15, C[0] + 15, C[1] + 15], fill=hx("#ff3b3b"))
d.ellipse([C[0] - 6, C[1] - 6, C[0] + 6, C[1] + 6], fill=hx("#ffd166"))

mono = lambda s: font(FIRACODE_BOLD, s)
for nx, ny, label in NODES:
    d.ellipse([nx - 13, ny - 13, nx + 13, ny + 13], outline=hx("#22d3ee", 110), width=2)
    d.ellipse([nx - 7, ny - 7, nx + 7, ny + 7], fill=hx("#22d3ee"))
    d.text((nx + 22, ny + 1), label, font=mono(24), fill=hx("#7dd3fc"), anchor="lm")

# ---------------------------------------------------------------- top bar
canvas.paste(h_gradient_img(W, 8, [(0.0, hx("#ff3b3b")), (0.5, hx("#ff7a18")), (1.0, hx("#ffbf3f"))]), (0, 0))

# ---------------------------------------------------------------- red team badge (top-right)
badge_font = mono(24)
icon_font = font(FA, 26)
icon_txt = "\uf54c"  # skull
label_txt = "RED TEAM"
pad = 24
gap = 14
iw = d.textlength(icon_txt, font=icon_font)
tw = d.textlength(label_txt, font=badge_font)
bw = pad + iw + gap + tw + pad
bh = 48
bx1 = W - 52
bx0 = bx1 - bw
by0 = 40
d.rounded_rectangle([bx0, by0, bx1, by0 + bh], bh / 2, fill=hx("#2a1114"), outline=hx("#ff3b3b"), width=2)
d.text((bx0 + pad, by0 + bh / 2), icon_txt, font=icon_font, fill=hx("#ff5a5f"), anchor="lm")
d.text((bx0 + pad + iw + gap, by0 + bh / 2 + 1), label_txt, font=badge_font, fill=hx("#ff8a8a"), anchor="lm")

# ---------------------------------------------------------------- text block
x0 = 476
title = "RESPONDER"
title_font = mono(94)

glowlayer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
ImageDraw.Draw(glowlayer).text((x0, 152), title, font=title_font, fill=hx("#ff3b3b", 190), anchor="ls")
glowlayer = glowlayer.filter(ImageFilter.GaussianBlur(18))
canvas = Image.alpha_composite(canvas, glowlayer)

text_gradient(
    canvas,
    (x0, 152),
    title,
    title_font,
    [(0.0, hx("#ff5a5f")), (0.55, hx("#ff9a3c")), (1.0, hx("#ffd166"))],
    anchor="ls",
)
d = ImageDraw.Draw(canvas)
tbb = d.textbbox((x0, 152), title, font=title_font, anchor="ls")
ul_w = tbb[2] - tbb[0]
canvas.paste(
    h_gradient_img(int(ul_w), 5, [(0.0, hx("#ff5a5f")), (1.0, hx("#ffd166"))]),
    (x0, tbb[3] + 12),
)

tag_font = font(DEJAVU_REG, 31)
d.text((x0, 236), "Name-resolution poisoning  \u00b7  rogue authentication servers", font=tag_font, fill=hx("#9fb3c8"), anchor="ls")

# protocol pills
pill_font = mono(24)
labels = ["LLMNR", "NBT-NS", "mDNS", "DHCPv6", "DNS", "WPAD"]
px = x0
py0, ph = 274, 46
for lab in labels:
    pw = d.textlength(lab, font=pill_font) + 46
    d.rounded_rectangle([px, py0, px + pw, py0 + ph], ph / 2, fill=hx("#101a26"), outline=hx("#26384f"), width=2)
    d.text((px + pw / 2, py0 + ph / 2 + 1), lab, font=pill_font, fill=hx("#7dd3fc"), anchor="mm")
    px += pw + 14
pills_end = px - 14

# terminal box
tb_x0, tb_y0 = x0, 346
tb_w = max(780, pills_end - x0)
tb_h = 62
d.rounded_rectangle([tb_x0, tb_y0, tb_x0 + tb_w, tb_y0 + tb_h], 12, fill=hx("#080c11"), outline=hx("#1e2a3a"), width=2)
icon_font2 = font(FA, 24)
d.text((tb_x0 + 20, tb_y0 + tb_h / 2), "\uf120", font=icon_font2, fill=hx("#4ade80"), anchor="lm")
cmd_font = mono(26)
cmd = "responder -I eth0 -w -d"
cx = tb_x0 + 58
d.text((cx, tb_y0 + tb_h / 2 + 1), "$", font=cmd_font, fill=hx("#4ade80"), anchor="lm")
cw = d.textlength("$ ", font=cmd_font)
d.text((cx + cw, tb_y0 + tb_h / 2 + 1), cmd, font=cmd_font, fill=hx("#d7e3f0"), anchor="lm")
cur_x = cx + cw + d.textlength(cmd, font=cmd_font) + 12
d.rectangle([cur_x, tb_y0 + 18, cur_x + 12, tb_y0 + 44], fill=hx("#4ade80"))

# footer
foot = mono(20)
d.text((x0, 430), "github.com/orionhack99/responder-rust", font=foot, fill=hx("#3f5568"), anchor="ls")
d.text((W - 52, 430), "for authorized security testing only", font=foot, fill=hx("#7a5252"), anchor="rs")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
canvas.convert("RGB").save(OUT, "PNG", optimize=True)
print("wrote", OUT, canvas.size)
print("  title bbox:", tbb, "underline_w:", ul_w)
print("  tagline bbox:", d.textbbox((x0, 236), "Name-resolution poisoning  \u00b7  rogue authentication servers", font=tag_font, anchor="ls"))
print("  pills_end:", pills_end, "terminal_right:", x0 + tb_w)
print("  badge:", bx0, by0, bx1, by0 + bh)
print("  footer right edge:", W - 52)
