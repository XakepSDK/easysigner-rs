"""Draws kzsigner's icon: assets/kzsigner.png (256 px), assets/kzsigner.ico (16..256 px),
assets/kzsigner-64.rgba (the window icon, raw 64x64 RGBA so the program needs no PNG decoder).

Run: python3 packaging/make-icon.py   (needs Pillow). The outputs are committed, so builds
do not need Python."""
from PIL import Image, ImageDraw

S = 1024  # drawn large, scaled down for each size


def draw():
    im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # background: rounded square, sky blue to deep blue (top to bottom)
    grad = Image.new("RGBA", (S, S))
    gd = ImageDraw.Draw(grad)
    top, bot = (0, 175, 202), (0, 92, 158)
    for y in range(S):
        t = y / (S - 1)
        gd.line([(0, y), (S, y)], fill=tuple(round(a + (b - a) * t) for a, b in zip(top, bot)) + (255,))
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([40, 40, S - 40, S - 40], radius=200, fill=255)
    im.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(im)
    # document with a folded corner
    x0, y0, x1, y1, fold = 250, 170, 700, 800, 150
    d.polygon([(x0, y0), (x1 - fold, y0), (x1, y0 + fold), (x1, y1), (x0, y1)], fill=(255, 255, 255, 255))
    d.polygon([(x1 - fold, y0), (x1 - fold, y0 + fold), (x1, y0 + fold)], fill=(196, 222, 236, 255))
    # text lines
    for i, w in enumerate([300, 330, 250, 330, 180]):
        y = 330 + i * 75
        d.rounded_rectangle([x0 + 60, y, x0 + 60 + w, y + 30], radius=15, fill=(150, 180, 200, 255))
    # gold seal with a check mark
    cx, cy, r = 700, 720, 190
    d.ellipse([cx - r - 22, cy - r - 22, cx + r + 22, cy + r + 22], fill=(0, 92, 158, 255))
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(254, 197, 20, 255))
    d.line([(cx - 95, cy + 5), (cx - 25, cy + 80), (cx + 100, cy - 75)], fill=(255, 255, 255, 255), width=56, joint="curve")
    for x, y in [(cx - 95, cy + 5), (cx + 100, cy - 75)]:
        d.ellipse([x - 28, y - 28, x + 28, y + 28], fill=(255, 255, 255, 255))
    return im


if __name__ == "__main__":
    im = draw()
    im.resize((256, 256), Image.LANCZOS).save("assets/kzsigner.png", optimize=True)
    open("assets/kzsigner-64.rgba", "wb").write(im.resize((64, 64), Image.LANCZOS).tobytes())
    sizes = [16, 24, 32, 48, 64, 128, 256]
    im.resize((256, 256), Image.LANCZOS).save("assets/kzsigner.ico", sizes=[(s, s) for s in sizes])
