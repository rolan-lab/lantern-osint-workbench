"""Render Lantern's logo (concentric rings) into a multi-size .ico — pure Python, no Pillow needed.

    python make_icon.py [lantern.ico]      desktop icon
    python make_icon.py --pwa ../icons     home-screen icons for the installable web app
"""
import math
import struct
import sys
import zlib
from pathlib import Path

BG = (26, 26, 25)        # dark surface
ACCENT = (57, 135, 229)  # dark-theme accent blue
SS = 4                   # supersampling for anti-aliasing


def coverage(px: float, py: float, n: float, scale: float = 1.0, radius: float = 7.0) -> tuple[float, float]:
    """Return (background alpha, accent alpha) at a sample point, in a 32-unit design grid like the SVG logo."""
    x, y = px / n * 32, py / n * 32
    # rounded-square background, corner radius 7
    r, lo, hi = radius, 0.0, 32.0
    dx = max(lo + r - x, 0, x - (hi - r)); dy = max(lo + r - y, 0, y - (hi - r))
    bg = 1.0 if dx * dx + dy * dy <= r * r else 0.0
    d = math.hypot(x - 16, y - 16) / scale  # scale < 1 shrinks the rings inside the square (maskable safe zone)
    acc = 0.0
    if abs(d - 11.2) <= 1.6: acc = 1.0          # outer ring
    elif abs(d - 6.1) <= 1.6: acc = 0.6         # inner ring (dimmed)
    elif d <= 2.6: acc = 1.0                    # centre dot
    return bg, acc


def render(size: int, scale: float = 1.0, radius: float = 7.0) -> bytes:
    rows = []
    n = size * SS
    for y in range(size):
        row = bytearray([0])  # PNG filter: none
        for x in range(size):
            bg_sum = acc_sum = 0.0
            for sy in range(SS):
                for sx in range(SS):
                    b, a = coverage(x * SS + sx + 0.5, y * SS + sy + 0.5, n, scale, radius)
                    bg_sum += b; acc_sum += a * b
            k = SS * SS
            alpha = bg_sum / k
            mix = acc_sum / bg_sum if bg_sum else 0.0
            rgb = [round(BG[i] * (1 - mix) + ACCENT[i] * mix) for i in range(3)]
            row += bytes(rgb + [round(alpha * 255)])
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(t: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + t + data + struct.pack(">I", zlib.crc32(t + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def build_ico(path: Path, sizes=(16, 24, 32, 48, 64, 128, 256)) -> None:
    images = [render(s) for s in sizes]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    for s, img in zip(sizes, images):
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(img), offset)
        offset += len(img)
    path.write_bytes(header + entries + b"".join(images))
    (path.with_suffix(".png")).write_bytes(images[-1])


def build_pwa(folder: Path) -> None:
    """Icons referenced by manifest.webmanifest and index.html. Full-bleed variants have no transparent corners,
    because iOS and Android apply their own mask."""
    folder.mkdir(parents=True, exist_ok=True)
    for name, size, scale, radius in (("icon-192.png", 192, 1.0, 7.0), ("icon-512.png", 512, 1.0, 7.0),
                                      ("icon-maskable-512.png", 512, 0.62, 0.0), ("apple-touch-icon.png", 180, 0.78, 0.0)):
        (folder / name).write_bytes(render(size, scale, radius))
        print(f"wrote {folder / name}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--pwa":
        build_pwa(Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).parent.parent / "icons")
        sys.exit(0)
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("lantern.ico")
    build_ico(out)
    print(f"wrote {out}")
