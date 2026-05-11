"""Generate the JPEG fixture images for the Day 3 inference-pipeline scenarios.

Each scenario emits one or more 640x480 JPEGs into
``tests/fixtures/day-3-scenarios/{N}/imageM.jpg``. The images are stylised
illustrations drawn with Pillow, not photographs; they exist to give the
multimodal model recognisable shapes and colours to describe so the
consistency-check pass has real content to reason about.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def _font(size: int) -> ImageFont.ImageFont:
    """Return a TrueType font, falling back to the bitmap default."""
    for candidate in (
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ):
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default()


def construction_site() -> Image.Image:
    """Render a construction-site scene: excavator, rebar, workers, fence."""
    img = Image.new("RGB", (640, 480), (210, 200, 180))
    draw = ImageDraw.Draw(img)
    draw.rectangle((0, 320, 640, 480), fill=(140, 110, 80))
    draw.rectangle((20, 200, 80, 320), fill=(200, 200, 200))
    draw.rectangle((80, 100, 86, 320), fill=(180, 180, 180))
    draw.rectangle((86, 100, 240, 130), fill=(180, 180, 180))
    draw.rectangle((230, 200, 470, 320), fill=(230, 200, 40))
    draw.rectangle((260, 170, 360, 220), fill=(230, 200, 40))
    draw.ellipse((230, 290, 290, 350), fill=(40, 40, 40))
    draw.ellipse((410, 290, 470, 350), fill=(40, 40, 40))
    for offset in range(0, 6):
        draw.line((480 + offset * 12, 280, 480 + offset * 12, 320), fill=(140, 90, 30), width=4)
    for worker_x in (130, 540):
        draw.rectangle((worker_x - 12, 250, worker_x + 12, 300), fill=(255, 120, 0))
        draw.ellipse((worker_x - 10, 220, worker_x + 10, 250), fill=(255, 220, 180))
        draw.rectangle((worker_x - 14, 215, worker_x + 14, 225), fill=(255, 220, 0))
    draw.text((20, 20), "ELM ST SITE 14 OCT", fill=(40, 40, 40), font=_font(22))
    return img


def construction_signage() -> Image.Image:
    """A close-up of the safety signage on the perimeter fence."""
    img = Image.new("RGB", (640, 480), (200, 200, 200))
    draw = ImageDraw.Draw(img)
    for x in range(0, 640, 40):
        draw.line((x, 0, x, 480), fill=(160, 160, 160), width=2)
    for y in range(0, 480, 40):
        draw.line((0, y, 640, y), fill=(160, 160, 160), width=2)
    draw.rectangle((120, 120, 520, 360), fill=(255, 240, 80), outline=(0, 0, 0), width=6)
    draw.text((150, 150), "DANGER", fill=(180, 0, 0), font=_font(56))
    draw.text((150, 220), "HARD HAT", fill=(0, 0, 0), font=_font(36))
    draw.text((150, 260), "AND VEST", fill=(0, 0, 0), font=_font(36))
    draw.text((150, 310), "REQUIRED", fill=(0, 0, 0), font=_font(36))
    return img


def creek_scene() -> Image.Image:
    """A creek with stones, a wooden footbridge, and oak trees in autumn."""
    img = Image.new("RGB", (640, 480), (150, 200, 230))
    draw = ImageDraw.Draw(img)
    draw.rectangle((0, 280, 640, 480), fill=(90, 140, 70))
    draw.polygon([(0, 280), (640, 280), (640, 380), (0, 380)], fill=(120, 180, 220))
    for stone in ((80, 340), (200, 360), (320, 345), (440, 365), (560, 340)):
        draw.ellipse((stone[0] - 18, stone[1] - 10, stone[0] + 18, stone[1] + 10), fill=(160, 150, 140))
    draw.rectangle((260, 260, 500, 280), fill=(120, 80, 40))
    draw.rectangle((260, 280, 280, 340), fill=(120, 80, 40))
    draw.rectangle((480, 280, 500, 340), fill=(120, 80, 40))
    for trunk_x in (60, 580):
        draw.rectangle((trunk_x - 10, 200, trunk_x + 10, 320), fill=(90, 60, 30))
        draw.ellipse((trunk_x - 60, 120, trunk_x + 60, 240), fill=(220, 140, 40))
    draw.text((20, 20), "PARK CREEK 1700", fill=(40, 40, 40), font=_font(22))
    return img


def parking_lot_one() -> Image.Image:
    """Empty parking lot, daylight, painted parking lines, light pole."""
    img = Image.new("RGB", (640, 480), (180, 195, 215))
    draw = ImageDraw.Draw(img)
    draw.rectangle((0, 260, 640, 480), fill=(70, 70, 75))
    for x in range(40, 640, 80):
        draw.rectangle((x, 280, x + 6, 460), fill=(240, 240, 240))
    draw.rectangle((300, 80, 312, 260), fill=(60, 60, 60))
    draw.ellipse((280, 60, 332, 100), fill=(240, 240, 100))
    draw.text((20, 20), "LOT B EXTERIOR", fill=(40, 40, 40), font=_font(22))
    return img


def parking_lot_two() -> Image.Image:
    """Parking lot from the opposite corner, with two parked cars and curb."""
    img = Image.new("RGB", (640, 480), (175, 190, 210))
    draw = ImageDraw.Draw(img)
    draw.rectangle((0, 240, 640, 480), fill=(80, 80, 85))
    draw.rectangle((0, 240, 640, 250), fill=(220, 220, 200))
    draw.rectangle((120, 290, 280, 380), fill=(40, 80, 160))
    draw.ellipse((130, 360, 170, 400), fill=(20, 20, 20))
    draw.ellipse((240, 360, 280, 400), fill=(20, 20, 20))
    draw.rectangle((360, 300, 520, 380), fill=(180, 30, 30))
    draw.ellipse((370, 360, 410, 400), fill=(20, 20, 20))
    draw.ellipse((480, 360, 520, 400), fill=(20, 20, 20))
    draw.text((20, 20), "LOT B WEST CORNER", fill=(40, 40, 40), font=_font(22))
    return img


def scenarios_root() -> Path:
    """Return the day-3-scenarios fixture directory."""
    here = Path(__file__).resolve()
    return here.parent


def save(scenario: int, name: str, image: Image.Image) -> None:
    """Write `image` as a quality-90 JPEG under ``scenario/name``."""
    out_dir = scenarios_root() / str(scenario)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / name
    image.save(target, format="JPEG", quality=90)
    print(f"wrote {target}")


def main() -> None:
    """Generate all fixture images."""
    save(1, "image1.jpg", construction_site())
    save(1, "image2.jpg", construction_signage())
    save(2, "image1.jpg", creek_scene())
    save(3, "image1.jpg", parking_lot_one())
    save(3, "image2.jpg", parking_lot_two())


if __name__ == "__main__":
    main()
