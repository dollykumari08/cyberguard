import io
import numpy as np
from PIL import Image, ImageChops

AI_TOOLS = ["stable diffusion", "midjourney", "dall-e", "dalle", "firefly",
            "comfyui", "leonardo", "openai", "gan"]
GEN_SIZES = {512, 768, 1024, 1536, 2048}


def analyze_image(img):
    """Return (suspicion score 0-100, reasons)."""
    score, reasons = 0, []

    # 1. Metadata
    try:
        exif = dict(img.getexif())
    except Exception:
        exif = {}
    info_text = " ".join(str(v) for v in list(img.info.values()) + list(exif.values())).lower()
    if any(t in info_text for t in AI_TOOLS):
        score += 60
        reasons.append("Metadata names an AI image generator")
    elif not exif:
        score += 15
        reasons.append("No camera metadata (EXIF) found, common in generated or edited images")

    rgb = img.convert("RGB")
    rgb.thumbnail((1024, 1024))

    # 2. Typical generator resolution
    w, h = img.size
    if w == h and w in GEN_SIZES:
        score += 15
        reasons.append(f"Square {w}x{h} resolution typical of AI generators")

    # 3. Error Level Analysis: inconsistent compression suggests editing or splicing
    buf = io.BytesIO()
    rgb.save(buf, "JPEG", quality=90)
    buf.seek(0)
    ela = np.asarray(ImageChops.difference(rgb, Image.open(buf))).astype(float).mean(axis=2)
    H, W = ela.shape
    blocks = [ela[i*H//8:(i+1)*H//8, j*W//8:(j+1)*W//8].mean()
              for i in range(8) for j in range(8)]
    ratio = max(blocks) / (np.median(blocks) + 0.5)
    if ratio > 4:
        score += 30
        reasons.append(f"Inconsistent compression across regions (ELA ratio {ratio:.1f}), possible splicing")

    # 4. Over-smooth texture (AI skin and backgrounds often lack natural noise)
    g = np.asarray(rgb.convert("L")).astype(float)
    lap = (4*g[1:-1, 1:-1] - g[:-2, 1:-1] - g[2:, 1:-1] - g[1:-1, :-2] - g[1:-1, 2:])
    noise = lap.var()
    if noise < 15:
        score += 25
        reasons.append(f"Unnaturally smooth texture (noise level {noise:.1f})")

    return min(score, 100), reasons