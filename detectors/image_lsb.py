from PIL import Image
import numpy as np, math
from collections import Counter

def file_entropy_bytes(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def _img_to_array(img: Image.Image):
    if img.mode not in ("RGB","L"):
        img = img.convert("RGB")
    return np.array(img)

def _lsb_bits(arr: np.ndarray):
    if arr.ndim == 3:
        return (arr & 1).reshape(-1)
    return (arr & 1).reshape(-1)

def _chi_square(arr: np.ndarray):
    vals = arr.flatten()
    hist = np.bincount(vals, minlength=256)
    chi = 0.0
    for i in range(0, 256, 2):
        o1, o2 = hist[i], hist[i+1]
        e = (o1 + o2) / 2.0
        if e > 0:
            chi += ((o1 - e)**2)/e + ((o2 - e)**2)/e
    return float(chi)

def _local_entropy(arr: np.ndarray, window=16):
    if arr.ndim == 3:
        gray = (0.2989*arr[:,:,0] + 0.5870*arr[:,:,1] + 0.1140*arr[:,:,2]).astype("uint8")
    else:
        gray = arr
    h, w = gray.shape
    ents = []
    for y in range(0, h, window):
        for x in range(0, w, window):
            block = gray[y:y+window, x:x+window].tobytes()
            ents.append(file_entropy_bytes(block))
    return float(np.mean(ents)) if ents else 0.0

def analyze_image(path):
    try:
        img = Image.open(path)
    except Exception as e:
        return {"error": f"open-failed: {e}", "suspicious_score": 0.0}
    arr = _img_to_array(img)
    bits = _lsb_bits(arr)
    ones = int(bits.sum()); zeros = bits.size - ones
    prop = ones / bits.size if bits.size else 0
    chi = _chi_square(arr)
    ent_full = file_entropy_bytes(img.tobytes())
    ent_local = _local_entropy(arr)

    score = 0.0
    if abs(prop - 0.5) < 0.02: score += 0.6
    if ent_full > 7.5: score += 0.5
    if ent_local > 6.5: score += 0.4

    return {
        "prop_one": round(prop,4),
        "chi_square": round(chi,3),
        "entropy_full": round(ent_full,3),
        "entropy_local": round(ent_local,3),
        "suspicious_score": round(score,3)
    }
