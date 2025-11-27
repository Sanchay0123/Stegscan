import os, math
from collections import Counter

MAGICS = [
    (b"PK\x03\x04", "zip"),
    (b"Rar!", "rar"),
    (b"\x37\x7A\xBC\xAF\x27\x1C", "7z"),
    (b"%PDF", "pdf"),
    (b"MZ", "exe"),
]

def entropy(b: bytes) -> float:
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def extract_jpeg_segments(data):
    """
    Returns all JPEG APP / COM segments as raw bytes.
    """
    segments = []
    i = 0
    while True:
        i = data.find(b'\xFF', i)
        if i == -1 or i+1 >= len(data):
            break
        marker = data[i+1]
        # APP0-APP15 markers: 0xE0 - 0xEF
        if 0xE0 <= marker <= 0xEF or marker == 0xFE:  # COM marker
            # length of segment stored in next 2 bytes
            if i+4 <= len(data):
                length = (data[i+2] << 8) + data[i+3]
                segment_data = data[i+4:i+2+length]
                segments.append(segment_data)
                i += length + 2
            else:
                break
        else:
            i += 1
    return segments

def analyze_file_append(path):
    ext = os.path.splitext(path)[1].lower()
    if ext not in [".jpg",".jpeg"]:
        return {"supported": False, "reason": "not jpeg"}

    with open(path, "rb") as f:
        data = f.read()

    segments = extract_jpeg_segments(data)

    if not segments:
        return {"supported": True, "found": False, "suspicion": 0.0}

    suspicion = 0.0
    hits = []

    for seg in segments:
        e = entropy(seg)
        for sig, name in MAGICS:
            if sig in seg:
                suspicion += 1.0
                hits.append(name)
        if e > 6.5:
            suspicion += 0.3

    return {
        "supported": True,
        "found": len(hits) > 0,
        "hits": hits,
        "entropy_avg": round(sum(entropy(s) for s in segments) / len(segments), 3),
        "suspicion": round(suspicion,3)
    }
