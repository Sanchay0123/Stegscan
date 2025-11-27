import struct, os, math
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

def analyze_png_chunks(path):
    ext = os.path.splitext(path)[1].lower()
    if ext != ".png":
        return {"supported": False}

    data = open(path, "rb").read()

    # PNG signature check
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return {"supported": False, "error": "not png signature"}

    i = 8
    suspicious = 0.0
    findings = []

    while i < len(data):
        if i+8 > len(data): break
        length = struct.unpack(">I", data[i:i+4])[0]
        ctype = data[i+4:i+8]
        chunk_data = data[i+8:i+8+length]

        # detect zip signatures inside chunk
        for sig, name in MAGICS:
            if sig in chunk_data:
                suspicious += 1.2
                findings.append(f"{name} in chunk {ctype.decode(errors='ignore')}")

        # entropy check for compressed embedded data
        e = entropy(chunk_data)
        if e > 6.8:
            suspicious += 0.4

        i += 12 + length  # skip chunk + CRC

    return {
        "supported": True,
        "suspicion": round(suspicious,3),
        "findings": findings
    }
