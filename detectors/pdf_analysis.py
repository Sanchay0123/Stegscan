import re, os, math
from collections import Counter
from PyPDF2 import PdfReader

MAGIC_SIGS = [
    (b"PK\x03\x04", "zip"),
    (b"%PDF", "pdf"),
    (b"MZ", "pe"),
    (b"Rar!", "rar"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
]

def entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())

def _scan_raw_streams(pdf_bytes: bytes):
    # crude but effective: find stream ... endstream blocks
    streams = []
    # Handles "stream\r\n" or "stream\n"
    for m in re.finditer(rb"stream\r?\n", pdf_bytes):
        start = m.end()
        endm = re.search(rb"\nendstream", pdf_bytes[start:])
        if not endm: break
        end = start + endm.start()
        blob = pdf_bytes[start:end]
        e = entropy(blob)
        magic = None
        for sig, name in MAGIC_SIGS:
            if sig in blob[:16]:
                magic = name; break
        streams.append({
            "index": len(streams),
            "length": len(blob),
            "entropy": round(e,3),
            "magic_hit": magic is not None,
            "magic": magic or "-"
        })
    return streams

def _extract_attachments(reader: PdfReader):
    # PyPDF2: embedded files are under Names/EmbeddedFiles
    atts = []
    try:
        root = reader.trailer["/Root"]
        names = root.get("/Names")
        if names:
            embedded = names.get("/EmbeddedFiles")
            if embedded:
                kids = embedded.get("/Names")
                if isinstance(kids, list):
                    for i in range(0, len(kids), 2):
                        fname = kids[i]
                        fs = kids[i+1].get_object()
                        ef = fs["/EF"]["/F"].get_object()
                        data = ef.get_data()
                        atts.append({
                            "name": str(fname),
                            "length": len(data),
                            "entropy": round(entropy(data),3)
                        })
    except Exception:
        pass
    return atts

def analyze_pdf_streams(path):
    out = {"streams": [], "attachments": [], "js_actions": False}
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        return {"error": f"open-failed: {e}"}

    out["streams"] = _scan_raw_streams(data)

    # Check for JavaScript markers
    if b"/JS" in data or b"/JavaScript" in data or b"/OpenAction" in data or b"/AA" in data:
        out["js_actions"] = True

    # Extract attachments via PyPDF2
    try:
        reader = PdfReader(path)
        out["attachments"] = _extract_attachments(reader)
    except Exception:
        pass

    return out
