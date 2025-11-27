import os, math
from collections import Counter
from zipfile import ZipFile

def entropy(b: bytes) -> float:
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def _scan_docx_embeds(path):
    embeds = []
    try:
        with ZipFile(path, "r") as z:
            for name in z.namelist():
                if name.startswith("word/embeddings/") or name.startswith("word/media/"):
                    data = z.read(name)
                    suspicious_ext = any(name.lower().endswith(ext) for ext in (
                        ".bin",".exe",".dll",".js",".vbs",".ps1",".zip",".rar",".7z"
                    ))
                    embeds.append({
                        "name": name,
                        "length": len(data),
                        "entropy": round(entropy(data),3),
                        "suspicious_ext": suspicious_ext
                    })
            # Macro indicator in docx/docm
            has_vba = "word/vbaProject.bin" in z.namelist()
    except Exception as e:
        return {"error": f"zip-open-failed: {e}", "embeds": [], "macros": {"has_macros": False}}
    return {"embeds": embeds, "macros": {"has_macros": has_vba, "tool": "zip-scan"}}

def _scan_doc_ole(path):
    # Legacy .doc: try oletools (olevba) if available
    try:
        from oletools.olevba import VBA_Parser
    except Exception:
        return {"embeds": [], "macros": {"has_macros": False, "note": "oletools not available"}}
    result = {"embeds": [], "macros": {"has_macros": False}}
    try:
        vba = VBA_Parser(path)
        result["macros"]["has_macros"] = vba.detect_vba_macros()
        if result["macros"]["has_macros"]:
            # Count macro streams
            macros = []
            for (filename, stream_path, vba_filename, vba_code) in vba.extract_all_macros():
                macros.append({"filename": vba_filename, "size": len(vba_code or b"")})
            result["macros"]["streams"] = macros
    except Exception as e:
        result["error"] = f"ole-parse-failed: {e}"
    return result

def analyze_docx_embeds(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".docx" or ext == ".docm":
        return _scan_docx_embeds(path)
    elif ext == ".doc":
        return _scan_doc_ole(path)
    else:
        return {"embeds": [], "macros": {"has_macros": False}, "note": "not a doc/docx"}
