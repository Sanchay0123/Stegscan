import os, json, hashlib, time

def _safe_name(path):
    base = os.path.basename(path)
    h = hashlib.sha1(path.encode()).hexdigest()[:8]
    return f"{base}.{h}.json"

def save_report(src_file, results):
    os.makedirs("reports", exist_ok=True)
    name = _safe_name(src_file)
    outpath = os.path.join("reports", name)
    results["_meta"] = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tool": "stegscan v1"
    }
    with open(outpath, "w") as f:
        json.dump(results, f, indent=2)
    return outpath
