import os, struct, zlib

SIG_LFH = b"\x50\x4B\x03\x04"  # local file header
SIG_CEN = b"\x50\x4B\x01\x02"  # central dir header
SIG_EOCD= b"\x50\x4B\x05\x06"  # end of central dir

def _find_all(data: bytes, sig: bytes):
    i = 0
    while True:
        i = data.find(sig, i)
        if i == -1: break
        yield i
        i += 1

def _dump(path, name, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f: f.write(data)
    return path

def _concat_idat(png_bytes: bytes):
    if not png_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("not a PNG")
    idat = b""
    i = 8
    L = len(png_bytes)
    while i+8 <= L:
        length = struct.unpack(">I", png_bytes[i:i+4])[0]
        ctype  = png_bytes[i+4:i+8]
        chunk  = png_bytes[i+8:i+8+length]
        if ctype == b"IDAT":
            idat += chunk
        i += 12 + length
        if i > L: break
    return idat

def _inflate(data: bytes):
    # try raw zlib
    try:
        return zlib.decompress(data)
    except Exception:
        # try with a decompressor to be tolerant to trailing junk
        try:
            d = zlib.decompressobj()
            out = d.decompress(data)
            out += d.flush()
            return out
        except Exception as e2:
            raise e2

def _carve_by_eocd(bytes_blob: bytes):
    """If EOCD exists, carve from the first LFH before it to EOCD end (22 + comment)."""
    eocd_off = bytes_blob.rfind(SIG_EOCD)
    if eocd_off == -1: return None
    if eocd_off + 22 > len(bytes_blob): return None
    # read comment length
    # EOCD structure: 4s 2H 2H 2H 2H 4I 2H -> we only need last 2 bytes (comment length)
    comment_len = struct.unpack("<H", bytes_blob[eocd_off+20:eocd_off+22])[0]
    end_off = eocd_off + 22 + comment_len
    # find a plausible start: nearest LFH before EOCD
    lfh_positions = list(_find_all(bytes_blob[:eocd_off], SIG_LFH))
    if not lfh_positions: 
        # fallback: central dir header
        cen_positions = list(_find_all(bytes_blob[:eocd_off], SIG_CEN))
        start_off = cen_positions[0] if cen_positions else None
    else:
        start_off = lfh_positions[0]
    if start_off is None: 
        # as last resort, take some window before EOCD
        start_off = max(0, eocd_off - 2_000_000)
    return bytes_blob[start_off:end_off]

def extract_zip_from_png(src_path: str, out_dir="extracted_payloads"):
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.basename(src_path)
    png = open(src_path, "rb").read()

    # 0) quick global scans (sometimes PK exists in whole file)
    for sig, tag in [(SIG_LFH,"LFH"), (SIG_EOCD,"EOCD")]:
        if png.find(sig) != -1:
            out_raw = os.path.join(out_dir, base + f".wholefile_{tag}.carve")
            return _dump(out_raw, "raw", png[png.find(sig):]), f"Found {tag} in whole PNG; carved."

    # 1) collect IDAT compressed stream
    try:
        idat = _concat_idat(png)
    except Exception as e:
        return None, f"PNG parse failed: {e}"

    # Save compressed IDAT for forensics
    idat_path = os.path.join(out_dir, base + ".idat.zlib")
    _dump(idat_path, "idat", idat)

    # 2) check inside compressed stream directly
    for sig, tag in [(SIG_LFH,"LFH"), (SIG_EOCD,"EOCD")]:
        pos = idat.find(sig)
        if pos != -1:
            outp = os.path.join(out_dir, base + f".idat_{tag}.carve")
            return _dump(outp, "idat-carve", idat[pos:]), f"Found {tag} in compressed IDAT; carved."

    # 3) inflate IDAT to raw scanlines
    try:
        raw = _inflate(idat)
    except Exception as e:
        return None, f"IDAT decompression failed: {e}"

    raw_path = os.path.join(out_dir, base + ".idat.raw")
    _dump(raw_path, "raw", raw)  # always keep a raw dump

    # 4) EOCD-guided carve from raw (most robust)
    carved = _carve_by_eocd(raw)
    if carved:
        outp = os.path.join(out_dir, base + ".zip")
        _dump(outp, "zip", carved)
        return outp, f"Rebuilt from EOCD ({len(carved)} bytes)."

    # 5) fallback: first LFH in raw
    lfh_pos = raw.find(SIG_LFH)
    if lfh_pos != -1:
        outp = os.path.join(out_dir, base + ".lfh.carve")
        _dump(outp, "lfh", raw[lfh_pos:])
        return outp, "Carved from first LFH in raw scanlines."

    # 6) last resort: take a big window of high-entropy raw as evidence
    # (keep idat.raw already saved; we mark as evidence)
    return None, "No reconstructable ZIP found; saved IDAT compressed & raw for forensics."
