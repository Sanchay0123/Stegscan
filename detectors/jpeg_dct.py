import os
import numpy as np

# Try jpegio (preferred)
try:
    import jpegio as jio
    _HAS_JPEGIO = True
except Exception:
    _HAS_JPEGIO = False

def _ac_coeffs(dct):
    # flatten AC coefficients (exclude (0,0) DC)
    h, w = dct.shape
    mask = np.ones((h,w), dtype=bool)
    mask[0,0] = False
    return dct[mask].astype(np.int32)

def _parity_ratio(ac):
    nz = ac[ac != 0]
    if nz.size == 0: return 0.0
    odds = np.sum((np.abs(nz) % 2) == 1)
    return odds / nz.size

def _hist_flatness(ac):
    # how flat the histogram of magnitudes looks (flatter => more suspicious)
    mags = np.abs(ac)
    mags = mags[mags > 0]
    if mags.size == 0: return 0.0
    hist = np.bincount(mags, minlength=min(64, mags.max()+1))[:64].astype(float)
    if hist.sum() == 0: return 0.0
    p = hist / hist.sum()
    uniform = np.ones_like(p) / len(p)
    # compute L2 distance to uniform; smaller distance => flatter => suspicious
    l2 = np.sqrt(np.sum((p - uniform)**2))
    # normalize to 0..1 then invert so higher means flatter
    max_l2 = np.sqrt(np.sum((uniform - np.eye(1, len(p), 0).flatten())**2))  # rough upper bound
    flat_score = 1.0 - min(1.0, l2 / (max_l2 + 1e-8))
    return float(flat_score)

def analyze_jpeg_dct(path):
    ext = os.path.splitext(path)[1].lower()
    if ext not in [".jpg",".jpeg"]:
        return {"supported": False, "dct_suspicion": 0.0, "note": "not a jpeg"}
    if not _HAS_JPEGIO:
        return {"supported": False, "dct_suspicion": 0.0, "note": "jpegio not available"}

    try:
        J = jio.read(path)
    except Exception as e:
        return {"supported": False, "dct_suspicion": 0.0, "error": f"jpeg read failed: {e}"}

    # Combine all component AC coefficients
    ac_all = []
    for comp in J.coef_arrays:
        ac_all.append(_ac_coeffs(comp))
    if not ac_all:
        return {"supported": True, "dct_suspicion": 0.0, "note": "no coef arrays"}
    ac = np.concatenate(ac_all)

    parity = _parity_ratio(ac)            # ~0.5 means suspicious (embedding randomizes parity)
    flat = _hist_flatness(ac)             # closer to 1.0 => flatter => suspicious

    susp = 0.0
    if 0.47 <= parity <= 0.53: susp += 0.5
    if flat >= 0.6: susp += 0.5

    return {
        "supported": True,
        "parity_ratio": round(parity,4),
        "hist_flatness": round(flat,3),
        "dct_suspicion": round(susp,3)
    }
