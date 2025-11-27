#!/usr/bin/env python3
"""
Rewritten evaluation script for stegscan.

Usage:
    python eval.py --clean <clean_folder> --stego <stego_folder> --out <out_dir>

It calls run_scan() from stegscan.py for each image, interprets the label
using the scanner's numeric_score + threshold, and computes metrics.
It also saves per-file features CSV, metrics.json, threshold_candidates.json,
and confusion matrix + ROC curve PNGs.
"""

import os
import argparse
import csv
import json
from math import sqrt

from stegscan import run_scan, compute_numeric_score

IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".bmp", ".tiff")


def is_stego_label(label: str) -> bool:
    """Return True if the human-readable label means 'stego'."""
    if not label:
        return False
    lab = str(label).upper()
    return ("HIGH" in lab) or ("MEDIUM" in lab) or ("STEGO" in lab)


def scan_folder(folder: str, true_label: str, out_rows: list) -> None:
    """Scan all images in folder and append result rows to out_rows."""
    files = []
    for root, _, names in os.walk(folder):
        for n in names:
            if n.lower().endswith(IMAGE_EXTS):
                files.append(os.path.join(root, n))
    files.sort()

    for f in files:
        print("Scanning:", f)
        # use full scanner logic (numeric_score + threshold), not forced heuristic
        result = run_scan(f, force_heuristic=False)
        summary = result.get("summary", {}) or {}

        # numeric score (compute if missing)
        numeric = summary.get("numeric_score", None)
        if numeric is None:
            numeric = compute_numeric_score(result)
        numeric = float(numeric)

        # final textual classification from scanner
        label_str = summary.get("classification") or summary.get("heuristic_label") or ""
        pred_label = "stego" if is_stego_label(label_str) else "clean"

        # aggregate detector features over all images in this file
        imgs = result.get("images_results", []) or []
        nimg = max(1, len(imgs))

        lsb_susp = 0.0
        lsb_prop_one = 0.0
        lsb_ent_full = 0.0
        lsb_ent_local = 0.0

        dct_susp = 0.0
        dct_flatness = 0.0
        dct_parity = 0.0

        append_susp = 0.0
        append_entropy = 0.0

        png_susp = 0.0
        png_hits = 0

        for im in imgs:
            lsb = im.get("lsb", {}) or {}
            dct = im.get("dct", {}) or {}
            app = im.get("append", {}) or {}
            png = im.get("pngchunks", {}) or {}

            lsb_susp += float(lsb.get("suspicious_score", 0.0) or 0.0)
            lsb_prop_one += float(lsb.get("prop_one", 0.0) or 0.0)
            # FIX: use entropy_full / entropy_local from image_lsb.py
            lsb_ent_full += float(lsb.get("entropy_full", 0.0) or 0.0)
            lsb_ent_local += float(lsb.get("entropy_local", 0.0) or 0.0)

            dct_susp += float(dct.get("dct_suspicion", 0.0) or 0.0)
            dct_flatness += float(dct.get("hist_flatness", 0.0) or 0.0)
            dct_parity += float(dct.get("parity_ratio", 0.0) or 0.0)

            append_susp += float(app.get("suspicion", 0.0) or 0.0)
            append_entropy += float(app.get("entropy_avg", 0.0) or 0.0)

            png_susp += float(png.get("suspicion", 0.0) or 0.0)
            png_hits += len(png.get("findings") or [])

        # convert sums to averages per-image
        lsb_susp /= nimg
        lsb_prop_one /= nimg
        lsb_ent_full /= nimg
        lsb_ent_local /= nimg

        dct_susp /= nimg
        dct_flatness /= nimg
        dct_parity /= nimg

        append_susp /= nimg
        append_entropy /= nimg

        png_susp /= nimg
        # png_hits stays as total count

        out_rows.append(
            {
                "file": f,
                "true": true_label,
                "pred_label": pred_label,
                "numeric_score": numeric,
                "label_text": label_str,
                "lsb_susp": lsb_susp,
                "lsb_prop_one": lsb_prop_one,
                "lsb_ent_full": lsb_ent_full,
                "lsb_ent_local": lsb_ent_local,
                "dct_susp": dct_susp,
                "dct_flatness": dct_flatness,
                "dct_parity": dct_parity,
                "append_susp": append_susp,
                "append_entropy": append_entropy,
                "png_susp": png_susp,
                "png_hits": png_hits,
            }
        )


def compute_metrics_at_threshold(y_true, y_score, thr):
    """Compute confusion-matrix metrics by thresholding numeric_score >= thr."""
    tp = fp = tn = fn = 0

    for t, s in zip(y_true, y_score):
        p = 1 if s >= thr else 0
        if t == 1 and p == 1:
            tp += 1
        elif t == 1 and p == 0:
            fn += 1
        elif t == 0 and p == 1:
            fp += 1
        elif t == 0 and p == 0:
            tn += 1

    accuracy = (tp + tn) / max(1, (tp + tn + fp + fn))
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "n": tp + tn + fp + fn,
        "threshold_used": thr,
    }


def save_csv(rows, outpath):
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with open(outpath, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def _compute_roc_points(y_true, y_score):
    """Compute ROC points and AUC using a simple threshold sweep."""
    # sort by descending score
    order = sorted(range(len(y_score)), key=lambda i: y_score[i], reverse=True)
    P = sum(1 for t in y_true if t == 1)
    N = sum(1 for t in y_true if t == 0)

    fprs = [0.0]
    tprs = [0.0]

    tp = fp = 0
    last_score = None
    for idx in order:
        s = y_score[idx]
        t = y_true[idx]

        if last_score is None or s != last_score:
            if last_score is not None:
                fprs.append(fp / N if N > 0 else 0.0)
                tprs.append(tp / P if P > 0 else 0.0)
            last_score = s

        if t == 1:
            tp += 1
        else:
            fp += 1

    # final point
    fprs.append(fp / N if N > 0 else 0.0)
    tprs.append(tp / P if P > 0 else 0.0)

    # trapezoidal area
    auc = 0.0
    for i in range(1, len(fprs)):
        auc += (fprs[i] - fprs[i - 1]) * (tprs[i] + tprs[i - 1]) / 2.0

    return fprs, tprs, auc


def plot_confusion(cm, out_path):
    """Plot a 2x2 confusion matrix using matplotlib."""
    import matplotlib.pyplot as plt
    import numpy as np

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    cm_arr = np.array(cm)

    fig, ax = plt.subplots()
    im = ax.imshow(cm_arr)  # default colormap, no explicit colors

    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm_arr[i, j]), ha="center", va="center")

    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["clean", "stego"])
    ax.set_yticklabels(["clean", "stego"])

    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def plot_roc(y_true, y_score, out_path):
    """Plot ROC curve from y_true / y_score."""
    import matplotlib.pyplot as plt

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    fprs, tprs, auc = _compute_roc_points(y_true, y_score)

    fig, ax = plt.subplots()
    ax.plot(fprs, tprs)  # default styling
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title(f"ROC curve (AUC={auc:.3f})")

    fig.tight_layout()
    fig.savefig(out_path)
    plt.close(fig)


def analyze_thresholds(y_true, y_score):
    """Sweep thresholds on numeric_score and report interesting operating points."""
    # unique sorted scores as candidates, plus endpoints
    scores_sorted = sorted(set(float(s) for s in y_score))
    if not scores_sorted:
        return {}

    candidates = [0.0] + scores_sorted + [1.0]

    best_f1 = {"f1": -1.0}
    best_youden = {"youden": -1.0}
    recall_095 = None

    def _confusion_at(thr):
        tp = fp = tn = fn = 0
        for t, s in zip(y_true, y_score):
            p = 1 if s >= thr else 0
            if t == 1 and p == 1:
                tp += 1
            if t == 1 and p == 0:
                fn += 1
            if t == 0 and p == 1:
                fp += 1
            if t == 0 and p == 0:
                tn += 1
        return tp, fp, tn, fn

    for thr in candidates:
        tp, fp, tn, fn = _confusion_at(thr)
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1 = 2 * prec * tpr / (prec + tpr) if (prec + tpr) > 0 else 0.0
        youden = tpr + tnr - 1.0

        if f1 > best_f1["f1"]:
            best_f1 = {
                "thr": thr,
                "TP": tp,
                "FP": fp,
                "TN": tn,
                "FN": fn,
                "precision": prec,
                "recall": tpr,
                "f1": f1,
            }

        if youden > best_youden["youden"]:
            best_youden = {
                "thr": thr,
                "TP": tp,
                "FP": fp,
                "TN": tn,
                "FN": fn,
                "tpr": tpr,
                "tnr": tnr,
                "youden": youden,
            }

        if recall_095 is None and tpr >= 0.95:
            recall_095 = {
                "thr": thr,
                "TP": tp,
                "FP": fp,
                "TN": tn,
                "FN": fn,
                "recall": tpr,
            }

    return {
        "best_f1": best_f1,
        "best_youden": best_youden,
        "recall_0.95": recall_095,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--clean", required=True, help="Folder with clean images")
    p.add_argument("--stego", required=True, help="Folder with stego images")
    p.add_argument("--out", default="reports/eval", help="Output directory")
    args = p.parse_args()

    rows = []
    print("Scanning CLEAN folder:", args.clean)
    scan_folder(args.clean, "clean", rows)
    print("Scanning STEGO folder:", args.stego)
    scan_folder(args.stego, "stego", rows)

    os.makedirs(args.out, exist_ok=True)

    # 1) Save per-file CSV
    csv_path = os.path.join(args.out, "per_file_results.csv")
    save_csv(rows, csv_path)
    print("Saved per-file results:", csv_path)

    # 2) Build y_true / y_score from numeric_score
    y_true = []
    y_score = []
    for r in rows:
        y_true.append(1 if r["true"] == "stego" else 0)
        y_score.append(float(r["numeric_score"]))

    # 3) Threshold analysis on numeric_score
    thr_info = analyze_thresholds(y_true, y_score)
    thr_path = os.path.join(args.out, "threshold_candidates.json")
    with open(thr_path, "w") as f:
        json.dump(thr_info, f, indent=2)
    print("Saved threshold candidates:", thr_path)

    # choose threshold = best F1 by default
    best_thr = thr_info.get("best_f1", {}).get("thr", 0.5)

    # 4) Compute metrics at best_thr
    metrics = compute_metrics_at_threshold(y_true, y_score, best_thr)
    metrics_path = os.path.join(args.out, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print("Saved metrics (at best F1 threshold {:.3f}): {}".format(best_thr, metrics_path))

    # 5) Confusion matrix using numeric_score >= best_thr
    cm = [[0, 0], [0, 0]]  # [[TN, FP],[FN, TP]] but we'll index as [true][pred]
    for t, s in zip(y_true, y_score):
        p_lab = 1 if s >= best_thr else 0
        cm[t][p_lab] += 1

    cm_path = os.path.join(args.out, "confusion_matrix.png")
    plot_confusion(cm, cm_path)
    print("Saved confusion matrix:", cm_path)

    # 6) ROC curve (unchanged)
    roc_path = os.path.join(args.out, "roc.png")
    plot_roc(y_true, y_score, roc_path)
    print("Saved ROC curve:", roc_path)


if __name__ == "__main__":
    main()
