#!/usr/bin/env python3
"""
Compute optimal decision threshold from per_file_results.csv using Youden's J.
Writes reports/eval/optimal_threshold.json and prints summary.

Usage:
    python find_threshold.py --csv reports/eval/per_file_results.csv --out reports/eval/optimal_threshold.json
"""

import argparse, csv, json, math
from collections import defaultdict

def load_scores(csvpath):
    rows = []
    with open(csvpath, newline='', encoding='utf8') as fh:
        r = csv.DictReader(fh)
        for row in r:
            # ensure numeric score
            s = row.get("score", "")
            try:
                score = float(s)
            except:
                score = 0.0
            true = 1 if row.get("true","").lower()=="stego" else 0
            rows.append((true, score))
    return rows

def compute_roc_points(rows):
    # rows: list of (true,label)
    scores = sorted(set(s for _,s in rows))
    pts = []
    P = sum(1 for t,_ in rows if t==1)
    N = len(rows) - P
    for thr in scores:
        TP = sum(1 for t,s in rows if t==1 and s>=thr)
        FP = sum(1 for t,s in rows if t==0 and s>=thr)
        TPR = TP / P if P>0 else 0.0
        FPR = FP / N if N>0 else 0.0
        pts.append({"thr": thr, "tpr": TPR, "fpr": FPR, "j": TPR - FPR})
    return pts

def find_best_threshold(rows):
    pts = compute_roc_points(rows)
    if not pts:
        return None, []
    best = max(pts, key=lambda x: x["j"])
    # also compute recommended thresholds around best one (for safety)
    sorted_thr = sorted(p["thr"] for p in pts)
    return best, pts

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", required=True)
    p.add_argument("--out", default="reports/eval/optimal_threshold.json")
    args = p.parse_args()

    rows = load_scores(args.csv)
    if not rows:
        print("No rows loaded from CSV.")
        return

    best, pts = find_best_threshold(rows)
    if not best:
        print("Could not compute threshold.")
        return

    print("Best threshold (Youden's J):")
    print(f"  thr = {best['thr']:.4f}, TPR = {best['tpr']:.4f}, FPR = {best['fpr']:.4f}, J = {best['j']:.4f}")

    # also compute simple operating point: prefer threshold that gets high recall but reduces FPR
    # we'll write the chosen thr and a small summary
    out = {
        "threshold": round(best["thr"], 4),
        "tpr": round(best["tpr"], 4),
        "fpr": round(best["fpr"], 4),
        "youden_j": round(best["j"], 4)
    }

    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=2)

    print("Written optimal threshold to:", args.out)

if __name__ == "__main__":
    main()
