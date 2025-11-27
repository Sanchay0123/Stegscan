#!/usr/bin/env python3
import csv, json, argparse
from collections import defaultdict
from math import inf

def load_rows(csvpath):
    rows=[]
    with open(csvpath,newline='',encoding='utf8') as fh:
        r=csv.DictReader(fh)
        for row in r:
            try:
                score=float(row.get("score",0))
            except:
                score=0.0
            true = 1 if row.get("true","").lower()=="stego" else 0
            rows.append((true, score, row))
    return rows

def evaluate_at_thr(rows, thr):
    TP = FP = TN = FN = 0
    for t,s,_ in rows:
        pred = 1 if s >= thr else 0
        if t==1 and pred==1: TP+=1
        if t==1 and pred==0: FN+=1
        if t==0 and pred==1: FP+=1
        if t==0 and pred==0: TN+=1
    precision = TP/(TP+FP) if (TP+FP)>0 else 0.0
    recall = TP/(TP+FN) if (TP+FN)>0 else 0.0
    f1 = 2*precision*recall/(precision+recall) if (precision+recall)>0 else 0.0
    return {"thr":thr,"TP":TP,"FP":FP,"TN":TN,"FN":FN,"precision":precision,"recall":recall,"f1":f1}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--csv", required=True)
    p.add_argument("--out", default="reports/eval_new/threshold_candidates.json")
    args=p.parse_args()
    rows=load_rows(args.csv)
    scores=sorted(set(s for _,s,_ in rows))
    candidates=[]
    for thr in scores:
        candidates.append(evaluate_at_thr(rows, thr))
    # find best by different metrics
    best_j = max(candidates, key=lambda c: (c["recall"] - (c["FP"]/(c["FP"]+c["TN"]) if (c["FP"]+c["TN"])>0 else 0)))
    best_f1 = max(candidates, key=lambda c: c["f1"])
    # thresholds for desired recall/precision
    def pick_for_recall(target):
        # smallest threshold achieving recall >= target
        for c in sorted(candidates, key=lambda x: x["thr"]):
            if c["recall"] >= target: return c
        return None
    def pick_for_precision(target):
        # largest threshold achieving precision >= target
        for c in sorted(candidates, key=lambda x: -x["thr"]):
            if c["precision"] >= target: return c
        return None

    out = {
        "best_youden": best_j,
        "best_f1": best_f1,
        "recall_0.99": pick_for_recall(0.99),
        "recall_0.98": pick_for_recall(0.98),
        "recall_0.95": pick_for_recall(0.95),
        "precision_0.99": pick_for_precision(0.99),
        "precision_0.95": pick_for_precision(0.95),
        "candidates_count": len(candidates)
    }

    import os
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out,"w") as fh:
        json.dump(out, fh, indent=2)
    print("Wrote:", args.out)
    print(json.dumps(out, indent=2))

if __name__=="__main__":
    main()
