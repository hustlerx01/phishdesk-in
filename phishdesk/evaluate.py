"""Score the analyser against data/labels.csv. Positive class = phishing.
'suspicious' counts as positive (it goes to an analyst queue, i.e. is not delivered silently)."""
import argparse, csv, json, time
from pathlib import Path
from .analyze import analyze_file


def evaluate(data_dir="data/samples", labels="data/labels.csv", strict=False):
    t0 = time.time()
    rows = list(csv.DictReader(open(labels)))
    tp = fp = tn = fn = 0
    errors, by_cat = [], {}
    for r in rows:
        res = analyze_file(Path(data_dir) / r["file"])
        pred = res["verdict"] == "phishing" if strict else res["verdict"] != "clean"
        gold = r["label"] == "phishing"
        tp += pred and gold; fp += pred and not gold; fn += (not pred) and gold; tn += (not pred) and (not gold)
        c = by_cat.setdefault(r["category"], [0, 0]); c[0] += pred == gold; c[1] += 1
        if pred != gold:
            errors.append({"file": r["file"], "gold": r["label"], "pred": res["verdict"], "score": res["score"], "note": r["note"]})
    P = tp / (tp + fp) if tp + fp else 0.0
    R = tp / (tp + fn) if tp + fn else 0.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    return {"n": len(rows), "mode": "strict(phishing only)" if strict else "phishing+suspicious",
            "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": round(P, 3), "recall": round(R, 3),
            "f1": round(F, 3), "accuracy": round((tp + tn) / len(rows), 3), "fpr": round(fp / (fp + tn), 3) if fp + tn else 0,
            "accuracy_by_category": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_cat.items())},
            "errors": errors, "runtime_s": round(time.time() - t0, 3)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--strict", action="store_true"); ap.add_argument("-o", default="")
    a = ap.parse_args()
    m = evaluate(strict=a.strict)
    s = json.dumps(m, indent=2); print(s)
    if a.o:
        Path(a.o).write_text(s)
