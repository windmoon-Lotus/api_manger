import argparse
import json
from collections import Counter


LABELS = ("potential_vuln", "need_review", "no_vuln")


def _normalize_label(v):
    text = str(v or "").strip().lower()
    if text in LABELS:
        return text
    if text in {"vuln", "high_risk"}:
        return "potential_vuln"
    if text in {"safe"}:
        return "no_vuln"
    return "need_review"


def _load_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _confusion(rows, pred_key, gold_key):
    cm = Counter()
    for row in rows:
        pred = _normalize_label(row.get(pred_key))
        gold = _normalize_label(row.get(gold_key))
        cm[(gold, pred)] += 1
    return cm


def _binary_prf(rows, pred_key, gold_key, positive="potential_vuln"):
    tp = fp = fn = tn = 0
    for row in rows:
        pred = _normalize_label(row.get(pred_key)) == positive
        gold = _normalize_label(row.get(gold_key)) == positive
        if pred and gold:
            tp += 1
        elif pred and not gold:
            fp += 1
        elif not pred and gold:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate rule/AI/fusion privilege judgements from JSONL.")
    parser.add_argument("--input", required=True, help="JSONL file path.")
    parser.add_argument("--gold-key", default="expected", help="Field name for ground truth label.")
    parser.add_argument("--rule-key", default="result", help="Field name for rule-only result.")
    parser.add_argument("--ai-key", default="ai_result", help="Field name for ai-only result.")
    parser.add_argument("--final-key", default="final_result", help="Field name for fusion result.")
    args = parser.parse_args()

    rows = _load_jsonl(args.input)
    if not rows:
        raise SystemExit("No rows found in input.")

    report = {
        "total": len(rows),
        "rule_binary": _binary_prf(rows, args.rule_key, args.gold_key),
        "ai_binary": _binary_prf(rows, args.ai_key, args.gold_key),
        "fusion_binary": _binary_prf(rows, args.final_key, args.gold_key),
        "rule_confusion": {f"{k[0]}->{k[1]}": v for k, v in _confusion(rows, args.rule_key, args.gold_key).items()},
        "ai_confusion": {f"{k[0]}->{k[1]}": v for k, v in _confusion(rows, args.ai_key, args.gold_key).items()},
        "fusion_confusion": {f"{k[0]}->{k[1]}": v for k, v in _confusion(rows, args.final_key, args.gold_key).items()},
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

