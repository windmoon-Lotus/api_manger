import argparse
import json
from collections import Counter


def _load_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _safe_div(a, b):
    return (float(a) / float(b)) if b else 0.0


def _normalize_class(v):
    val = str(v or "").strip()
    if not val:
        return "UNKNOWN"
    return val


def _normalize_relation_label(v):
    val = str(v or "").strip().lower()
    if val in {"weak", "related", "true", "1", "yes"}:
        return "weak"
    if val in {"not_equal", "no", "false", "0", "none", "unrelated"}:
        return "none"
    return "none"


def _to_positive(v):
    return _normalize_relation_label(v) == "weak"


def eval_classification(rows, gold_key="action_expected", pred_key="action_pred", topn=10):
    total = 0
    correct = 0
    labels = set()
    cm = Counter()
    miss = Counter()
    for row in rows:
        gold = _normalize_class(row.get(gold_key))
        pred = _normalize_class(row.get(pred_key))
        total += 1
        labels.add(gold)
        labels.add(pred)
        cm[(gold, pred)] += 1
        if gold == pred:
            correct += 1
        else:
            miss[(gold, pred)] += 1

    per_label = {}
    for label in sorted(labels):
        tp = cm[(label, label)]
        fp = sum(v for (g, p), v in cm.items() if p == label and g != label)
        fn = sum(v for (g, p), v in cm.items() if g == label and p != label)
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        f1 = _safe_div(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
        per_label[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(v for (g, _), v in cm.items() if g == label),
        }

    top_errors = [
        {"gold": g, "pred": p, "count": c}
        for (g, p), c in miss.most_common(max(1, int(topn or 10)))
    ]

    return {
        "total": total,
        "correct": correct,
        "accuracy": round(_safe_div(correct, total), 4),
        "per_label": per_label,
        "top_errors": top_errors,
    }


def _relation_pred(row, pred_key, score_key, threshold):
    pred = row.get(pred_key)
    if pred is not None and str(pred).strip() != "":
        return _to_positive(pred)
    score = row.get(score_key)
    try:
        score_val = float(score)
    except Exception:
        score_val = 0.0
    return score_val >= threshold


def eval_relation(
        rows,
        gold_key="relation_expected",
        pred_key="relation_pred",
        score_key="relation_score_pred",
        threshold=60.0,
):
    tp = fp = fn = tn = 0
    for row in rows:
        gold = _to_positive(row.get(gold_key))
        pred = _relation_pred(row, pred_key=pred_key, score_key=score_key, threshold=threshold)
        if pred and gold:
            tp += 1
        elif pred and not gold:
            fp += 1
        elif not pred and gold:
            fn += 1
        else:
            tn += 1
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "threshold": threshold,
    }


def build_markdown_report(class_report, relation_report):
    lines = []
    lines.append("# 分类与关联评估报告")
    lines.append("")
    lines.append("## 分类指标")
    lines.append("- total: {}".format(class_report["total"]))
    lines.append("- accuracy: {}".format(class_report["accuracy"]))
    lines.append("")
    lines.append("### 分类误差 Top")
    for item in class_report.get("top_errors", []):
        lines.append(
            "- {} -> {} : {}".format(item["gold"], item["pred"], item["count"])
        )
    lines.append("")
    lines.append("## 关联指标（weak 作为正样本）")
    lines.append("- precision: {}".format(relation_report["precision"]))
    lines.append("- recall: {}".format(relation_report["recall"]))
    lines.append("- f1: {}".format(relation_report["f1"]))
    lines.append("- threshold: {}".format(relation_report["threshold"]))
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Evaluate API classification and relation inference from JSONL.")
    parser.add_argument("--input", required=True, help="Input JSONL.")
    parser.add_argument("--class-gold-key", default="action_expected")
    parser.add_argument("--class-pred-key", default="action_pred")
    parser.add_argument("--class-topn", type=int, default=10)
    parser.add_argument("--relation-gold-key", default="relation_expected")
    parser.add_argument("--relation-pred-key", default="relation_pred")
    parser.add_argument("--relation-score-key", default="relation_score_pred")
    parser.add_argument("--relation-threshold", type=float, default=60.0)
    parser.add_argument("--report-md", help="Optional markdown report output path.")
    args = parser.parse_args()

    rows = _load_jsonl(args.input)
    if not rows:
        raise SystemExit("No rows loaded from input.")

    class_report = eval_classification(
        rows,
        gold_key=args.class_gold_key,
        pred_key=args.class_pred_key,
        topn=args.class_topn,
    )
    relation_report = eval_relation(
        rows,
        gold_key=args.relation_gold_key,
        pred_key=args.relation_pred_key,
        score_key=args.relation_score_key,
        threshold=args.relation_threshold,
    )

    output = {
        "classification": class_report,
        "relation": relation_report,
        "total_rows": len(rows),
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))

    if args.report_md:
        markdown = build_markdown_report(class_report, relation_report)
        with open(args.report_md, "w", encoding="utf-8") as f:
            f.write(markdown)


if __name__ == "__main__":
    main()

