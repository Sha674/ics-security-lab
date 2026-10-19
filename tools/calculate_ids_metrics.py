
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "results/ids_analysis/ids_results.csv"

with INPUT.open() as f:
    rows = list(csv.DictReader(f))

# Measure IDS classification on baseline traffic,
# where the firewall did not block scenario execution.
baseline = [r for r in rows if r["configuration"] == "A"]

if len(baseline) != 18:
    raise RuntimeError(
        f"Expected 18 baseline trials, found {len(baseline)}"
    )

if not all(
    r["ids_evaluable"] == "True" for r in baseline
):
    raise RuntimeError(
        "Some baseline requests were unsuccessful. "
        "Investigate before calculating metrics."
    )

def evaluate(data, field):
    tp = fp = tn = fn = 0

    for row in data:
        actual = row["ground_truth"] == "Suspicious"
        predicted = row[field] == "True"

        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and predicted:
            fp += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "Precision": round(precision, 4),
        "Recall": round(recall, 4),
        "FPR": round(fpr, 4),
        "F1": round(f1, 4),
    }

rules = {
    "General write rule": "rule_1000001_alert",
    "Process-aware rule": "rule_1000002_alert",
    "Any custom alert": "any_alert",
}

output = []

for name, field in rules.items():
    metrics = evaluate(baseline, field)
    metrics["Rule"] = name
    output.append(metrics)

    print(f"\n{name}")
    for key, value in metrics.items():
        if key != "Rule":
            print(f"  {key}: {value}")

path = ROOT / "results/ids_analysis/detection_metrics.csv"

with path.open("w", newline="") as f:
    fields = [
        "Rule", "TP", "FP", "TN", "FN",
        "Precision", "Recall", "FPR", "F1"
    ]

    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(output)

print(f"\nSaved: {path}")
