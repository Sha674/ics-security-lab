
import csv
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "experiments"

SCENARIOS = ["E01", "E02", "E06"]

def load_results(config):
    path = RESULTS / f"{config}_summary.csv"

    with path.open(newline="") as f:
        return list(csv.DictReader(f))

baseline = load_results("A")
firewall = load_results("B")

output = []

for scenario in SCENARIOS:
    measurements = {}

    for config, rows in [
        ("A", baseline),
        ("B", firewall)
    ]:
        selected = [
            r for r in rows
            if r["test_id"] == scenario
        ]

        if len(selected) != 3:
            raise RuntimeError(
                f"Expected 3 trials: {config} {scenario}"
            )

        if not all(
            r["request_success"].lower() == "true"
            for r in selected
        ):
            raise RuntimeError(
                f"Failed legitimate request: {config} {scenario}"
            )

        measurements[config] = [
            float(r["elapsed_ms"])
            for r in selected
        ]

    a = measurements["A"]
    b = measurements["B"]

    baseline_median = statistics.median(a)
    firewall_median = statistics.median(b)

    difference = firewall_median - baseline_median

    change_percent = (
        difference / baseline_median * 100
        if baseline_median > 0 else None
    )

    output.append({
        "Scenario": scenario,
        "Baseline_Median_ms": round(baseline_median, 3),
        "Firewall_Median_ms": round(firewall_median, 3),
        "Difference_ms": round(difference, 3),
        "Change_Percent": (
            round(change_percent, 2)
            if change_percent is not None else ""
        ),
        "Baseline_Min_ms": round(min(a), 3),
        "Baseline_Max_ms": round(max(a), 3),
        "Firewall_Min_ms": round(min(b), 3),
        "Firewall_Max_ms": round(max(b), 3),
    })

path = ROOT / "results" / "performance_comparison.csv"

with path.open("w", newline="") as f:
    writer = csv.DictWriter(
        f, fieldnames=output[0].keys()
    )
    writer.writeheader()
    writer.writerows(output)

for result in output:
    print(f"\nScenario: {result['Scenario']}")
    print(
        f"Baseline median: "
        f"{result['Baseline_Median_ms']} ms"
    )
    print(
        f"Firewall median: "
        f"{result['Firewall_Median_ms']} ms"
    )
    print(
        f"Difference: {result['Difference_ms']} ms"
    )
    print(
        f"Change: {result['Change_Percent']}%"
    )

print(f"\nSaved: {path}")
