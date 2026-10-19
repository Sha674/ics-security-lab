
import csv
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "experiments"
PCAPS = ROOT / "evidence" / "pcaps" / "experiments"
OUTPUT = ROOT / "results" / "ids_analysis"
RULES = ROOT / "ids" / "rules" / "modbus.rules"
CONFIG = Path("/etc/suricata/suricata.yaml")

RULE_IDS = {1000001, 1000002}

rows = []

def run_suricata(pcap, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)

    command = [
        "sudo", "suricata",
        "-c", str(CONFIG),
        "-S", str(RULES),
        "-r", str(pcap),
        "-l", str(output_dir),
        "-k", "none",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Suricata failed for {pcap.name}:\n"
            f"{result.stderr}\n{result.stdout}"
        )

def extract_alerts(eve_path):
    alerts = []

    if not eve_path.exists():
        raise RuntimeError(f"Missing EVE log: {eve_path}")

    with eve_path.open() as file:
        for line in file:
            event = json.loads(line)

            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert", {})
            sid = alert.get("signature_id")

            if sid in RULE_IDS:
                alerts.append({
                    "sid": sid,
                    "source": event.get("src_ip"),
                    "timestamp": event.get("timestamp"),
                })

    return alerts

def analyse_trial(summary_path):
    summary = json.loads(summary_path.read_text())

    config = summary["configuration"]
    test_id = summary["test_id"]
    trial = summary["trial"]

    stem = f"{config}_{test_id}_trial{trial}"
    pcap = PCAPS / f"{stem}.pcap"
    output_dir = OUTPUT / stem

    if not pcap.exists() or pcap.stat().st_size <= 24:
        raise RuntimeError(f"Invalid PCAP: {pcap}")

    run_suricata(pcap, output_dir)

    alerts = extract_alerts(output_dir / "eve.json")

    count_1 = sum(
        a["sid"] == 1000001 for a in alerts
    )
    count_2 = sum(
        a["sid"] == 1000002 for a in alerts
    )

    # A blocked connection provides no Modbus transaction
    # for the application-layer detector to inspect.
    blocked = (
        config == "B"
        and test_id in ("E03", "E04")
        and not summary["connection_success"]
    )

    row = {
        "configuration": config,
        "test_id": test_id,
        "trial": trial,
        "ground_truth": summary["ground_truth"],
        "client": summary["client"],
        "operation": summary["operation"],
        "request_success": summary["request_success"],
        "register_before": summary["register_before"],
        "register_after": summary["register_after"],
        "state_verified": summary["state_verified"],
        "elapsed_ms": summary["elapsed_ms"],
        "blocked_by_firewall": blocked,
        "rule_1000001_count": count_1,
        "rule_1000002_count": count_2,
        "rule_1000001_alert": count_1 > 0,
        "rule_1000002_alert": count_2 > 0,
        "any_alert": bool(alerts),
        "ids_evaluable": (
            summary["connection_success"]
            and summary["request_success"]
        ),
        "pcap_file": pcap.name,
    }

    print(
        f"{stem}: "
        f"rule1={count_1}, "
        f"rule2={count_2}, "
        f"blocked={blocked}",
        flush=True,
    )

    return row

def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)

    summaries = sorted(
        RESULTS.glob("*_summary.json")
    )

    expected = {
        f"{config}_{test}_trial{trial}_summary.json"
        for config in ("A", "B")
        for test in ("E01", "E02", "E03",
                     "E04", "E05", "E06")
        for trial in range(1, 4)
    }

    actual = {p.name for p in summaries}

    if actual != expected:
        raise RuntimeError(
            f"Missing: {sorted(expected - actual)}\n"
            f"Unexpected: {sorted(actual - expected)}"
        )

    if not RULES.exists():
        raise RuntimeError(f"Missing rules: {RULES}")

    try:
        for path in summaries:
            rows.append(analyse_trial(path))

    finally:
        if rows:
            output_file = OUTPUT / "ids_results.csv"

            with output_file.open("w", newline="") as file:
                writer = csv.DictWriter(
                    file, fieldnames=rows[0].keys()
                )
                writer.writeheader()
                writer.writerows(rows)

            print(f"\nSaved {len(rows)} rows: {output_file}")

if __name__ == "__main__":
    main()
