
import argparse
import csv
import json
import shlex
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "experiments"
PCAPS = ROOT / "evidence" / "pcaps" / "experiments"

BLOCKED_IP = "172.28.10.20"

FIREWALL_RULE = [
    "-s", BLOCKED_IP,
    "-p", "tcp",
    "--dport", "5020",
    "-j", "REJECT",
    "--reject-with", "tcp-reset",
]

SCENARIOS = [
    ("E01", "hmi", "read", None, "Benign"),
    ("E02", "hmi", "write", 65, "Benign"),
    ("E03", "test-client", "read", None, "Suspicious"),
    ("E04", "test-client", "write", 40, "Suspicious"),
    ("E05", "hmi", "write", 40, "Suspicious"),
    ("E06", "hmi", "write", 60, "Benign"),
]


def docker(*args, timeout=15):
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def firewall_exists():
    result = docker(
        "exec", "-T", "gateway",
        "iptables", "-C", "INPUT", *FIREWALL_RULE,
    )
    return result.returncode == 0


def set_firewall(enabled):
    exists = firewall_exists()

    if enabled and not exists:
        action = "-I"
    elif not enabled and exists:
        action = "-D"
    else:
        return

    args = ["iptables", action, "INPUT"]

    if action == "-I":
        args.append("1")

    result = docker(
        "exec", "-T", "gateway",
        *args, *FIREWALL_RULE,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)


def client_request(
    container, operation, test_id, trial,
    config, value=None
):
    cmd = [
        "exec", "-T", container,
        "python", "experiment_client.py",
        operation,
        "--address", "0",
        "--test-id", test_id,
        "--trial", str(trial),
        "--configuration", config,
    ]

    if value is not None:
        cmd += ["--value", str(value)]

    result = docker(*cmd)

    if result.returncode != 0:
        raise RuntimeError(
            f"Client process failed: {result.stderr}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid client JSON: {result.stdout}"
        ) from exc


def read_register(config, trial, label):
    result = client_request(
        "hmi", "read", label, trial, config
    )

    if not result["request_success"]:
        raise RuntimeError(
            f"HMI verification failed: {result}"
        )

    return result["response_value"]


def reset_register(config, trial):
    result = client_request(
        "hmi", "write", "RESET", trial,
        config, value=60
    )

    if not result["request_success"]:
        raise RuntimeError(
            f"PLC reset failed: {result}"
        )

    actual = read_register(config, trial, "PRECHECK")

    if actual != 60:
        raise RuntimeError(
            f"Register reset verification failed: {actual}"
        )

    return actual


def run_capture(stem):
    container_path = (
        f"/evidence/pcaps/experiments/{stem}.pcap"
    )

    command = (
        "tcpdump -i any -s 0 -nn "
        f"-w {shlex.quote(container_path)} "
        "'tcp port 5020 and net 172.28.10.0/24' "
        '& pid=$!; sleep 7; kill -INT "$pid"; wait "$pid"'
    )

    return subprocess.Popen(
        [
            "docker", "compose", "exec", "-T",
            "gateway", "sh", "-c", command
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def execute(config, trial, scenario):
    test_id, container, operation, value, ground_truth = scenario
    stem = f"{config}_{test_id}_trial{trial}"

    print(f"Running {stem}", flush=True)

    before = reset_register(config, trial)

    capture = run_capture(stem)

    try:
        time.sleep(1)

        result = client_request(
            container, operation,
            test_id, trial, config, value
        )

        _, capture_errors = capture.communicate(timeout=15)

        if capture.returncode != 0:
            raise RuntimeError(
                f"Packet capture failed: {capture_errors}"
            )

        pcap = PCAPS / f"{stem}.pcap"

        if not pcap.exists() or pcap.stat().st_size <= 24:
            raise RuntimeError(
                f"Missing or empty PCAP: {pcap}"
            )

    finally:
        if capture.poll() is None:
            capture.kill()
            capture.communicate()

    after = read_register(config, trial, "POSTCHECK")

    changed = (before != after)

    expected_after = before

    if operation == "write" and result["request_success"]:
        expected_after = value

    state_verified = (after == expected_after)

    summary = {
        "test_id": test_id,
        "configuration": config,
        "trial": trial,
        "client": container,
        "operation": operation,
        "ground_truth": ground_truth,
        "register_before": before,
        "register_after": after,
        "register_changed": changed,
        "expected_register_after": expected_after,
        "state_verified": state_verified,
        "connection_success": result["connection_success"],
        "request_success": result["request_success"],
        "request_outcome": result["outcome"],
        "elapsed_ms": result["elapsed_ms"],
        "timestamp_utc": result["timestamp_utc"],
        "pcap_file": f"{stem}.pcap",
    }

    (RESULTS / f"{stem}.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )

    (RESULTS / f"{stem}_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )

    if not state_verified:
        raise RuntimeError(
            f"PLC state mismatch during {stem}: {summary}"
        )

    print(
        f"  Outcome: {result['outcome']} | "
        f"Before: {before} | After: {after} | "
        f"Time: {result['elapsed_ms']} ms",
        flush=True,
    )

    return summary


def save_csv(config, records):
    path = RESULTS / f"{config}_summary.csv"

    with path.open("w", newline="") as file:
        writer = csv.DictWriter(
            file, fieldnames=list(records[0].keys())
        )
        writer.writeheader()
        writer.writerows(records)

    print(f"Saved results: {path}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config", choices=["A", "B"], required=True
    )
    parser.add_argument(
        "--trials", type=int, default=3
    )
    args = parser.parse_args()

    if args.trials < 1:
        parser.error("--trials must be at least 1")

    RESULTS.mkdir(parents=True, exist_ok=True)
    PCAPS.mkdir(parents=True, exist_ok=True)

    records = []

    try:
        set_firewall(args.config == "B")

        if firewall_exists() != (args.config == "B"):
            raise RuntimeError(
                "Firewall state does not match configuration"
            )

        # Run each scenario for the selected number of trials.
        for scenario in SCENARIOS:
            for trial in range(1, args.trials + 1):
                records.append(
                    execute(args.config, trial, scenario)
                )

    finally:
        # Restore the protective rule, even after failure.
        set_firewall(True)

        if records:
            save_csv(args.config, records)


if __name__ == "__main__":
    main()
