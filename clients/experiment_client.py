
import argparse
import json
import time
from datetime import datetime, timezone

from pymodbus.client import ModbusTcpClient

parser = argparse.ArgumentParser()
parser.add_argument("operation", choices=["read", "write"])
parser.add_argument("--address", type=int, default=0)
parser.add_argument("--value", type=int, default=60)
parser.add_argument("--host", default="gateway")
parser.add_argument("--port", type=int, default=5020)
parser.add_argument("--test-id", required=True)
parser.add_argument("--trial", type=int, required=True)
parser.add_argument("--configuration", required=True)

args = parser.parse_args()

record = {
    "test_id": args.test_id,
    "configuration": args.configuration,
    "trial": args.trial,
    "operation": args.operation,
    "register": args.address,
    "requested_value": (
        args.value if args.operation == "write" else None
    ),
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "connection_success": False,
    "request_success": False,
    "outcome": "Not executed",
    "elapsed_ms": None,
    "response_value": None,
    "error": None,
}

client = ModbusTcpClient(
    host=args.host,
    port=args.port,
    timeout=3,
    retries=0,
)

start = time.perf_counter()

try:
    if not client.connect():
        record["outcome"] = "Connection Failed"

    else:
        record["connection_success"] = True

        if args.operation == "read":
            result = client.read_holding_registers(
                address=args.address,
                count=1,
                device_id=1,
            )
        else:
            result = client.write_register(
                address=args.address,
                value=args.value,
                device_id=1,
            )

        if result.isError():
            record["outcome"] = "Modbus Error"
            record["error"] = str(result)

        else:
            record["request_success"] = True
            record["outcome"] = "Success"

            if args.operation == "read":
                record["response_value"] = result.registers[0]
            else:
                record["response_value"] = args.value

except Exception as exc:
    record["outcome"] = "Exception"
    record["error"] = str(exc)

finally:
    record["elapsed_ms"] = round(
        (time.perf_counter() - start) * 1000, 3
    )
    client.close()

print(json.dumps(record, indent=2))
