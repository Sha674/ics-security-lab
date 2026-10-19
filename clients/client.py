
import argparse
import time
from datetime import datetime, timezone
from pymodbus.client import ModbusTcpClient

parser = argparse.ArgumentParser()

parser.add_argument(
    "operation", choices=["read", "write"]
)
parser.add_argument("--address", type=int, default=0)
parser.add_argument("--value", type=int, default=60)
parser.add_argument("--host", default="gateway")
parser.add_argument("--port", type=int, default=5020)

args = parser.parse_args()

client = ModbusTcpClient(
    host=args.host,
    port=args.port,
    timeout=3
)

start = time.perf_counter()
connected = client.connect()

if not connected:
    print("Connection failed")
    raise SystemExit(1)

try:
    if args.operation == "read":
        result = client.read_holding_registers(
            address=args.address,
            count=1,
            device_id=1
        )
    else:
        result = client.write_register(
            address=args.address,
            value=args.value,
            device_id=1
        )

    elapsed = (time.perf_counter() - start) * 1000

    if result.isError():
        print(f"Modbus error: {result}")
    else:
        print("Timestamp:", datetime.now(timezone.utc).isoformat())
        print("Operation:", args.operation)
        print("Register:", args.address)
        print("Result:", result)
        print("Elapsed (ms):", round(elapsed, 3))

finally:
    client.close()
