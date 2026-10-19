
from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.server import StartTcpServer

# Simulated heating-system process variables
initial_values = [60, 55, 1, 85] + [0] * 96

device = ModbusDeviceContext(
    hr=ModbusSequentialDataBlock(0, initial_values)
)

context = ModbusServerContext(
    devices=device,
    single=True
)

print("Starting simulated ICS PLC on port 5020", flush=True)

StartTcpServer(
    context=context,
    address=("0.0.0.0", 5020),
)
