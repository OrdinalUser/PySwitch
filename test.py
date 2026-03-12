from PySwitch.network.service import ServiceImplementation, Service, Arp, Syslog
from PySwitch.network.interface import InterfaceData

def on_service_data(data: bytes):
    print(f"out: {len(data)=} {data=}")

services = Service.Initialize(on_data_send=on_service_data)
arp = services.Get(Arp)

test_data = [
    InterfaceData(
        data=b"H",
        frame=None
    ),
    InterfaceData(
        data=b"Hi",
        frame=None
    ),
]

syslog = services.Get(Syslog)

for data in test_data:
    if not services.Process(data):
        print(f"{data} has not been processed")

syslog.Send("Hi")