from .types import Physical
from typing import List

from scapy.all import conf

def GetAllAvailableNICs() -> List[Physical.Interface]:
    conf.ifaces.reload()
    interfaces: List[Physical.Interface] = []
    for iface in conf.ifaces.values():
        interfaces.append(Physical.Interface(
            name=getattr(iface, "name", ""),
            description=getattr(iface, "description", getattr(iface, "name", "")),
            mac=getattr(iface, "mac", ""),
            ip=getattr(iface, "ip", ""),
            guid=getattr(iface, "guid", ""),
            ips=list(getattr(iface, "ips", {}).keys()),
        ))
    return interfaces
