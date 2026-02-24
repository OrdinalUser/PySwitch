from PySwitch.common import Optional, List
from PySwitch.network.interface import Physical, MediaType

from scapy.all import conf
import subprocess, json

def _get_nic_types() -> dict[str, str]:
    """Returns GUID -> PhysicalMediaType mapping. One-shot at startup."""
    result = subprocess.run(
        ["powershell", "-Command",
         "Get-NetAdapter | Select-Object InterfaceGuid, PhysicalMediaType | ConvertTo-Json"],
        capture_output=True, text=True, check=True
    )
    adapters = json.loads(result.stdout)
    if isinstance(adapters, dict):  # single adapter edge case
        adapters = [adapters]
    return {a["InterfaceGuid"]: a["PhysicalMediaType"] for a in adapters}


_pyswitch_common_physical_interfaces_cache: Optional[List[Physical.Interface]] = None
def GetAllAvailableNICs(force_reload: bool = False) -> List[Physical.Interface]:
    global _pyswitch_common_physical_interfaces_cache
    if _pyswitch_common_physical_interfaces_cache is None or force_reload:
        conf.ifaces.reload()
        nic_types = _get_nic_types()
        _pyswitch_common_physical_interfaces_cache = []
        for iface in conf.ifaces.values():
            guid = getattr(iface, "guid", "")
            media_type = MediaType.from_str(nic_types.get(guid.upper(), "Unspecified"))
            if media_type == MediaType.Unknown: continue
            _pyswitch_common_physical_interfaces_cache.append(Physical.Interface(
                name=getattr(iface, "name", ""),
                description=getattr(iface, "description", getattr(iface, "name", "")),
                mac=getattr(iface, "mac", ""),
                ip=getattr(iface, "ip", ""),
                guid=getattr(iface, "guid", ""),
                ips=list(getattr(iface, "ips", {}).keys()),
                media_type=media_type),
            )
    return _pyswitch_common_physical_interfaces_cache


# def GetAllAvailableNICs() -> List[Physical.Interface]:
#     conf.ifaces.reload()
#     interfaces: List[Physical.Interface] = []
#     for iface in conf.ifaces.values():
#         interfaces.append(Physical.Interface(
#             name=getattr(iface, "name", ""),
#             description=getattr(iface, "description", getattr(iface, "name", "")),
#             mac=getattr(iface, "mac", ""),
#             ip=getattr(iface, "ip", ""),
#             guid=getattr(iface, "guid", ""),
#             ips=list(getattr(iface, "ips", {}).keys()),
#         ))
#     return interfaces
