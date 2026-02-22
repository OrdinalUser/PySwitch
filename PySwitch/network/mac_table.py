from __future__ import annotations
from PySwitch.common import Configuration, Dict, List, NamedTuple
from PySwitch.network.interface import Virtual
from PySwitch.network.types import MAC

import time

class MACTable:
    class Entry(NamedTuple):
        mac: MAC
        interface: Virtual.Interface    # references the actual interface
                                        # contains .slot which is used like a port
        timestamp_expiration: float     # future timestamp in which it expires
    
    mapping: Dict[int, Entry] # manual hash to avoid keys() being owned by the Dict
    configuration: Configuration
    
    def __init__(self):
        self.mapping = dict()
        self.configuration = Configuration.Get()
    
    def Learn(self, source_mac: MAC, interface: Virtual.Interface) -> None:
        if interface.physical is None: return
        now = time.monotonic()
        self.mapping[hash(source_mac)] = MACTable.Entry(source_mac, interface, now + self.configuration.live.core.mac_expiry_s)
    
    def Get(self, dest_mac: MAC) -> int:
        """Returns -1 if flood"""
        key = hash(dest_mac)
        if key in self.mapping:
            now = time.monotonic()
            entry = self.mapping[key]
            return entry.interface.slot if now < entry.timestamp_expiration else -1
        return -1
    
    def Clean(self, slot: int) -> None:
        now = time.monotonic()
        replacement_map = dict()
        for mac_source, (mac, interface, timestamp_expiry) in self.mapping.items():
            if interface.slot == slot: continue
            if interface.physical is None: continue
            if now < timestamp_expiry:
                replacement_map[mac_source] = MACTable.Entry(mac, interface, timestamp_expiry)
        self.mapping = replacement_map
    
    def ToList(self) -> List[MACTable.Entry]:
        """Used for GUIs to show status"""
        return list(self.mapping.values())
    
    def Clear(self) -> None:
        self.mapping = dict()
