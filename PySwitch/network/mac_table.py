from __future__ import annotations # debugger must have for odd reasons
from PySwitch.common import Configuration, Dict, List, NamedTuple
from PySwitch.network.interface import Virtual
from PySwitch.network.types import MAC

import time

import logging
logger = logging.getLogger(__name__)

class MACTable:
    class Entry(NamedTuple):
        mac: MAC
        interface: Virtual.Interface    # references the actual interface
                                        # contains .slot which is used like a port
        timestamp_expiration: float     # future timestamp in which it expires
    
    mapping: Dict[MAC, Entry] # the actual mapping logic for constant time lookup
    configuration: Configuration # global singleton for configuration
    
    def __init__(self):
        self.mapping = dict()
        self.configuration = Configuration.Get()
    
    def Learn(self, source_mac: MAC, interface: Virtual.Interface) -> None:
        """Learns the source mac address from a given interface to be present on given slot"""
        if interface.physical is None: return
        now = time.monotonic()
        self.mapping[source_mac] = MACTable.Entry(source_mac, interface, now + self.configuration.live.core.mac_expiry_s)
    
    def Get(self, dest_mac: MAC) -> int:
        """Returns -1 if flood"""
        if dest_mac in self.mapping:
            now = time.monotonic()
            entry = self.mapping[dest_mac]
            return entry.interface.slot if now < entry.timestamp_expiration else -1
        return -1
    
    def Clean(self, slot: int) -> None:
        """Removes all entries accompanied on slot or those that are expired"""
        if slot != -1:
            # No need to log periodic cleaning
            logger.info(f"Cleaning MAC table for {slot=}")
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
        """Clears the entire table"""
        self.mapping = dict()
