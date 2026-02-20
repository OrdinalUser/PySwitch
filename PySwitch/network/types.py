from dataclasses import dataclass, field
from PySwitch.common import List, Dict, StrEnum, deque, Optional
import time

# this will probably need to work differently later
class Protocols(StrEnum):
    UDP = "UDP"
    TCP = "TCP"

class Physical:
    @dataclass
    class Interface:
        name: str           # Scapy iface identifier (on Windows: GUID path)
        description: str    # Human-readable NIC name
        mac: str
        ip: str
        guid: str = ""
        ips: List[str] = field(default_factory=list)

        def __str__(self) -> str:
            return f"{self.description} [{self.mac}] {self.ip}"

@dataclass
class Statistics:
    @dataclass(frozen=True)
    class Entry:
        size: int
        timestamp: float
    
    processed_max_size: int
    processed: deque[Statistics.Entry] = field(default_factory=lambda: deque()) # Rolling buffer of max size used for aggregation metrics like 'total throughput Bytes/s'
    counts: Dict[Protocols, int] = field(default_factory=lambda: dict()) # total count of all stages of a packet up to L7 (of those that I can support of course)
    
    def AggregateThroughput(self, time_s: float) -> int:
        # Returns the bytes processed in the last timeframe
        now = time.time()
        return sum([entry.size for entry in self.processed if (now - entry.timestamp) <= time_s])
    
    def AddFrame(self, size: int):
        self.processed.append(Statistics.Entry(size, time.time()))
        if len(self.processed) > self.processed_max_size:
            self.processed.popleft()

@dataclass
class InterfaceMetrics:
    ingress: Statistics
    egress: Statistics

class Virtual:
    @dataclass
    class Interface:
        physical: Optional[Physical.Interface]
        metrics: InterfaceMetrics
        
        def __str__(self) -> str:
            return str(self.physical)