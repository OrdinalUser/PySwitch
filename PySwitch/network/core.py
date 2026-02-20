from PySwitch.common import Optional, ClassVar, Configuration, List
from PySwitch.network.types import Physical, Virtual, InterfaceMetrics, Statistics
from PySwitch.network.common import GetAllAvailableNICs

# Manages slots of virtual network interfaces that the Core works with - TODO
class Interfaces:
    interfaces: List[Optional[Virtual.Interface]]

    def __init__(self, slots: int = 2, processed_size: int = 1000):
        self.interfaces = [Virtual.Interface(None, InterfaceMetrics(Statistics(processed_size), Statistics(processed_size))) for _ in range(slots)]

    def SlotInUse(self, slot: int):
        if slot >= len(self.interfaces) or slot < 0:
            raise ValueError(f"Invalid slot argument, provided {slot}, expected in range 0-{len(self.interfaces)-1}")
        return self.interfaces[slot] is None

    def ClearSlot(self, slot: int):
        if slot >= len(self.interfaces) or slot < 0:
            raise ValueError(f"Invalid slot argument, provided {slot}, expected in range 0-{len(self.interfaces)-1}")
        if self.interfaces[slot] is None:
            raise ValueError(f"Slot {slot} is already empty")
        self.interfaces[slot] = None

    def AssignSlot(self, slot: int, interface: Virtual.Interface):
        if slot >= len(self.interfaces) or slot < 0:
            raise ValueError(f"Invalid slot argument, provided {slot}, expected in range 0-{len(self.interfaces)-1}")
        if self.interfaces[slot] is not None:
            raise ValueError(f"Slot {slot} is in use")
        self.interfaces[slot] = interface

    def AvailableNICs(self, exclude_slot: int | None = None) -> List[Physical.Interface]:
        """Returns NICs not already assigned to another slot."""
        assigned = {
            self.interfaces[i].physical.name
            for i in range(len(self.interfaces))
            if i != exclude_slot and self.interfaces[i].physical is not None
        }
        return [nic for nic in GetAllAvailableNICs() if nic.name not in assigned]

class Core:
    _instance: ClassVar[Optional[Core]]
    configuration: Configuration
    interfaces: Interfaces

    @staticmethod
    def Get() -> Core:
        if not hasattr(Core, '_instance'):
            Core._instance = Core.Init()
        return getattr(Core, '_instance')

    @staticmethod
    def Init() -> Core:
        instance = Core()
        instance.configuration = Configuration.Get()
        instance.interfaces = Interfaces(instance.configuration.static.interface_count)
        return instance