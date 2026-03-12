from PySwitch.common import List, Dict, Protocol, Callable, Optional, Cast, ClassVar, TypeVar, Type
from PySwitch.network.interface import InterfaceData
from PySwitch.network.types import IPv4, MAC

class ServiceImplementation(Protocol):    
    """Purely for programmer reference"""
    _on_data_send: Callable[[bytes], None] # Handles the underlying callback
    _event_loop: Optional[asyncio.AbstractEventLoop] = None
    
    def FrameFilter(self, if_data: InterfaceData) -> bool:
        """Filters whether the frame is destined for the service"""
        ...
    
    def OnFrameReceived(self, if_data: InterfaceData) -> bool:
        """Processes the actual frame data, returns true if has been processed, false if not"""
        ...

T = TypeVar('T')
import asyncio

class Service:
    __services: ClassVar[Dict[type, ServiceImplementation]]  = {}
    __sequence_input: List[ServiceImplementation] = []
    _on_data_send: Optional[Callable[[bytes], None]] = None
    _event_loop: Optional[asyncio.AbstractEventLoop] = None

    @staticmethod
    def Initialize(*, on_data_send: Callable[[bytes], None], event_loop: Optional[asyncio.AbstractEventLoop] = None) -> 'Service':
        ins = Service()
        ins._on_data_send = on_data_send
        ins._event_loop = event_loop
        for service in ins.__services.values():
            service._on_data_send = on_data_send
            service._event_loop = event_loop
        return ins
    
    def __init_subclass__(cls) -> None:
        service_obj = cls.__call__()
        # Register service
        Service.__services[cls.__mro__[0]] = service_obj # type: ignore
        # Check if service accepts input at all
        if hasattr(cls, "OnFrameReceived") and callable(getattr(cls, "OnFrameReceived")) and hasattr(cls, "FrameFilter") and callable(getattr(cls, "FrameFilter")):
            Service.__sequence_input.append(service_obj) # type: ignore
        # Ensure event loop attribute exists on subclass
        if not hasattr(service_obj, '_event_loop'):
            service_obj._event_loop = None
    
    def SendBytes(self, data) -> None:
        """Inherited by the services; used to queue data to be sent outside"""
        if self._on_data_send:
            self._on_data_send(data)
    
    def Get(self, cls: Type[T]) -> T:
        if cls.__mro__[0] not in self.__services:
            raise KeyError(f"Unknown service type {cls.__mro__[0]}, known {self.__services.keys()}")
        return Cast(T, self.__services[cls.__mro__[0]])
    
    def Process(self, if_data: InterfaceData) -> bool:
        """Returns true if it has been processed otherwise false"""
        for service in self.__sequence_input:
            if service.FrameFilter(if_data):
                if service.OnFrameReceived(if_data):
                    return True
        return False
    
class Arp(Service):
    table = {}
    def FrameFilter(self, if_data: InterfaceData) -> bool:
        return len(if_data.data) == 1
    
    def OnFrameReceived(self, if_data: InterfaceData) -> bool:
        self.SendBytes(f"Arp received - {if_data.data}")
        return True
    
    def _createRequest(self, ip: IPv4) -> bytes:
        ...
    
    async def Resolve(self, ip: IPv4) -> MAC:
        ...
    
class Syslog(Service):
    dest_ip: str = "127.0.0.1"
    dest_port: int = 4444
    
    async def Send(self, text: str) -> None:
        msg = f"syslog: {self.dest_ip}:{self.dest_port} - {text}"
        self.SendBytes(bytes(msg.encode('ascii')))

    def logging_callback(self, log: str) -> None:
        self.Send(log)
    