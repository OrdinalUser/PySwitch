import logging
import socket
from dataclasses import dataclass
from PySwitch.common import List, Dict, Protocol, Callable, Optional, Cast, ClassVar, TypeVar, Type
from PySwitch.network.interface import InterfaceData
from abc import ABC, abstractmethod

class ServiceImplementation(Protocol):
    """Purely for programmer reference"""
    _on_data_send: Callable[[bytes], None] # Handles the underlying callback

    def FrameFilter(self, if_data: InterfaceData) -> bool:
        """Filters whether the frame is destined for the service"""
        ...

    def OnFrameReceived(self, if_data: InterfaceData) -> bool:
        """Processes the actual frame data, returns true if has been processed, false if not"""
        ...

T = TypeVar('T')

class Service:
    __services: ClassVar[Dict[Type, ServiceImplementation]]  = {}

    def __init_subclass__(cls) -> None:
        # Create the service
        service_obj = cls.__call__()
        # Register service
        Service.__services[cls.__mro__[0]] = service_obj # type: ignore
    
    @classmethod
    def Get(cls, service: Type[T]) -> T:
        if service.__mro__[0] not in cls.__services:
            raise KeyError(f"Unknown service type {service.__mro__[0]}, known {cls.__services.keys()}")
        return Cast(T, cls.__services[service.__mro__[0]])
    
    def GetAll(self) -> Dict[Type, ServiceImplementation]:
        return self.__services

    @classmethod
    def All(cls) -> 'Dict[Type, ServiceImplementation]':
        """Returns all registered service instances keyed by their type."""
        return dict(cls.__services)
    
_SYSLOG_SEVERITY: dict[int, int] = {
    logging.DEBUG:    7,  # LOG_DEBUG
    logging.INFO:     6,  # LOG_INFO
    logging.WARNING:  4,  # LOG_WARNING
    logging.ERROR:    3,  # LOG_ERR
    logging.CRITICAL: 2,  # LOG_CRIT
}
_SYSLOG_FACILITY = 1  # LOG_USER

@dataclass(slots=True)
class SyslogSettings:
    ip: str   = "127.0.0.1"
    port: int = 514
    enabled: bool = True

class Syslog(Service):
    _sock: socket.socket
    settings: SyslogSettings

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.settings = SyslogSettings()

    def logging_callback(self, record: logging.LogRecord, msg: str) -> None:
        if not self.settings.enabled:
            return
        severity = _SYSLOG_SEVERITY.get(record.levelno, 6)
        priority = _SYSLOG_FACILITY * 8 + severity
        message = f"<{priority}>{msg}\n".encode("ascii")
        self._sock.sendto(message, (self.settings.ip, self.settings.port))

    def Update(self, settings: SyslogSettings) -> None:
        self.settings = settings
