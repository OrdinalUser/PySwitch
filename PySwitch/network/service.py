import datetime
import logging
import socket
from dataclasses import dataclass
from PySwitch.common import Dict, Cast, ClassVar, TypeVar, Type

import logging
logger = logging.getLogger(__name__)

T = TypeVar('T')

class Service:
    __services: ClassVar[Dict[Type, Service]]  = {}

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
    
    def GetAll(self) -> Dict[Type, Service]:
        return self.__services

    @classmethod
    def All(cls) -> Dict[Type, Service]:
        """Returns all registered service instances keyed by their type."""
        return dict(cls.__services)
    
_SYSLOG_SEVERITY: Dict[int, int] = {
    logging.DEBUG:    7,  # LOG_DEBUG
    logging.INFO:     6,  # LOG_INFO
    logging.WARNING:  4,  # LOG_WARNING
    logging.ERROR:    3,  # LOG_ERR
    logging.CRITICAL: 2,  # LOG_CRIT
}
_SYSLOG_FACILITY = 1  # LOG_USER

@dataclass(slots=True)
class SyslogSettings:
    server_ip: str = "127.0.0.1"
    port: int      = 514
    source_ip: str = ""           # empty = let OS pick the source address
    enabled: bool  = True
    severity: int  = _SYSLOG_SEVERITY[logging.INFO]

class Syslog(Service):
    _sock: socket.socket
    _bound_ip: str
    settings: SyslogSettings
    hostname: str

    def __init__(self) -> None:
        self._bound_ip = ""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.settings = SyslogSettings()
        self.hostname = socket.gethostname()

    def _format(self, priority: int, msg: str) -> bytes:
        """RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG"""
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
        return f"<{priority}>1 {ts} {self.hostname} PySwitch - - - {msg}".encode("utf-8")

    def _ensure_socket(self) -> None:
        """Recreate and rebind the socket if source_ip has changed."""
        target = self.settings.source_ip
        if self._bound_ip == target:
            return
        try:
            self._sock.close()
        except Exception:
            pass
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if target:
            self._sock.bind((target, 0))
        self._bound_ip = target

    def _send(self, data: bytes) -> None:
        """Send pre-formatted bytes to the configured server, logging failures at DEBUG."""
        self._ensure_socket()
        try:
            self._sock.sendto(data, (self.settings.server_ip, self.settings.port))
        except Exception as e:
            # This is why we don't support debug level in the syslog, would cause a circular mess
            logging.debug("Couldn't send syslog %s -> %s:%d: %s", self.settings.source_ip, self.settings.server_ip, self.settings.port, e)

    def logging_callback(self, record: logging.LogRecord, _msg: str) -> None:
        """Callback function meant to take data from Python logging module and retransmit over Syslog format"""
        if not self.settings.enabled:
            return
        severity = _SYSLOG_SEVERITY.get(record.levelno, _SYSLOG_SEVERITY[logging.INFO])
        if severity > self.settings.severity:
            return
        self._send(self._format(_SYSLOG_FACILITY * 8 + severity, f"{record.name}: {record.getMessage()}"))

    def test_and_apply(self, server_ip: str, source_ip: str, port: int, severity: int) -> str | None:
        """Validates, tests sending - not connection, then applies settings if os doesn't complain. Returns None on success, error string on failure."""
        try:
            socket.inet_aton(server_ip)
        except OSError:
            return f"Invalid server IP: {server_ip!r}"
        if source_ip:
            try:
                socket.inet_aton(source_ip)
            except OSError:
                return f"Invalid source IP: {source_ip!r}"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as test_sock:
                if source_ip:
                    test_sock.bind((source_ip, 0))
                test_sock.sendto(self._format(_SYSLOG_FACILITY * 8 + severity, "Syslog test and set hello"), (server_ip, port))
        except Exception as e:
            return f"Test failed: {e}"
        
        self.settings.server_ip = server_ip
        self.settings.source_ip = source_ip
        self.settings.port      = port
        self.settings.severity  = severity
        
        logger.info(f"Syslog settings changed to {self.settings}")
        return None
