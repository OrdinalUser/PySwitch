from PySwitch.common import Callable, Cast, ClassVar, Dict, Optional, Type, TypeVar

import datetime
import logging
import os
import socket
from dataclasses import dataclass

logger = logging.getLogger(__name__)

T = TypeVar("T")


class Service:
    __services: ClassVar[Dict[Type, Service]] = {}

    def __init_subclass__(cls) -> None:
        # Create the service
        service_obj = cls.__call__()
        # Register service
        Service.__services[cls.__mro__[0]] = service_obj  # type: ignore

    @classmethod
    def Get(cls, service: Type[T]) -> T:
        if service.__mro__[0] not in cls.__services:
            raise KeyError(
                f"Unknown service type {service.__mro__[0]}, known {cls.__services.keys()}"
            )
        return Cast(T, cls.__services[service.__mro__[0]])

    def GetAll(self) -> Dict[Type, Service]:
        return self.__services

    @classmethod
    def All(cls) -> Dict[Type, Service]:
        """Returns all registered service instances keyed by their type."""
        return dict(cls.__services)


_SYSLOG_SEVERITY: Dict[int, int] = {
    logging.DEBUG: 7,  # LOG_DEBUG
    logging.INFO: 6,  # LOG_INFO
    logging.WARNING: 4,  # LOG_WARNING
    logging.ERROR: 3,  # LOG_ERR
    logging.CRITICAL: 2,  # LOG_CRIT
}
_SYSLOG_FACILITY = 1  # LOG_USER


@dataclass(slots=True)
class SyslogSettings:
    server_ip: str = "127.0.0.1"
    port: int = 514
    source_ip: str = "127.0.0.1"
    enabled: bool = False
    severity: int = _SYSLOG_SEVERITY[logging.INFO]


class Syslog(Service):
    settings: SyslogSettings
    hostname: str
    pid: int
    _send_fn: Optional[Callable[[bytes, SyslogSettings], None]]

    def __init__(self) -> None:
        self.settings = SyslogSettings()
        self.hostname = socket.gethostname()
        self.pid = os.getpid()
        self._send_fn = None

    def set_send_fn(self, fn: Callable[[bytes, SyslogSettings], None]) -> None:
        self._send_fn = fn

    def _format(self, priority: int, msg: str) -> bytes:
        """RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG"""
        ts = (
            datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        return (
            f"<{priority}>1 {ts} {self.hostname} PySwitch {self.pid} - - {msg}".encode(
                "utf-8"
            )
        )

    def _send(self, data: bytes, settings: SyslogSettings) -> None:
        """Send pre-formatted bytes to the configured server, logging failures at DEBUG."""
        if self._send_fn is not None:
            try:
                self._send_fn(data, settings)
            except Exception as e:
                msg = f"Raw syslog send failed: {e}"
                logger.debug(msg)
                raise RuntimeError(msg)

    def logging_callback(self, record: logging.LogRecord, _msg: str) -> None:
        """Callback function meant to take data from Python logging module and retransmit over Syslog format"""
        if not self.settings.enabled:
            return
        severity = _SYSLOG_SEVERITY.get(record.levelno, _SYSLOG_SEVERITY[logging.INFO])
        if severity > self.settings.severity:
            return
        try:
            self._send(
                self._format(
                    _SYSLOG_FACILITY * 8 + severity,
                    f"{record.name}: {record.getMessage()}",
                ),
                self.settings,
            )
        except Exception as e:
            logger.debug(e)

    def test_and_apply(
        self, server_ip: str, source_ip: str, port: int, severity: int
    ) -> str | None:
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

        temp_settings = SyslogSettings(
            server_ip=server_ip, port=port, source_ip=source_ip
        )

        try:
            self._send(
                self._format(
                    _SYSLOG_FACILITY * 8 + severity, "Syslog test and set hello"
                ),
                temp_settings,
            )
        except Exception as e:
            return str(e)

        self.settings.server_ip = server_ip
        self.settings.source_ip = source_ip
        self.settings.port = port
        self.settings.severity = severity

        logger.info(f"Syslog settings changed to {self.settings}")
        return None
