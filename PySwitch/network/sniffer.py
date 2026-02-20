import threading
from typing import Callable

from scapy.all import sniff, Packet

from .types import Physical


class Sniffer:
    def __init__(self, interface: Physical.Interface, callback: Callable[[Packet], None]):
        self._iface = interface
        self._callback = callback
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def Start(self) -> None:
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def Stop(self) -> None:
        self._stop_event.set()

    def _run(self) -> None:
        sniff(
            iface=self._iface.name,
            prn=self._callback,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def __del__(self) -> None:
        if self.running:
            self.Stop()
