from __future__ import annotations
from PySwitch.common import List, Dict, Deque, Optional, Queue
from PySwitch.network.types import Frame, Protocols
from dataclasses import dataclass, field

import ctypes
import threading
import time
import logging

logger = logging.getLogger(__name__)

# ── wpcap.dll ctypes bindings ──────────────────────────────────────────────────

PCAP_OPENFLAG_PROMISCUOUS     = 1
PCAP_OPENFLAG_NOCAPTURE_LOCAL = 4
_PCAP_ERRBUF_SIZE             = 256

class _PcapPkthdr(ctypes.Structure):
    # struct timeval uses 32-bit longs on Windows (LLP64), followed by caplen/len
    _fields_ = [
        ("tv_sec",  ctypes.c_uint32),
        ("tv_usec", ctypes.c_uint32),
        ("caplen",  ctypes.c_uint32),
        ("len",     ctypes.c_uint32),
    ]

def _load_wpcap() -> ctypes.CDLL:
    lib = ctypes.cdll.LoadLibrary("wpcap.dll")

    # pcap_t *pcap_open(source, snaplen, flags, read_timeout, auth, errbuf)
    lib.pcap_open.restype  = ctypes.c_void_p
    lib.pcap_open.argtypes = [
        ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
        ctypes.c_int,    ctypes.c_void_p, ctypes.c_char_p,
    ]
    # int pcap_next_ex(handle, **pkthdr, **data)
    lib.pcap_next_ex.restype  = ctypes.c_int
    lib.pcap_next_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(_PcapPkthdr)),
        ctypes.POINTER(ctypes.c_char_p),
    ]
    # int pcap_sendpacket(handle, buf, size)
    lib.pcap_sendpacket.restype  = ctypes.c_int
    lib.pcap_sendpacket.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int,
    ]
    # void pcap_close(handle)
    lib.pcap_close.restype  = None
    lib.pcap_close.argtypes = [ctypes.c_void_p]

    return lib

_wpcap: Optional[ctypes.CDLL] = None

def _get_wpcap() -> ctypes.CDLL:
    global _wpcap
    if _wpcap is None:
        _wpcap = _load_wpcap()
    return _wpcap

# ──────────────────────────────────────────────────────────────────────────────

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

        def IsConnected(self) -> bool:
            import winreg, psutil
            # scapy description = adapter model; psutil keys = Windows friendly name.
            # Bridge via GUID → registry → friendly name so we always hit the right NIC.
            # huh? I'm so glad the LLMs can figure these things out..
            try:
                reg_path = (
                    f"SYSTEM\\CurrentControlSet\\Control\\Network\\"
                    f"{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\{self.guid}\\Connection"
                )
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                    friendly_name: str = winreg.QueryValueEx(key, "Name")[0]
            except OSError:
                return False
            iface = psutil.net_if_stats().get(friendly_name)
            if iface is None:
                return False
            return iface.isup

        def __hash__(self) -> int:
            return hash(self.name)

@dataclass
class Statistics:
    @dataclass(frozen=True)
    class Entry:
        size: int
        timestamp: float

    processed_max_size: int
    processed: Deque[Statistics.Entry] = field(default_factory=lambda: Deque())
    counts: Dict[Protocols, int] = field(default_factory=lambda: dict())

    def AggregateThroughput(self, time_s: float) -> int:
        now = time.time()
        return sum([entry.size for entry in self.processed if (now - entry.timestamp) <= time_s])

    def AddFrame(self, size: int):
        self.processed.append(Statistics.Entry(size, time.time()))
        if len(self.processed) > self.processed_max_size:
            self.processed.popleft()

    def Clear(self) -> None:
        self.processed = Deque()
        self.counts = dict()

@dataclass
class InterfaceMetrics:
    ingress: Statistics
    egress: Statistics

    def Clear(self) -> None:
        self.ingress.Clear()
        self.egress.Clear()

class Virtual:
    @dataclass
    class Interface:
        physical:      Optional[Physical.Interface]
        metrics:       InterfaceMetrics
        ingress_queue: Queue[tuple[Frame, Virtual.Interface]]  # shared with Core, supplied externally
        slot: int

        _stop_event:       threading.Event            = field(default_factory=threading.Event, init=False, repr=False)
        _thread:           Optional[threading.Thread] = field(default=None,               init=False, repr=False)
        _send_thread:      Optional[threading.Thread] = field(default=None,               init=False, repr=False)
        _pcap_handle:      Optional[int]              = field(default=None,               init=False, repr=False)  # capture — only touched by capture thread
        _pcap_send_handle: Optional[int]              = field(default=None,               init=False, repr=False)  # send — only touched by send thread
        _send_queue:       Queue[Optional[Frame]]     = field(default_factory=lambda: Queue(maxsize=512), init=False, repr=False)

        def __str__(self) -> str:
            return str(self.physical)

        @property
        def running(self) -> bool:
            return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

        def IsConnected(self) -> Optional[bool]:
            if self.physical is None: return None
            return self.physical.IsConnected()

        def ClearMetrics(self) -> None:
            self.metrics.Clear()

        def Start(self, interface: Physical.Interface) -> None:
            """Assigns physical interface and starts capture + send threads."""
            if self.running:
                return
            self.physical = interface
            self._send_queue = Queue()
            self._stop_event.clear()
            self._thread      = threading.Thread(target=self._capture,     daemon=True)
            self._send_thread = threading.Thread(target=self._send_worker, daemon=True)
            self._thread.start()
            self._send_thread.start()

        def Stop(self) -> None:
            """Signals both threads to stop and releases the physical interface."""
            self._stop_event.set()
            self._send_queue.put(None)  # wake the send thread so it exits promptly
            self._send_thread = None
            self._thread = None
            self.physical = None

        def Send(self, frame: Frame) -> None:
            """Enqueues a frame for async sending; drops silently if the send queue is full."""
            try:
                self._send_queue.put_nowait(frame)
            except Exception:
                pass  # queue full — drop the frame rather than stalling FrameHandler

        def _send_worker(self) -> None:
            """Drains the send queue and calls pcap_sendpacket; isolated so FrameHandler never blocks on NIC latency."""
            from queue import Empty
            wpcap = _get_wpcap()
            while not self._stop_event.is_set():
                try:
                    frame = self._send_queue.get(timeout=0.05)
                except Empty:
                    continue
                if frame is None:  # Stop() sentinel
                    break
                handle = self._pcap_send_handle
                if handle is None:
                    continue
                data = frame.data
                rc = wpcap.pcap_sendpacket(handle, data, len(data))
                if rc != 0:
                    logger.warning("pcap_sendpacket failed on slot %d", self.slot)
                else:
                    self.metrics.egress.AddFrame(len(data))

        def _capture(self) -> None:
            physical = self.physical
            if physical is None:
                return

            errbuf = ctypes.create_string_buffer(_PCAP_ERRBUF_SIZE)
            wpcap  = _get_wpcap()

            # pcap_open requires the npcap device path (\Device\NPF_{GUID}),
            # not the Windows friendly name that scapy stores in iface.name.
            pcap_device = f"\\Device\\NPF_{physical.guid}" if physical.guid else physical.name

            # Capture handle: NOCAPTURE_LOCAL suppresses npcap echoing our own sent frames back.
            rx_handle = wpcap.pcap_open(
                pcap_device.encode(),
                65535,
                PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_NOCAPTURE_LOCAL,
                1000,   # read timeout ms — pcap_next_ex blocks at most this long per call
                None,
                errbuf,
            )
            if rx_handle is None:
                logger.error("pcap_open (rx) failed for %s: %s", physical.name, errbuf.value.decode(errors="replace"))
                return

            # Send handle: separate from capture so FrameHandler and capture thread
            # never touch the same pcap_t concurrently (npcap handles are not thread-safe).
            tx_handle = wpcap.pcap_open(
                pcap_device.encode(),
                65535,
                PCAP_OPENFLAG_PROMISCUOUS,
                0,
                None,
                errbuf,
            )
            if tx_handle is None:
                wpcap.pcap_close(rx_handle)
                logger.error("pcap_open (tx) failed for %s: %s", physical.name, errbuf.value.decode(errors="replace"))
                return

            self._pcap_handle      = rx_handle
            self._pcap_send_handle = tx_handle

            pkt_header = ctypes.POINTER(_PcapPkthdr)()
            pkt_data   = ctypes.c_char_p()

            try:
                while not self._stop_event.is_set():
                    rc = wpcap.pcap_next_ex(
                        rx_handle,
                        ctypes.byref(pkt_header),
                        ctypes.byref(pkt_data),
                    )
                    if rc == 1:
                        length = pkt_header.contents.caplen
                        data   = ctypes.string_at(pkt_data, length)
                        self._on_packet(data)
                    elif rc == 0:
                        continue  # read timeout, loop back and check stop_event
                    else:
                        logger.error("pcap_next_ex returned %d on slot %d", rc, self.slot)
                        break
            finally:
                self._pcap_send_handle = None
                self._pcap_handle      = None
                wpcap.pcap_close(tx_handle)
                wpcap.pcap_close(rx_handle)

        def _on_packet(self, data: bytes) -> None:
            frame = Frame(data)
            self.metrics.ingress.AddFrame(len(frame.data))
            self.ingress_queue.put((frame, self))

        def __hash__(self) -> int:
            return hash(self.physical)
