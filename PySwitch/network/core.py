from __future__ import annotations
from typing import Literal
from PySwitch.common import Optional, ClassVar, Configuration, List, Queue, Tuple, Callable, Dict, Set, NamedTuple, Cast, BoundedSet
from PySwitch.network.interface import Physical, Virtual, InterfaceMetrics, Statistics, InterfaceData
from PySwitch.network.common import GetAllAvailableNICs
from PySwitch.network.types import MAC, Ethernet2, IPv4
from PySwitch.network.mac_table import MACTable
from PySwitch.network.frame import Frame
import PySwitch.network.service as Service

from threading import Thread, Event
from queue import Empty
import time

import logging
logger = logging.getLogger(__name__)

# Manages slots of virtual network interfaces that the Core works with - TODO
class Interfaces:
    interfaces: List[Virtual.Interface]
    port_mapping: Dict[Virtual.Interface, int]
    mac_table: MACTable
    on_change: Callable

    def __init__(self, configuration: Configuration, *, ingress_queue: Queue[List[Tuple[InterfaceData, Virtual.Interface]]], mac_table: MACTable, on_change: Callable):
        self.on_change = on_change
        self.interfaces = [
            Virtual.Interface(
                None,
                InterfaceMetrics(Statistics(configuration.static.metrics.throughput_buffer_size), Statistics(configuration.static.metrics.throughput_buffer_size)),
                ingress_queue=ingress_queue,
                slot=slot,
                batch_latency=configuration.static.core.interface_drain_s,
                batch_size=configuration.static.core.inteface_buffer
            )
            for slot in range(configuration.static.core.interface_count)
        ]
        self.port_mapping = dict()
        self.mac_table = mac_table

    def SlotInUse(self, slot: int):
        if slot >= len(self.interfaces) or slot < 0:
            raise ValueError(f"Invalid slot argument, provided {slot}, expected in range 0-{len(self.interfaces)-1}")
        return self.interfaces[slot].physical is not None

    def ClearSlot(self, slot: int):
        if slot >= len(self.interfaces) or slot < 0:
            raise ValueError(f"Invalid slot argument, provided {slot}, expected in range 0-{len(self.interfaces)-1}")
        if self.interfaces[slot].physical is None:
            raise ValueError(f"Slot {slot} is already empty")
        self.mac_table.Clean(slot)
        self.port_mapping.pop(self.interfaces[slot])
        logger.info(f"Unassigned interface {slot=}, removing {self.interfaces[slot]}")
        self.interfaces[slot].Stop()
        self.interfaces[slot].ClearMetrics()
        self.on_change()

    def AssignSlot(self, slot: int, interface: Physical.Interface):
        if slot >= len(self.interfaces) or slot < 0:
            raise ValueError(f"Invalid slot argument, provided {slot}, expected in range 0-{len(self.interfaces)-1}")
        if self.interfaces[slot].physical is not None:
            raise ValueError(f"Slot {slot} is in use")
        logger.info(f"Assigning interface slot {slot} to {interface}")
        self.interfaces[slot].Start(interface)
        self.port_mapping[self.interfaces[slot]] = slot
        self.on_change()

    def AvailableNICs(self, exclude_slot: int | None = None, force_reload: bool = False) -> List[Physical.Interface]:
        """Returns NICs not already assigned to another slot."""
        assigned = {
            self.interfaces[i].physical.name # type: ignore
            for i in range(len(self.interfaces))
            if i != exclude_slot and self.interfaces[i].physical is not None
        }
        return [nic for nic in GetAllAvailableNICs(force_reload) if nic.name not in assigned]
    
    def SendVia(self, frame: InterfaceData, slot_from: int, slot_to: int = -1,):
        """Forwards frame via virtual port assigned on slot_to, -1 implies flooding to every port except sender"""
        if slot_to != -1:
            # Unicast
            if self.interfaces[slot_to].connected:
                self.interfaces[slot_to].Send(frame)
        else:
            # Send everywhere
            for slot_idx in range(len(self.interfaces)):
                if slot_idx == slot_from or not self.interfaces[slot_idx].connected: continue
                self.interfaces[slot_idx].Send(frame)
    
    def ResetMetrics(self, slot: int) -> None:
        if slot >= len(self.interfaces) or slot < 0:
            raise ValueError(f"Invalid slot argument, provided {slot}, expected in range 0-{len(self.interfaces)-1}")
        if self.interfaces[slot].physical is None:
            raise ValueError(f"Slot {slot} is not bound")
        self.interfaces[slot].ClearMetrics()
    
    def Shutdown(self) -> None:
        """Stops all listening interfaces"""
        for slot in range(len(self.interfaces)):
            if self.SlotInUse(slot):
                self.ClearSlot(slot)

class Core:
    class ListeningOn(NamedTuple):
        mac: Set[MAC]
        ip: Set[IPv4]
    
    _instance: ClassVar[Optional[Core]]
    configuration: Configuration
    
    interfaces: Interfaces
    ingress_queue: Queue[List[Tuple[InterfaceData, Virtual.Interface]]]
    mac_table: MACTable
    
    listening: ListeningOn
    
    core_thread: Thread
    clean_thread: Thread
    stop_event: Event
    
    processed_frames: BoundedSet
    services: Service.Service
    wmi_thread: Thread

    @staticmethod
    def Get() -> Core:
        if not hasattr(Core, '_instance'):
            Core._instance = Core.Init()
        return getattr(Core, '_instance')

    @staticmethod
    def Init() -> Core:
        instance = Core()
        instance.ingress_queue = Queue()
        instance.configuration = Configuration.Get()
        
        instance.mac_table = MACTable()
        instance.interfaces = Interfaces(
            configuration=instance.configuration,
            ingress_queue=instance.ingress_queue,
            on_change=instance.OnInterfaceChange,
            mac_table=instance.mac_table
        )
        
        instance.OnInterfaceChange()
        instance.processed_frames = BoundedSet(instance.configuration.static.core.dedup_last_frames)
        
        instance.stop_event = Event()
        instance.core_thread = Thread(daemon=True, target=instance.FrameHandler)
        instance.core_thread.start()
        instance.clean_thread = Thread(daemon=True, target=instance.CleanHandler)
        instance.clean_thread.start()
        instance.wmi_thread = Thread(daemon=True, target=instance._wmi_watch)
        instance.wmi_thread.start()

        logger.critical("Initialized")
        return instance
    
    def _process_frame_data(self, if_data: InterfaceData, interface: Virtual.Interface) -> None:
        if interface.physical is None: # Poor mans data race check
            return
        
        # Has this frame already been processed? Thanks Windows
        # This is a terrible solution as it can actually drop repeating frames
        # that WERE supposed to be repeated! Tread cautiously and keep this in mind!
        # This does not fix data races on said interfaces! Slot 1 may still preempt Slot 0, even if said frame was meant to arrive on Slot 0
        if if_data.data in self.processed_frames:
            return
        else:
            self.processed_frames.add(if_data.data)
            # Had to pull this out from ingress threads to not skew metrics
            interface.metrics.ingress.AddFrame(if_data)
        
        # Deal with the L2 data
        frame = if_data.frame
        eth = Cast(Ethernet2, frame.ethernet2)
        # Discard loopback: source MAC is known on a different slot than the one
        # this frame arrived on — npcap echoed our own sendp() back as ingress
        source_slot = self.mac_table.Get(eth.mac_source)
        if source_slot != -1 and source_slot != interface.slot:
            # Some frames do fall under this check, perhaps the host OS is fighting us?
            return
        
        ## Learn MAC from packet
        self.mac_table.Learn(eth.mac_source, interface)
        
        ## If MAC broadcast, flood early
        if eth.mac_destination.is_broadcast:
            self.interfaces.SendVia(if_data, interface.slot, -1)
            return
        
        # Figure out if the frame is for us on L2
        # No need, we can use host stack for this!
        # if eth.mac_destination in self.listening.mac: # includes broadcast check
            # Maybe frame intended is intended for us - TODO
            # Most likely ARP or some other service, and consume
            # or return to pipeline
            # pass
        
        ## Frame is not meant for us, nor a broadcast, look for interface to forward through or flood
        destination_slot = self.mac_table.Get(eth.mac_destination)
        if destination_slot == interface.slot:
            # Output to source slot, nuh-uh? Let us not cause another cycle, please
            return
        ## Forward or flood, we don't care now
        self.interfaces.SendVia(if_data, interface.slot, destination_slot)

    def OnSlotEvent(self, slot: int, event: Literal["connect", "disconnect"]) -> None:
        iface = self.interfaces.interfaces[slot]
        if event == "disconnect":
            iface.disconnected_at = time.monotonic()
            self.mac_table.Clean(slot=slot)
            logger.info("Link down on slot %d (%s) [%s]", slot, iface.physical.name if iface.physical else "?", iface.physical.description if iface.physical else "?")
        else:
            logger.info("Link up on slot %d (%s) [%s]", slot, iface.physical.name if iface.physical else "?", iface.physical.description if iface.physical else "?")
        self.OnInterfaceChange()

    def _wmi_watch(self) -> None:
        try:
            import wmi  # type: ignore
            c = wmi.WMI()
            watcher = c.Win32_NetworkAdapter.watch_for(
                notification_type="modification",
                delay_secs=self.configuration.static.core.wmi_delay_s,
            )
            while not self.stop_event.is_set():
                try:
                    change = watcher(timeout_ms=1000)
                except wmi.x_wmi_timed_out:
                    continue

                for iface in self.interfaces.interfaces:
                    if iface.physical is None or iface.physical.guid != change.GUID:
                        continue
                    now_connected: bool = bool(change.NetEnabled)
                    was_connected = iface.connected
                    iface.connected = now_connected
                    if was_connected is True and not now_connected:
                        self.OnSlotEvent(iface.slot, "disconnect")
                    elif was_connected is not True and now_connected:
                        self.OnSlotEvent(iface.slot, "connect")
                    break
        except Exception:
            logger.exception("WMI watcher thread crashed")

    def FrameHandler(self) -> None:
        while not self.stop_event.is_set():
            try:
                frames = self.ingress_queue.get(timeout=self.configuration.live.core.cleanup_thread_sleep_s)
                print(f"Processing len={len(frames)} frames; qsize={self.ingress_queue.qsize()}", end="")
            except Empty:
                print("\r", end="")
                continue
            try:
                for frame, interface in frames:
                    self._process_frame_data(frame, interface)
            finally:
                self.ingress_queue.task_done()
                print("\r", end="")
    
    def CleanHandler(self) -> None:
        while not self.stop_event.is_set():
            self.mac_table.Clean(slot=-1) # Check all slots
            time.sleep(self.configuration.live.core.core_thread_sleep_s)
    
    def OnInterfaceChange(self) -> None:
        self.listening = Core.ListeningOn(
            mac=set([
                MAC.from_str(interface.physical.mac)
                for interface in self.interfaces.interfaces
                if interface.physical is not None and interface.physical.mac != ""
            ] + [MAC.from_str("ff:ff:ff:ff:ff:ff")] ),
            ip=set([
                IPv4.from_str(interface.physical.ip)
                for interface in self.interfaces.interfaces
                if interface.physical is not None and interface.physical.mac != "" and interface.physical.ip != ""
            ])
        )
        
        return

    def Send(self, data: bytes):
        if_data = InterfaceData(data=data, frame=Frame.from_bytes(data))
        self.interfaces.SendVia(if_data, -1, -1)

    def ClearMac(self) -> None:
        logger.info("Clearing global MAC table")
        self.mac_table.Clear()

    def ClearMetrics(self, slot: int) -> None:
        logger.info(f"Clearing metrics on {slot=}")
        self.interfaces.ResetMetrics(slot)

    def Shutdown(self) -> None:
        """Explicit shutdown"""
        self.interfaces.Shutdown()
        logger.critical("Shutdown")
