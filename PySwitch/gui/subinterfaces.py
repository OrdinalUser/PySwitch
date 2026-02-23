import time

import PySwitch.network as network
import PySwitch.startup as startup
from PySwitch.common.config import Configuration

from PySide6.QtWidgets import (
    QHBoxLayout,
    QVBoxLayout,
    QWidget,
    QLabel,
    QPlainTextEdit,
    QTableWidgetItem,
    QHeaderView,
    QAbstractItemView,
)

from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont

from qfluentwidgets import (
    ComboBox,
    PushButton,
    PrimaryPushButton,
    SimpleCardWidget,
    MessageBoxBase,
    SubtitleLabel,
    StrongBodyLabel,
    BodyLabel,
    CaptionLabel,
    FlowLayout,
    TableWidget
)

# ── Helpers ───────────────────────────────────────────────────────────────────

_THROUGHPUT_WINDOW_S = 5.0

def _fmt_bytes(n: int) -> str:
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f} MB/s"
    if n >= 1024:
        return f"{n / 1024:.1f} KB/s"
    return f"{n} B/s"


# ── Assign NIC dialog ─────────────────────────────────────────────────────────

class AssignNICDialog(MessageBoxBase):
    def __init__(self, slot: int, parent=None):
        super().__init__(parent)
        self._slot  = slot
        self._ifaces: list[network.Physical.Interface] = []

        self._title = SubtitleLabel(f"Assign NIC to Slot {slot}", self)

        row = QHBoxLayout()
        self._combo       = ComboBox(self)
        self._combo.setMinimumWidth(300)
        self._refresh_btn = PushButton("Refresh", self)
        row.addWidget(self._combo, stretch=1)
        row.addWidget(self._refresh_btn)

        self.viewLayout.addWidget(self._title)
        self.viewLayout.addLayout(row)

        self.yesButton.setText("Assign")
        self.cancelButton.setText("Cancel")

        self._refresh_btn.clicked.connect(self._populate)
        self._populate()

    def _populate(self) -> None:
        self._ifaces = network.Core.Get().interfaces.AvailableNICs(exclude_slot=self._slot)
        self._combo.clear()
        for iface in self._ifaces:
            self._combo.addItem(iface.description or iface.name)

    def selected(self) -> network.Physical.Interface | None:
        idx = self._combo.currentIndex()
        return self._ifaces[idx] if 0 <= idx < len(self._ifaces) else None


# ── Interface slot card ───────────────────────────────────────────────────────

class InterfaceSlotCard(SimpleCardWidget):
    assign_clicked     = Signal(int)
    disconnect_clicked = Signal(int)

    _DOT_UNKNOWN      = "background: #888888; border-radius: 5px;"
    _DOT_CONNECTED    = "background: #3cb371; border-radius: 5px;"
    _DOT_DISCONNECTED = "background: #cc3333; border-radius: 5px;"

    def __init__(self, slot: int, parent=None):
        super().__init__(parent)
        self._slot = slot
        self.setMinimumSize(240, 220)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(4)

        # Header: "Slot N"
        header = QHBoxLayout()
        self._slot_label  = StrongBodyLabel(f"Slot {slot}", self)
        self._status_dot  = QLabel(self)
        self._status_dot.setFixedSize(10, 10)
        self._status_dot.setStyleSheet(self._DOT_UNKNOWN)
        header.addWidget(self._slot_label)
        header.addStretch()
        header.addWidget(self._status_dot)
        root.addLayout(header)

        root.addSpacing(4)

        # Interface info
        self._name_label = BodyLabel("—", self)
        self._mac_label  = CaptionLabel("", self)
        self._ip_label   = CaptionLabel("", self)
        root.addWidget(self._name_label)
        root.addWidget(self._mac_label)
        root.addWidget(self._ip_label)

        root.addSpacing(8)

        # Throughput
        self._rx_label = BodyLabel("↓  —", self)
        self._tx_label = BodyLabel("↑  —", self)
        root.addWidget(self._rx_label)
        root.addWidget(self._tx_label)

        root.addStretch()

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        self._assign_btn     = PrimaryPushButton("Assign",     self)
        self._disconnect_btn = PushButton("Disconnect", self)
        btn_row.addWidget(self._assign_btn)
        btn_row.addWidget(self._disconnect_btn)
        root.addLayout(btn_row)

        self._assign_btn.clicked.connect(    lambda: self.assign_clicked.emit(self._slot))
        self._disconnect_btn.clicked.connect(lambda: self.disconnect_clicked.emit(self._slot))

        self._set_unassigned()

    # ── internal state helpers ────────────────────────────────────────────────

    def _set_unassigned(self) -> None:
        self._name_label.setText("No interface assigned")
        self._mac_label.setText("")
        self._ip_label.setText("")
        self._rx_label.setText("↓  —")
        self._tx_label.setText("↑  —")
        self._status_dot.setStyleSheet(self._DOT_UNKNOWN)
        self._assign_btn.setVisible(True)
        self._disconnect_btn.setVisible(False)

    def Refresh(self, iface: network.Virtual.Interface) -> None:
        p = iface.physical
        if p is None:
            self._set_unassigned()
            return

        self._name_label.setText(p.description or p.name)
        self._mac_label.setText(p.mac)
        self._ip_label.setText(p.ip)

        rx = iface.metrics.ingress.AggregateThroughput(_THROUGHPUT_WINDOW_S)
        tx = iface.metrics.egress.AggregateThroughput(_THROUGHPUT_WINDOW_S)
        self._rx_label.setText(f"↓ {_fmt_bytes(rx)}")
        self._tx_label.setText(f"↑ {_fmt_bytes(tx)}")

        self._status_dot.setStyleSheet(self._DOT_CONNECTED if p.IsConnected() else self._DOT_DISCONNECTED)

        self._assign_btn.setVisible(False)
        self._disconnect_btn.setVisible(True)

# ── Interfaces subinterface ───────────────────────────────────────────────────

class Interfaces(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("Sub.Interfaces")
        self._core = network.Core.Get()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        cards_row = FlowLayout(needAni=True)
        cards_row.setSpacing(12)
        n = self._core.configuration.static.core.interface_count
        self._cards = [InterfaceSlotCard(i, self) for i in range(n)]
        for card in self._cards:
            cards_row.addWidget(card)
            card.assign_clicked.connect(self._on_assign)
            card.disconnect_clicked.connect(self._on_disconnect)
        # cards_row.addStretch()

        layout.addLayout(cards_row)
        layout.addStretch()

        self._timer = QTimer(self)
        self._timer.setInterval(self._core.configuration.static.ui.refresh_rate_ms)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()
        self._refresh()

    def _refresh(self) -> None:
        for i, card in enumerate(self._cards):
            card.Refresh(self._core.interfaces.interfaces[i])

    def _on_assign(self, slot: int) -> None:
        dlg = AssignNICDialog(slot, self.window())
        if dlg.exec():
            physical_interface = dlg.selected()
            if physical_interface:
                self._core.interfaces.AssignSlot(slot, physical_interface)
        self._refresh()

    def _on_disconnect(self, slot: int) -> None:
        self._core.interfaces.ClearSlot(slot)
        self._refresh()


# ── Logs ──────────────────────────────────────────────────────────────────────

class Logs(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("Sub.Logs")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        self._clear_btn = PushButton("Clear", self)
        toolbar.addStretch()
        toolbar.addWidget(self._clear_btn)

        self._console = QPlainTextEdit(self)
        self._console.setReadOnly(True)
        self._console.setFont(QFont("Consolas", 9))
        self._console.setMaximumBlockCount(2000)  # cap lines so it never grows unbounded

        layout.addLayout(toolbar)
        layout.addWidget(self._console)

        self._clear_btn.clicked.connect(self._console.clear)

        self._timer = QTimer(self)
        self._timer.setInterval(Configuration.Get().static.ui.log_drain_ms)  # drain at ~20 fps
        self._timer.timeout.connect(self._drain)
        self._timer.start()

    def _drain(self) -> None:
        q = startup.get_log_queue()
        while not q.empty():
            try:
                self._console.appendPlainText(q.get_nowait())
            except Exception:
                break


# ── NIC Sniffer ───────────────────────────────────────────────────────────────

class PhysicalSniffer(QWidget):
    _packet_received = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("Sub.PhysicalSniffer")
        self._sniffer: network.Sniffer | None = None
        self._ifaces: list[network.Physical.Interface] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        # Controls row
        controls = QHBoxLayout()
        controls.setSpacing(8)

        self._nic_dropdown = ComboBox(self)
        self._nic_dropdown.setMinimumWidth(240)

        self._start_btn   = PushButton("Start",   self)
        self._stop_btn    = PushButton("Stop",    self)
        self._clear_btn   = PushButton("Clear",   self)
        self._refresh_btn = PushButton("Refresh", self)
        self._stop_btn.setEnabled(False)

        controls.addWidget(self._nic_dropdown, stretch=1)
        controls.addWidget(self._start_btn)
        controls.addWidget(self._stop_btn)
        controls.addWidget(self._clear_btn)
        controls.addWidget(self._refresh_btn)

        # Packet console
        self._console = QPlainTextEdit(self)
        self._console.setReadOnly(True)
        self._console.setFont(QFont("Consolas", 9))
        self._console.setPlaceholderText("Captured packets will appear here…")

        layout.addLayout(controls)
        layout.addWidget(self._console)

        # Wire up
        self._start_btn.clicked.connect(self._on_start)
        self._stop_btn.clicked.connect(self._on_stop)
        self._clear_btn.clicked.connect(self._console.clear)
        self._refresh_btn.clicked.connect(self._populate_nics)
        self._packet_received.connect(self._console.appendPlainText)

        self._populate_nics()

    def _populate_nics(self) -> None:
        self._ifaces = network.GetAllAvailableNICs()
        self._nic_dropdown.clear()
        for iface in self._ifaces:
            label = iface.description or iface.name
            self._nic_dropdown.addItem(label)

    def _on_start(self) -> None:
        idx = self._nic_dropdown.currentIndex()
        if idx < 0 or not self._ifaces:
            return
        self._sniffer = network.Sniffer(self._ifaces[idx], self._on_packet)
        self._sniffer.Start()
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._nic_dropdown.setEnabled(False)

    def _on_stop(self) -> None:
        if self._sniffer:
            self._sniffer.Stop()
            self._sniffer = None
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._nic_dropdown.setEnabled(True)

    def _on_packet(self, pkt) -> None:
        # Called from sniffer thread — emit signal to marshal onto main thread
        self._packet_received.emit(pkt.summary())


# ── MAC Table ─────────────────────────────────────────────────────────────────

class MACTableView(QWidget):
    _COLUMNS = ("MAC Address", "Interface Name", "Slot", "Expires In (s)")

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setObjectName("Sub.MACTable")
        self._core = network.Core.Get()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        self._clear_btn = PushButton("Clear Table", self)
        toolbar.addStretch()
        toolbar.addWidget(self._clear_btn)

        self._table = TableWidget(self)
        self._table.setColumnCount(len(self._COLUMNS))
        self._table.setHorizontalHeaderLabels(self._COLUMNS)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False)
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

        layout.addLayout(toolbar)
        layout.addWidget(self._table)

        self._clear_btn.clicked.connect(self._on_clear)

        self._timer = QTimer(self)
        self._timer.setInterval(self._core.configuration.static.ui.refresh_rate_ms)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()
        self._refresh()

    def _refresh(self) -> None:
        entries = self._core.mac_table.ToList()
        now = time.monotonic()
        self._table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            remaining = max(0.0, entry.timestamp_expiration - now)
            self._table.setItem(row, 0, QTableWidgetItem(str(entry.mac)))
            self._table.setItem(row, 1, QTableWidgetItem(entry.interface.physical.name))
            self._table.setItem(row, 2, QTableWidgetItem(str(entry.interface.slot)))
            self._table.setItem(row, 3, QTableWidgetItem(f"{remaining:.1f}"))

    def _on_clear(self) -> None:
        self._core.ClearMac()
        self._refresh()