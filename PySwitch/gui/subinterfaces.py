import PySwitch.network as network
import PySwitch.network.service as svc
import PySwitch.startup as startup
from PySwitch.common import Configuration, List, Live, Tuple, Union, UnionType

from pydantic import BaseModel as _PydanticBase
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDoubleSpinBox,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QStackedWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import (  # type: ignore
    BodyLabel,
    CaptionLabel,
    ComboBox,
    FlowLayout,
    LineEdit,
    MessageBoxBase,
    PrimaryPushButton,
    PushButton,
    SimpleCardWidget,
    SpinBox,
    StrongBodyLabel,
    SubtitleLabel,
    SwitchButton,
    TableWidget,
    TransparentPushButton,
)

import time

# ── Helpers ───────────────────────────────────────────────────────────────────

_THROUGHPUT_WINDOW_S = 5.0


def _fmt_bytes(n: int, suffix: str = "/s") -> str:
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f} MiB{suffix}"
    if n >= 1024:
        return f"{n / 1024:.1f} KiB{suffix}"
    return f"{n} B{suffix}"


def _fmt_elapsed(started: float) -> str:
    s = int(time.time() - started)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60:02d}s"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60:02d}m"
    return f"{s // 86400}d {(s % 86400) // 3600:02d}h"


_PROTOCOL_ROWS: List[Tuple[network.Protocols, str]] = [
    (protocol, protocol.value) for protocol in network.Protocols
]

# ── Assign NIC dialog ─────────────────────────────────────────────────────────


class AssignNICDialog(MessageBoxBase):
    def __init__(self, slot: int, parent=None):
        super().__init__(parent)
        self._slot = slot
        self._ifaces: list[network.Physical.Interface] = []

        self._title = SubtitleLabel(f"Assign NIC to Slot {slot}", self)

        row = QHBoxLayout()
        self._combo = ComboBox(self)
        self._combo.setMinimumWidth(300)
        self._refresh_btn = PushButton("Refresh", self)
        row.addWidget(self._combo, stretch=1)
        row.addWidget(self._refresh_btn)

        self.viewLayout.addWidget(self._title)
        self.viewLayout.addLayout(row)

        self.yesButton.setText("Assign")
        self.cancelButton.setText("Cancel")

        self._refresh_btn.clicked.connect(lambda: self._populate(force_reload=True))
        self._populate(force_reload=False)

    def _populate(self, force_reload: bool = True) -> None:
        self._ifaces = network.Core.Get().interfaces.AvailableNICs(
            exclude_slot=self._slot, force_reload=force_reload
        )
        self._combo.clear()
        for iface in self._ifaces:
            self._combo.addItem(iface.description or iface.name)

    def selected(self) -> network.Physical.Interface | None:
        idx = self._combo.currentIndex()
        return self._ifaces[idx] if 0 <= idx < len(self._ifaces) else None


# ── Interface slot card ───────────────────────────────────────────────────────


class InterfaceSlotCard(SimpleCardWidget):
    assign_clicked = Signal(int)
    disconnect_clicked = Signal(int)

    _DOT_UNKNOWN = "background: #888888; border-radius: 5px;"
    _DOT_CONNECTED = "background: #3cb371; border-radius: 5px;"
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
        self._slot_label = StrongBodyLabel(f"Slot {slot}", self)
        self._status_dot = QLabel(self)
        self._status_dot.setFixedSize(10, 10)
        self._status_dot.setStyleSheet(self._DOT_UNKNOWN)
        header.addWidget(self._slot_label)
        header.addStretch()
        header.addWidget(self._status_dot)
        root.addLayout(header)

        root.addSpacing(4)

        # Interface info
        self._friendly_label = BodyLabel("—", self)
        self._name_label = CaptionLabel("", self)
        self._mac_label = CaptionLabel("", self)
        self._ip_label = CaptionLabel("", self)
        root.addWidget(self._friendly_label)
        root.addWidget(self._name_label)
        root.addWidget(self._mac_label)
        root.addWidget(self._ip_label)

        root.addSpacing(8)

        # Throughput
        self._rx_label = BodyLabel("↓  —", self)
        self._tx_label = BodyLabel("↑  —", self)
        self._elapsed_label = CaptionLabel("", self)
        root.addWidget(self._rx_label)
        root.addWidget(self._tx_label)
        root.addWidget(self._elapsed_label)

        root.addSpacing(4)

        # Stats toggle
        toggle_row = QHBoxLayout()
        self._stats_btn = TransparentPushButton("▶ Stats", self)
        self._stats_btn.clicked.connect(self._toggle_stats)
        toggle_row.addStretch()
        toggle_row.addWidget(self._stats_btn)

        root.addLayout(toggle_row)

        # Stats section — hidden by default
        self._stats_section = QWidget(self)
        self._stats_section.setVisible(False)
        grid = QGridLayout(self._stats_section)
        grid.setContentsMargins(0, 2, 0, 0)
        grid.setSpacing(2)
        for col, text in enumerate(("", "IN", "OUT")):
            lbl = CaptionLabel(text, self._stats_section)
            lbl.setAlignment(
                Qt.AlignmentFlag.AlignRight if col > 0 else Qt.AlignmentFlag.AlignLeft
            )
            grid.addWidget(lbl, 0, col)
        self._stats_labels: list[tuple[CaptionLabel, CaptionLabel]] = []
        for row_i, (_, name) in enumerate(_PROTOCOL_ROWS, start=1):
            name_lbl = CaptionLabel(name, self._stats_section)
            in_lbl = CaptionLabel("0", self._stats_section)
            out_lbl = CaptionLabel("0", self._stats_section)
            in_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
            out_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
            grid.addWidget(name_lbl, row_i, 0)
            grid.addWidget(in_lbl, row_i, 1)
            grid.addWidget(out_lbl, row_i, 2)
            self._stats_labels.append((in_lbl, out_lbl))
        self._clear_btn = TransparentPushButton("Clear", self._stats_section)
        self._clear_btn.clicked.connect(
            lambda: network.Core.Get().ClearMetrics(self._slot)
        )
        grid.addWidget(self._clear_btn, len(_PROTOCOL_ROWS) + 1, 2)
        root.addWidget(self._stats_section)

        root.addStretch()

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        self._assign_btn = PrimaryPushButton("Assign", self)
        self._disconnect_btn = PushButton("Disconnect", self)
        btn_row.addWidget(self._assign_btn)
        btn_row.addWidget(self._disconnect_btn)
        root.addLayout(btn_row)

        self._assign_btn.clicked.connect(lambda: self.assign_clicked.emit(self._slot))
        self._disconnect_btn.clicked.connect(
            lambda: self.disconnect_clicked.emit(self._slot)
        )

        self._set_unassigned()

    # ── internal state helpers ────────────────────────────────────────────────

    def _toggle_stats(self) -> None:
        visible = not self._stats_section.isVisible()
        self._stats_section.setVisible(visible)
        self._stats_btn.setText("▼ Stats" if visible else "▶ Stats")

    def _update_stats(self, metrics: network.InterfaceMetrics) -> None:
        for i, (proto, _) in enumerate(_PROTOCOL_ROWS):
            in_lbl, out_lbl = self._stats_labels[i]
            in_lbl.setText(str(metrics.ingress.counts.get(proto, 0)))
            out_lbl.setText(str(metrics.egress.counts.get(proto, 0)))

    def _set_unassigned(self) -> None:
        self._friendly_label.setText("No interface assigned")
        self._name_label.setText("")
        self._mac_label.setText("")
        self._ip_label.setText("")
        self._rx_label.setText("↓  —")
        self._tx_label.setText("↑  —")
        self._elapsed_label.setText("")
        self._status_dot.setStyleSheet(self._DOT_UNKNOWN)
        self._stats_section.setVisible(False)
        self._stats_btn.setText("▶ Stats")
        self._stats_btn.setEnabled(False)
        for in_lbl, out_lbl in self._stats_labels:
            in_lbl.setText("0")
            out_lbl.setText("0")
        self._assign_btn.setVisible(True)
        self._disconnect_btn.setVisible(False)

    def Refresh(self, iface: network.Virtual.Interface) -> None:
        p = iface.physical
        if p is None:
            self._set_unassigned()
            return

        self._friendly_label.setText(p.description)
        self._name_label.setText(f"{p.media_type.value} - {p.name}")
        self._mac_label.setText(p.mac)
        self._ip_label.setText(p.ip)

        rx = iface.metrics.ingress.AggregateThroughput(_THROUGHPUT_WINDOW_S)
        tx = iface.metrics.egress.AggregateThroughput(_THROUGHPUT_WINDOW_S)
        self._rx_label.setText(
            f"↓ {_fmt_bytes(rx)} ({_fmt_bytes(iface.metrics.ingress.total_bytes, suffix='')})"
        )
        self._tx_label.setText(
            f"↑ {_fmt_bytes(tx)} ({_fmt_bytes(iface.metrics.egress.total_bytes, suffix='')})"
        )

        elapsed = (
            f"Elapsed time {_fmt_elapsed(iface.record_started)}"
            if iface.record_started is not None
            else ""
        )
        self._elapsed_label.setText(elapsed)

        # connected = iface.connected if iface.connected is not None else p.IsConnected()
        connected = iface.connected
        self._status_dot.setStyleSheet(
            self._DOT_CONNECTED if connected else self._DOT_DISCONNECTED
        )
        self._stats_btn.setEnabled(True)
        self._update_stats(iface.metrics)

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
        self._console.setFont(QFont("Consolas", 10))
        self._console.setMaximumBlockCount(
            2000
        )  # cap lines so it never grows unbounded

        layout.addLayout(toolbar)
        layout.addWidget(self._console)

        self._clear_btn.clicked.connect(self._console.clear)

        self._timer = QTimer(self)
        self._timer.setInterval(
            Configuration.Get().static.ui.log_drain_ms
        )  # drain at ~20 fps
        self._timer.timeout.connect(self._drain)
        self._timer.start()

    def _drain(self) -> None:
        q = startup.get_log_queue()
        while not q.empty():
            try:
                self._console.appendPlainText(q.get_nowait())
            except Exception:
                break


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
            self._table.setItem(
                row,
                1,
                QTableWidgetItem(
                    entry.interface.physical.name
                    if entry.interface.physical
                    else "Unknown"
                ),
            )
            self._table.setItem(row, 2, QTableWidgetItem(str(entry.interface.slot)))
            self._table.setItem(row, 3, QTableWidgetItem(f"{remaining:.1f}"))

    def _on_clear(self) -> None:
        self._core.ClearMac()
        self._refresh()


# ── Services ──────────────────────────────────────────────────────────────────

_SEVERITY_OPTIONS: list[tuple[str, int]] = [
    ("Critical", 2),
    ("Error", 3),
    ("Warning", 4),
    ("Info", 6),
]


class _SyslogSettingsCard(SimpleCardWidget):
    def __init__(self, service: "svc.Syslog", parent=None):
        super().__init__(parent)
        self._service = service
        s = service.settings

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 22)
        root.setSpacing(10)
        root.addWidget(StrongBodyLabel("Syslog", self))

        LBL_W = 90

        # Enabled — applied immediately, no socket involved
        row = QHBoxLayout()
        lbl = BodyLabel("Enabled", self)
        lbl.setMinimumWidth(LBL_W)
        # This stupid thing sometimes dumps "QFont::setPointSize: Point size <= 0 (-1), must be greater than 0" into the stdout, no idea how to fix
        # not even a QFont() with explicit point size fixes it
        self._enabled = SwitchButton(self)
        self._enabled.setChecked(s.enabled)
        self._enabled.checkedChanged.connect(
            lambda v: setattr(self._service.settings, "enabled", v)
        )
        row.addWidget(lbl)
        row.addStretch()
        row.addWidget(self._enabled)
        root.addLayout(row)

        # Source IP
        row = QHBoxLayout()
        lbl = BodyLabel("Source IP", self)
        lbl.setMinimumWidth(LBL_W)
        self._source_ip = LineEdit(self)
        self._source_ip.setText(s.source_ip)
        self._source_ip.setPlaceholderText("Leave empty for auto")
        row.addWidget(lbl)
        row.addWidget(self._source_ip, stretch=1)
        root.addLayout(row)

        # Server IP
        row = QHBoxLayout()
        lbl = BodyLabel("Server IP", self)
        lbl.setMinimumWidth(LBL_W)
        self._server_ip = LineEdit(self)
        self._server_ip.setText(s.server_ip)
        self._server_ip.setPlaceholderText("e.g. 192.168.1.100")
        row.addWidget(lbl)
        row.addWidget(self._server_ip, stretch=1)
        root.addLayout(row)

        # Port
        row = QHBoxLayout()
        lbl = BodyLabel("Port", self)
        lbl.setMinimumWidth(LBL_W)
        self._port = SpinBox(self)
        self._port.setRange(1, 65535)
        self._port.setValue(s.port)
        row.addWidget(lbl)
        row.addWidget(self._port, stretch=1)
        root.addLayout(row)

        # Min severity
        row = QHBoxLayout()
        lbl = BodyLabel("Min Severity", self)
        lbl.setMinimumWidth(LBL_W)
        self._severity = ComboBox(self)
        self._severity_values = [val for _, val in _SEVERITY_OPTIONS]
        for label, _ in _SEVERITY_OPTIONS:
            self._severity.addItem(label)
        for i, val in enumerate(self._severity_values):
            if val == s.severity:
                self._severity.setCurrentIndex(i)
                break
        row.addWidget(lbl)
        row.addWidget(self._severity, stretch=1)
        root.addLayout(row)

        # Status + button
        self._status = BodyLabel("", self)
        root.addSpacing(4)
        root.addWidget(self._status)
        self._apply_btn = PrimaryPushButton("Test && Apply", self)
        self._apply_btn.clicked.connect(self._on_apply)
        root.addWidget(self._apply_btn)

        root.addStretch()

    def _on_apply(self) -> None:
        error = self._service.test_and_apply(
            server_ip=self._server_ip.text().strip(),
            source_ip=self._source_ip.text().strip(),
            port=self._port.value(),
            severity=self._severity_values[self._severity.currentIndex()],
        )
        self._status.setText(error or "Settings applied.")
        QTimer.singleShot(3000, lambda: self._status.setText(""))


class Services(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Sub.Services")

        outer = QHBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(16)

        sidebar = QWidget(self)
        sidebar.setFixedWidth(140)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(4)
        sidebar_layout.addWidget(StrongBodyLabel("Services"))
        sidebar_layout.addSpacing(4)

        self._stack = QStackedWidget(self)

        for svc_type, _ in svc.Service.All().items():
            if svc_type is svc.Syslog:
                card = _SyslogSettingsCard(svc.Service.Get(svc.Syslog), self)
            else:
                continue
            btn = TransparentPushButton(svc_type.__name__, sidebar)
            btn.clicked.connect(
                lambda checked=False, p=card: self._stack.setCurrentWidget(p)
            )
            sidebar_layout.addWidget(btn)
            self._stack.addWidget(card)

        sidebar_layout.addStretch()
        outer.addWidget(sidebar)
        outer.addWidget(self._stack, stretch=1)

        if self._stack.count():
            self._stack.setCurrentIndex(0)


# ── Live Config ───────────────────────────────────────────────────────────────


def _field_label(name: str) -> str:
    return name.replace("_", " ").title()


def _unwrap_annotation(annotation):
    """Strip Optional/Union wrappers and return the bare type."""
    origin = getattr(annotation, "__origin__", None)
    if origin is UnionType or origin is Union:
        args = [a for a in annotation.__args__ if a is not type(None)]
        return args[0] if args else annotation
    return annotation


class LiveConfigView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Sub.LiveConfig")
        cfg = Configuration.Get()
        self._filepath = cfg.env.config_directory / "live.toml"
        self._widgets: dict[str, QWidget] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        card = SimpleCardWidget(self)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 14, 16, 22)
        card_layout.setSpacing(10)
        card_layout.addWidget(StrongBodyLabel("Live Configuration", card))

        self._build_fields(Live, card, card_layout, prefix="")

        card_layout.addSpacing(4)
        self._status = BodyLabel("", card)
        card_layout.addWidget(self._status)

        btn_row = QHBoxLayout()
        self._reload_btn = PushButton("Reload", card)
        self._apply_btn = PrimaryPushButton("Apply", card)
        self._reload_btn.clicked.connect(self._load)
        self._apply_btn.clicked.connect(self._on_apply)
        btn_row.addStretch()
        btn_row.addWidget(self._reload_btn)
        btn_row.addWidget(self._apply_btn)
        card_layout.addLayout(btn_row)
        card_layout.addStretch()

        layout.addWidget(card)
        layout.addStretch()

        self._load()

    def _build_fields(self, model_cls, parent_widget, layout, prefix: str) -> None:
        for field_name, field_info in model_cls.model_fields.items():
            key = f"{prefix}.{field_name}" if prefix else field_name
            ann = _unwrap_annotation(field_info.annotation)

            if isinstance(ann, type) and issubclass(ann, _PydanticBase):
                layout.addSpacing(4)
                layout.addWidget(
                    CaptionLabel(_field_label(field_name).upper(), parent_widget)
                )
                self._build_fields(ann, parent_widget, layout, prefix=key)
                continue

            widget = self._make_widget(ann, parent_widget)
            if widget is None:
                continue

            row = QHBoxLayout()
            lbl = BodyLabel(_field_label(field_name), parent_widget)
            lbl.setMinimumWidth(190)
            row.addWidget(lbl)
            row.addWidget(widget, stretch=1)
            layout.addLayout(row)
            self._widgets[key] = widget

    @staticmethod
    def _make_widget(ann, parent) -> QWidget | None:
        if ann is float:
            sb = QDoubleSpinBox(parent)
            sb.setRange(0.0, 1e9)
            sb.setDecimals(2)
            sb.setSingleStep(1.0)
            return sb
        if ann is int:
            sb = SpinBox(parent)
            sb.setRange(0, 1_000_000)
            return sb
        if ann is str:
            return LineEdit(parent)
        if ann is bool:
            return SwitchButton(parent)
        return None

    def _set_values(self, model_cls, instance, prefix: str) -> None:
        for field_name, field_info in model_cls.model_fields.items():
            key = f"{prefix}.{field_name}" if prefix else field_name
            ann = _unwrap_annotation(field_info.annotation)
            value = getattr(instance, field_name)
            if isinstance(ann, type) and issubclass(ann, _PydanticBase):
                self._set_values(ann, value, prefix=key)
                continue
            widget = self._widgets.get(key)
            if widget is None:
                continue
            if isinstance(widget, QDoubleSpinBox):
                widget.setValue(float(value))
            elif isinstance(widget, SpinBox):
                widget.setValue(int(value))
            elif isinstance(widget, LineEdit):
                widget.setText(str(value))
            elif isinstance(widget, SwitchButton):
                widget.setChecked(bool(value))

    def _collect_values(self, model_cls, prefix: str) -> dict:
        result = {}
        for field_name, field_info in model_cls.model_fields.items():
            key = f"{prefix}.{field_name}" if prefix else field_name
            ann = _unwrap_annotation(field_info.annotation)
            if isinstance(ann, type) and issubclass(ann, _PydanticBase):
                result[field_name] = self._collect_values(ann, prefix=key)
                continue
            widget = self._widgets.get(key)
            if widget is None:
                continue
            if isinstance(widget, QDoubleSpinBox):
                result[field_name] = widget.value()  # type: ignore
            elif isinstance(widget, SpinBox):
                result[field_name] = widget.value()
            elif isinstance(widget, LineEdit):
                result[field_name] = widget.text().strip()
            elif isinstance(widget, SwitchButton):
                result[field_name] = widget.isChecked()
        return result

    def _load(self) -> None:
        self._set_values(Live, Configuration.Get().live, prefix="")
        self._status.setText("")

    def _on_apply(self) -> None:
        from pydantic import ValidationError

        try:
            live = Live.model_validate(self._collect_values(Live, prefix=""))
        except ValidationError as e:
            self._status.setText(f"Invalid value: {e.errors()[0]['msg']}")
            QTimer.singleShot(5000, lambda: self._status.setText(""))
            return
        live.Save(self._filepath)
        self._status.setText("Saved — watcher will hot-reload.")
        QTimer.singleShot(3000, lambda: self._status.setText(""))
