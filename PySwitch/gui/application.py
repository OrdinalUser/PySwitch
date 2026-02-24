import PySwitch.gui.subinterfaces as Subinterfaces

from PySide6.QtWidgets import QApplication

from qfluentwidgets import (
    FluentWindow,
    FluentIcon,
    setTheme,
    Theme
)

class Application(FluentWindow):
    def __init__(self):
        super().__init__()
        setTheme(Theme.AUTO)
        self.setWindowTitle("PySwitch")
        self.resize(960, 640)

        self.interfaces = Subinterfaces.Interfaces(self)
        self.sniffer    = Subinterfaces.PhysicalSniffer(self)
        self.logs       = Subinterfaces.Logs(self)
        self.mac_view   = Subinterfaces.MACTableView(self)

        self.addSubInterface(self.interfaces, FluentIcon.HOME,              "Interfaces")
        self.addSubInterface(self.sniffer,    FluentIcon.WIFI,              "NIC Sniffer")
        self.addSubInterface(self.logs,       FluentIcon.DEVELOPER_TOOLS,   "Logs")
        self.addSubInterface(self.mac_view,   FluentIcon.CALENDAR,          "MAC Table")

    @staticmethod
    def Run() -> int:
        import sys
        app = QApplication(sys.argv)
        window = Application()
        window.show()
        return app.exec()