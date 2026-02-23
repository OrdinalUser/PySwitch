from PySwitch.common import StrEnum, IntEnum, ClassVar
import struct

class MAC:
    data: bytes
    
    def __hash__(self) -> int:
        return int.from_bytes(self.data)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, MAC) and self.data == other.data

    def __str__(self) -> str:
        return self.to_str()

    def __repr__(self) -> str:
        return self.to_str()

    def to_str(self, delim: str = ':') -> str:
        return delim.join([f"{octet:02x}" for octet in self.data[:6]])
    
    @classmethod
    def from_str(cls, mac_address: str, delim: str = ':') -> MAC:
        mac = cls()
        mac.data = bytes([int(octet, 16) for octet in mac_address.split(delim)])[:6]
        return mac
    
    @classmethod
    def from_bytes(cls, mac_address: bytes) -> MAC:
        mac = cls()
        mac.data = bytes(list(reversed(mac_address))[:6])
        return mac
    
    @property
    def is_broadcast(self) -> bool:
        return hash(self) == _broadcast_hash

_broadcast_hash = hash(MAC.from_str('ff:ff:ff:ff:ff:ff'))

class IPv4:
    data: bytes
    
    def __hash__(self) -> int:
        return int.from_bytes(self.data)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, IPv4) and self.data == other.data

    def __str__(self) -> str:
        return self.to_str()

    def __repr__(self) -> str:
        return self.to_str()

    def to_str(self) -> str:
        return ".".join([f"{octet:}" for octet in self.data[:4]])
    
    @classmethod
    def from_str(cls, ip_address: str) -> IPv4:
        ip = cls()
        ip.data = bytes([int(octet) for octet in ip_address.split(".")])[:4]
        return ip
    
    @classmethod
    def from_bytes(cls, ip_address: bytes) -> IPv4:
        ip = cls()
        ip.data = ip_address[:4]
        return ip

# this will probably need to work differently later
class Protocols(StrEnum):
    UDP = "UDP"
    TCP = "TCP"

class Frame:
    data: bytes

    def __init__(self, data: bytes):
        self.data = data
    
    def GetMacSourceAddress(self) -> MAC:
        return MAC()

_ETH_STRUCT = struct.Struct('!6s6sIH')

class Ethernet2:
    class EtherType(IntEnum):
        pass

    # According to https://en.wikipedia.org/wiki/Ethernet_frame
    mac_destination: MAC # 6B
    mac_source: MAC # 6B
    tag: int # 4B
    ether_type: int # 2B
    payload: bytes # 42-1500B
    frame_check_sequence: int #4B

    @classmethod
    def from_frame(cls, frame: Frame) -> Ethernet2:
        mv = memoryview(frame.data)
        dst_b, src_b, tag, ether_type = _ETH_STRUCT.unpack_from(mv)

        mac_dst = MAC(); mac_dst.data = dst_b
        mac_src = MAC(); mac_src.data = src_b

        eth = cls()
        eth.mac_destination = mac_dst
        eth.mac_source = mac_src
        eth.tag = tag
        eth.ether_type = ether_type
        eth.payload = bytes(mv[18:-4])
        eth.frame_check_sequence = struct.unpack_from('!I', mv, len(mv) - 4)[0]
        return eth
    