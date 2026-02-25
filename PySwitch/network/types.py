from PySwitch.common import IntEnum, Optional, NamedTuple
from enum import IntFlag, StrEnum

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

class Ethernet2:
    # Reference: https://en.wikipedia.org/wiki/Ethernet_frame
    class EtherType(IntEnum):
        pass

    mac_destination: MAC # 6B
    mac_source: MAC # 6B
    tag: Optional[int] # 4B
    ether_type: int # 2B
    payload: memoryview # 42-1500B
    frame_check_sequence: int # 4B

class IP4_Header:
    # Reference::
    # https://en.wikipedia.org/wiki/IPv4
    # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    class Version(IntEnum):
        V4 = 4
    class Protocol(IntEnum):
        ICMP = 1
        IGMP = 2
        TCP = 6
        UDP = 17
        ENCAP = 4
        OSPF = 89
        SCTP = 132
    class Flags:
        reserved: bool
        dont_fragment: bool
        more_fragments: bool
    
    version: int # 4 bits
    ihl: int # 4 bits (Internet Header Length)
    dscp: int # 6 bits
    ecn: int # 2 bits
    total_length: int # 2B (entire packet size including header and data)
    identification: int # 2B
    flags: Flags # 3 bits - R-DF-MF -> Reserved, Don't Fragment, More Fragments
    fragment_offset: int # 13 bits (in 8-byte units)
    time_to_live: int # 1B
    protocol: Protocol # 1B
    header_checksum: int # 2B
    source: IPv4 # 4B
    destination: IPv4 # 4B
    options: memoryview # 0-320 bits, padded to multiple of 32bits
    payload: memoryview # the rest of the packet

class ARP:
    # Reference: https://en.wikipedia.org/wiki/Address_Resolution_Protocol
    class ProtocolType(IntEnum):
        IPv4 = 0x0800
    class Operation(IntEnum):
        Request = 1
        Reply = 2
    hardware_type: int # 2B (1 = Ethernet)
    protocol_type: ARP.ProtocolType # 2B (0x0800 = IPv4)
    hardware_length: int # 1B (6 for MAC)
    protocol_length: int # 1B (4 for IPv4)
    operation: ARP.Operation # 2B (1 = request, 2 = reply)
    sender_mac: MAC # 6B
    sender_ip: IPv4 # 4B
    target_mac: MAC # 6B
    target_ip: IPv4 # 4B

class UDP:
    # Reference: https://en.wikipedia.org/wiki/User_Datagram_Protocol
    source_port: int # 2B
    destination_port: int # 2b
    length: int # 2B
    checksum: int # 2B
    payload: memoryview # the rest

class TCP:
    # Reference: https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    class Flags(IntFlag):
        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        ECE = 0x40
        CWR = 0x80
    source_port: int # 2B
    destination_port: int # 2B
    sequence_number: int # 4B
    acknowledgement_number: int # 4B
    data_offset: int # 4 bits
    # reserved # 4bits - not needed
    flags: TCP.Flags
    window: int # 2B
    checksum: int # 2B
    urgent_pointer: int # 2B
    options: Optional[memoryview] # (Options) If present, Data Offset will be greater than 5. Padded with zeroes to a multiple of 32 bits, since Data Offset counts words of 4 octets.
    payload: memoryview

class ICMP:
    # Reference: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
    class Type(IntEnum):
        echo_reply = 0
        reserved_1 = 1
        reserved_2 = 2
        destination_unreachable = 3
        redirect_message = 5
        echo_request = 8
        router_advertisement = 9
        router_solicitation = 10
        time_exceeded = 11
        parameter_problem = 12
        timestamp = 13
        timestamp_reply = 14
        extended_echo_request = 42
        extended_echo_reply = 43
    
    type: ICMP.Type     # 1B
    code: int           # 1B
    checksum: int       # 2B
    data: memoryview    # 4B
    payload: memoryview # the rest of the header

class HTTP:
    # Reference: https://en.wikipedia.org/wiki/HTTP
    class Method(StrEnum):
        get = "GET"
        put = "PUT"
        head = "HEAD"
        post = "POST"
        trace = "TRACE"
        patch = "PATCH"
        delete = "DELETE"
        connect = "CONNECT"
        options = "OPTIONS"
    
    method: Optional[Method]
    payload: memoryview # includes payload

    # Precomputed once: encoded request method prefixes + response prefix
    _MAGIC: frozenset = frozenset(m.encode(encoding="ascii") for m in Method) | {b'HTTP/'}

    @staticmethod
    def ContainsMagic(view: memoryview) -> bool:
        if len(view) < 4:
            return False
        start = bytes(view[:8])
        return any(start.startswith(magic) for magic in HTTP._MAGIC)
