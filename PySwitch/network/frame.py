from PySwitch.common import Dict, StrEnum, Any, Optional, Callable, TypeAlias, Tuple, Cast, OrderedDict, Protocol, runtime_checkable
from PySwitch.network.types import MAC, IPv4, Ethernet2, IP4_Header, ARP, UDP, TCP, ICMP, HTTP
import struct

class Protocols(StrEnum):
    Ethernet2 = "Ethernet2"
    IPv4 = "IPv4"
    Arp = "ARP"
    Udp = "UDP"
    Tcp = "TCP"
    Icmp = "ICMP"
    Http = "HTTP"

# LayerParseFunc takes in the entire "current" layer data
# returns the parsed header, encapsulated layer type and memory view if any
LayerParseReturn: TypeAlias = Tuple[Any, Optional[Tuple[Protocols, memoryview]]]
LayerParseFunc: TypeAlias = Callable[[memoryview], LayerParseReturn]

@runtime_checkable
class ProtocolParserEntry(Protocol):
    @staticmethod
    def parse(data: memoryview) -> Tuple[Any, Optional[Tuple[Protocols, memoryview]]]: ...

class ProtocolParser:
    _registered: Dict[Protocols, LayerParseFunc] = dict()
    def __init_subclass__(cls, protocol: Protocols) -> None:
        assert protocol not in ProtocolParser._registered
        assert isinstance(cls, ProtocolParserEntry)
        assert callable(cls.parse)
        ProtocolParser._registered[protocol] = cls.parse

    @classmethod
    def dispatch(cls, data: memoryview, protocol: Protocols) -> Tuple[Any, Optional[Tuple[Protocols, memoryview]]]:
        if parser_fn := cls._registered.get(protocol, None):
            return parser_fn(data)
        else:
            raise ValueError(f"Attempting to parse unregistered protocol {protocol.value}={protocol.name}")

# === L2 Parsing =============
class Ethernet2Parser(ProtocolParser, protocol=Protocols.Ethernet2):
    _ETH_ETHERTYPE_TO_PROTOCOLS: Dict[int, Protocols] = {
        0x0800: Protocols.IPv4,
        0x0806: Protocols.Arp
    }
    _ETH_STRUCT = struct.Struct('!6s6sH')  # dst, src, type_or_tpid
    _VLAN_TPID  = 0x8100
    @staticmethod
    def parse(data: memoryview) -> Tuple[Any, Optional[Tuple[Protocols, memoryview]]]:
        dst_b, src_b, type_or_tpid = Ethernet2Parser._ETH_STRUCT.unpack_from(data)
        
        eth = Ethernet2()
        mac_dst = MAC(); mac_dst.data = dst_b
        mac_src = MAC(); mac_src.data = src_b
        eth.mac_destination = mac_dst
        eth.mac_source = mac_src

        if type_or_tpid == Ethernet2Parser._VLAN_TPID:
            # 802.1Q tag present: [TCI 2B][EtherType 2B] follow
            tci, ether_type = struct.unpack_from('!HH', data, 14)
            eth.tag        = tci & 0x0FFF  # bottom 12 bits = VLAN ID
            eth.ether_type = ether_type
            eth.payload    = data[18:] # normally, we would cut off another 4 bytes for frame check sequence..
        else:
            eth.tag        = None
            eth.ether_type = type_or_tpid
            eth.payload    = data[14:] # normally, we would cut off another 4 bytes for frame check sequence..

        eth.frame_check_sequence = 0 # seems to be unsupported for software solutions
        # eth.frame_check_sequence = struct.unpack_from('!I', data, len(data) - 4)[0]

        if eth.ether_type in Ethernet2Parser._ETH_ETHERTYPE_TO_PROTOCOLS:
            return (eth, (Ethernet2Parser._ETH_ETHERTYPE_TO_PROTOCOLS[eth.ether_type], eth.payload))
        else:
            return (eth, None)

# === L2.5 Parsing =============
class ArpParser(ProtocolParser, protocol=Protocols.Arp):
    _ARP_STRUCT = struct.Struct('!HHBBH6s4s6s4s')

    @staticmethod
    def parse(data: memoryview) -> Tuple[Any, Optional[Tuple[Protocols, memoryview]]]:
        hw_type, proto_type, hw_len, proto_len, operation, sender_mac, sender_ip, target_mac, target_ip = ArpParser._ARP_STRUCT.unpack_from(data)
        
        arp = ARP()
        arp.hardware_type = hw_type
        arp.protocol_type = ARP.ProtocolType(proto_type)
        arp.hardware_length = hw_len
        arp.protocol_length = proto_len
        arp.operation = ARP.Operation(operation)
        arp.sender_mac = MAC() ; arp.sender_mac.data = sender_mac
        arp.sender_ip = IPv4.from_bytes(sender_ip)
        arp.target_mac = MAC() ; arp.target_mac.data = target_mac
        arp.target_ip = IPv4.from_bytes(target_ip)
        
        return (arp, None)  # ARP has no nested protocol

# === L3 Parsing =============
class IPv4Parser(ProtocolParser, protocol=Protocols.IPv4):
    _IP4_PROTOCOL_TO_PROTOCOLS: Dict[IP4_Header.Protocol, Protocols] = {
        IP4_Header.Protocol.UDP: Protocols.Udp,
        IP4_Header.Protocol.TCP: Protocols.Tcp,
        IP4_Header.Protocol.ICMP: Protocols.Icmp
    }
    _IP_STRUCT = struct.Struct("!BBHHHBBH4s4s")

    @staticmethod
    def parse(data: memoryview) -> Tuple[IP4_Header, Optional[Tuple[Protocols, memoryview]]]:
        ver_ihl, dscp_ecn, total_length, identification, flags_fragment_offset, ttl, protocol, checksum, src, dest = IPv4Parser._IP_STRUCT.unpack_from(data)
        
        # Extract version (upper 4 bits) and IHL (lower 4 bits)
        ip4_version = (ver_ihl >> 4) & 0x0f
        ip4_ihl = ver_ihl & 0x0f
        
        # Extract DSCP (upper 6 bits) and ECN (lower 2 bits) from dscp_ecn byte
        ip4_dscp = (dscp_ecn >> 2) & 0x3f
        ip4_ecn = dscp_ecn & 0x03
        
        # Extract flags and fragment offset from 2-byte field
        # Bit 15: Reserved, Bit 14: DF, Bit 13: MF, Bits 12-0: Fragment Offset
        ip4_reserved = bool(flags_fragment_offset & 0x8000)
        ip4_df = bool(flags_fragment_offset & 0x4000)
        ip4_mf = bool(flags_fragment_offset & 0x2000)
        ip4_frag_offset = flags_fragment_offset & 0x1fff
        
        # Calculate header size from IHL (IHL is in 32-bit words, so multiply by 4)
        ip_header_size = ip4_ihl * 4
        
        ip4 = IP4_Header()
        ip4.version = ip4_version
        ip4.ihl = ip4_ihl
        ip4.dscp = ip4_dscp
        ip4.ecn = ip4_ecn
        ip4.total_length = total_length
        ip4.identification = identification
        ip4.flags = IP4_Header.Flags()
        ip4.flags.reserved = ip4_reserved
        ip4.flags.dont_fragment = ip4_df
        ip4.flags.more_fragments = ip4_mf
        ip4.fragment_offset = ip4_frag_offset
        ip4.time_to_live = ttl
        ip4.protocol = IP4_Header.Protocol(protocol)
        ip4.header_checksum = checksum
        ip4.source = IPv4.from_bytes(src)
        ip4.destination = IPv4.from_bytes(dest)
        
        # Extract options and payload using actual IHL-calculated header size
        if ip_header_size > 20:
            ip4.options = data[20:ip_header_size]
            ip4.payload = data[ip_header_size:]
        else:
            ip4.options = memoryview(b'')
            ip4.payload = data[20:]
        
        if ip4.protocol in IPv4Parser._IP4_PROTOCOL_TO_PROTOCOLS:
            return (ip4, (IPv4Parser._IP4_PROTOCOL_TO_PROTOCOLS[ip4.protocol], ip4.payload))
        else:
            return (ip4, None)

# === L4 Parsing =============
class UdpParser(ProtocolParser, protocol=Protocols.Udp):
    _UDP_STRUCT = struct.Struct("!HHHH")
    _UDP_PORT_TO_PROTOCOL: Dict[int, Protocols] = {
        # empty for now
    }
    @staticmethod
    def parse(data: memoryview) -> Tuple[UDP, Optional[Tuple[Protocols, memoryview]]]:
        udp = UDP()
        udp.source_port, udp.destination_port, udp.length, udp.checksum = UdpParser._UDP_STRUCT.unpack_from(data)
        udp.payload = data[16:]
        # um.. there is no protocol field.. huh, we gotta blindly trust port numbers..
        if udp.destination_port in UdpParser._UDP_PORT_TO_PROTOCOL:
            return (udp, (UdpParser._UDP_PORT_TO_PROTOCOL[udp.source_port], udp.payload))
        return (udp, None)

class TcpParser(ProtocolParser, protocol=Protocols.Tcp):
    _TCP_STRUCT1 = struct.Struct("!HHLL")
    _TCP_STRUCT2 = struct.Struct("!BBHHH")
    @staticmethod
    def parse(data: memoryview) -> Tuple[TCP, Optional[Tuple[Protocols, memoryview]]]:
        tcp = TCP()
        tcp.source_port, tcp.destination_port, tcp.sequence_number, tcp.acknowledgement_number = TcpParser._TCP_STRUCT1.unpack_from(data, 0)
        
        dataoffset_reserved, flags, tcp.window, tcp.checksum, tcp.urgent_pointer = TcpParser._TCP_STRUCT2.unpack_from(data, 12)
        data_offset = (dataoffset_reserved >> 4) & 0x0f
        tcp.data_offset = data_offset
        tcp.flags = TCP.Flags(flags)
        
        header_size = data_offset * 4
        tcp.options = data[20:header_size]
        tcp.payload = data[header_size:]
        
        if HTTP.ContainsMagic(tcp.payload):
            return (tcp, (Protocols.Http, tcp.payload))
        
        return (tcp, None)

class IcmpParser(ProtocolParser, protocol=Protocols.Icmp):
    _ICMP_STRUCT = struct.Struct("!BBH")
    @staticmethod
    def parse(data: memoryview) -> Tuple[ICMP, Optional[Tuple[Protocols, memoryview]]]:
        icmp = ICMP()
        icmp_type, icmp.code, icmp.checksum = IcmpParser._ICMP_STRUCT.unpack_from(data)
        icmp.type = ICMP.Type(icmp_type)
        icmp.data = data[4:8]
        icmp.payload = data[8:]
        
        return (icmp, None)

class HttpParser(ProtocolParser, protocol=Protocols.Http):
    @staticmethod
    def parse(data: memoryview) -> Tuple[HTTP, Optional[Tuple[Protocols, memoryview]]]:
        http = HTTP()
        first_word = data[:8].tobytes().split(b' ', 1)[0].decode('ascii', errors='replace')
        try:
            http.method = HTTP.Method(first_word)
        except ValueError:
            http.method = None  # response frame (HTTP/1.1 200 OK etc.)
        http.payload = data
        return (http, None)

# Full parsing wrapper
class Frame:
    """Parses network frames"""
    data: memoryview
    protocol_stack: OrderedDict[Protocols, Any]
    
    # === Intended way of creation, straight from bytes
    @classmethod
    def from_bytes(cls, frame_data: bytes) -> Frame:
        frame = Frame(memoryview(frame_data), OrderedDict())
        frame._parse()
        return frame
    
    # === Object creation wrapper, do not use
    def __init__(self, data: memoryview, protocol_stack: OrderedDict[Protocols, Any]):
        self.data = data
        self.protocol_stack = protocol_stack
    
    # === Parsing nonsense ===
    def _parse(self) -> None:
        # Read L2
        eth, next_proto_data = Cast(Tuple[Ethernet2, Optional[Tuple[Protocols, memoryview]]], ProtocolParser.dispatch(self.data, Protocols.Ethernet2))
        self._add_protocol(Protocols.Ethernet2, eth)
        while next_proto_data is not None:
            next_proto_type, next_proto_payload = next_proto_data
            try:
                this_header, next_proto = ProtocolParser.dispatch(next_proto_payload, next_proto_type)
                next_proto_data = next_proto
                self._add_protocol(next_proto_type, this_header)
            except Exception as e:
                next_proto_data = None
                raise e
    
    def _add_protocol(self, protocol: Protocols, parsed_header: Any) -> None:
        assert protocol not in self.protocol_stack
        self.protocol_stack[protocol] = parsed_header
    
    # === Common read-only getters ===
    @property
    def ethernet2(self) -> Optional[Ethernet2]:
        return self.protocol_stack.get(Protocols.Ethernet2, None)
    
    @property
    def arp(self):
        return self.protocol_stack.get(Protocols.Arp, None)
    
    @property
    def ipv4(self) -> Optional[IP4_Header]:
        return self.protocol_stack.get(Protocols.IPv4, None)
    
    @property
    def udp(self) -> Optional[UDP]:
        return self.protocol_stack.get(Protocols.Udp, None)
    
    @property
    def tcp(self) -> Optional[TCP]:
        return self.protocol_stack.get(Protocols.Tcp, None)
    
    @property
    def icmp(self) -> Optional[ICMP]:
        return self.protocol_stack.get(Protocols.Icmp, None)
    
    # === Default overrides for QoL
    def __iter__(self):
        return iter(self.protocol_stack.items())
    
    def __contains__(self, item):
        return item in self.protocol_stack
    
    def __len__(self):
        return len(self.data)
