import ctypes
import socket
import struct

from PySwitch.network.types import MAC, IPv4, Ethernet2, IP4, UDP


def resolve_dns(hostname: str) -> str:
    """Resolves a hostname to an IPv4 address string using the OS resolver."""
    return socket.gethostbyname(hostname)


def resolve_arp(dst_ip: str, src_ip: str = "") -> bytes:
    """Resolves the MAC address for dst_ip via Windows SendARP. Returns 6 bytes or raises OSError."""
    iphlpapi = ctypes.windll.iphlpapi  # type: ignore
    mac_buf = (ctypes.c_ubyte * 6)()
    buf_len = ctypes.c_ulong(6)
    dst_dword = struct.unpack('<I', socket.inet_aton(dst_ip))[0]
    src_dword = struct.unpack('<I', socket.inet_aton(src_ip))[0] if src_ip else 0
    rc = iphlpapi.SendARP(dst_dword, src_dword, mac_buf, ctypes.byref(buf_len))
    if rc != 0:
        raise OSError(f"SendARP failed: error code {rc}")
    return bytes(mac_buf)


def build_udp_frame(
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    ttl: int = 64,
) -> bytes:
    """Builds a complete Ethernet II / IPv4 / UDP frame and returns raw bytes."""
    udp = UDP()
    udp.source_port = src_port
    udp.destination_port = dst_port
    udp_bytes = udp.to_bytes(payload)

    ip = IP4()
    ip.time_to_live = ttl
    ip.protocol = IP4.Protocol.UDP
    ip.source = IPv4.from_str(src_ip)
    ip.destination = IPv4.from_str(dst_ip)
    ip_bytes = ip.to_bytes(udp_bytes)

    eth = Ethernet2()
    eth.mac_destination = MAC()
    eth.mac_destination.data = dst_mac[:6]
    eth.mac_source = MAC()
    eth.mac_source.data = src_mac[:6]
    eth.ether_type = 0x0800
    return eth.to_bytes(ip_bytes)
