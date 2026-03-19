"""
模块一：流量采集与解析
- 支持 PCAP 文件离线分析
- 支持实时网卡抓包（需 root/sudo）
- 深度解析 TCP/UDP/HTTP/DNS 协议
- 提取五元组、包长、时间间隔、Payload 特征
- 输出结构化 JSON 日志
"""

import json
import asyncio
import threading
from pathlib import Path
from scapy.all import (
    sniff, rdpcap, IP, TCP, UDP, DNS,
    Raw, ARP, Ether,
)
from datetime import datetime

try:
    from scapy.layers.http import HTTPRequest
except Exception:
    HTTPRequest = None

# 手动开始/停止抓包（无时长限制）
_live_stop_event = threading.Event()
_live_capture_thread = None
_live_capture_result = []
_live_capture_interface = None


def parse_packet(pkt, pkt_index: int = 0) -> dict | None:
    """将单个 Scapy 数据包解析为结构化字典"""
    if not pkt.haslayer(IP):
        if pkt.haslayer(ARP):
            return parse_arp_packet(pkt, pkt_index)
        return None

    record = {
        "index": pkt_index,
        "timestamp": float(pkt.time),
        "datetime": datetime.fromtimestamp(float(pkt.time)).isoformat(),
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "protocol": "unknown",
        "src_port": None,
        "dst_port": None,
        "pkt_len": len(pkt),
        "ttl": pkt[IP].ttl,
        "ip_flags": str(pkt[IP].flags),
        "payload_hex": None,
        "payload_len": 0,
        "payload_entropy": 0.0,
        "http_method": None,
        "http_host": None,
        "http_uri": None,
        "dns_query": None,
        "dns_response": None,
        "tcp_flags": None,
    }

    if pkt.haslayer(TCP):
        record["protocol"] = "TCP"
        record["src_port"] = pkt[TCP].sport
        record["dst_port"] = pkt[TCP].dport
        record["tcp_flags"] = str(pkt[TCP].flags)
        if HTTPRequest and pkt.haslayer(HTTPRequest):
            record["protocol"] = "HTTP"
            req = pkt[HTTPRequest]
            record["http_method"] = req.Method.decode() if req.Method else None
            record["http_host"] = req.Host.decode() if req.Host else None
            record["http_uri"] = req.Path.decode() if req.Path else None

    elif pkt.haslayer(UDP):
        record["protocol"] = "UDP"
        record["src_port"] = pkt[UDP].sport
        record["dst_port"] = pkt[UDP].dport
        if pkt.haslayer(DNS):
            record["protocol"] = "DNS"
            dns = pkt[DNS]
            if dns.qd:
                record["dns_query"] = dns.qd.qname.decode() if dns.qd.qname else None
            if dns.an:
                answers = []
                rr = dns.an
                while rr:
                    if hasattr(rr, "rdata"):
                        answers.append(str(rr.rdata))
                    rr = rr.payload if hasattr(rr, "payload") and rr.payload else None
                record["dns_response"] = answers

    if pkt.haslayer(Raw):
        raw_data = bytes(pkt[Raw])
        record["payload_len"] = len(raw_data)
        record["payload_hex"] = raw_data[:64].hex()
        record["payload_entropy"] = compute_entropy(raw_data)

    return record


def parse_arp_packet(pkt, pkt_index: int) -> dict:
    """ARP 包专用解析"""
    arp = pkt[ARP]
    return {
        "index": pkt_index,
        "timestamp": float(pkt.time),
        "datetime": datetime.fromtimestamp(float(pkt.time)).isoformat(),
        "protocol": "ARP",
        "src_ip": arp.psrc,
        "dst_ip": arp.pdst,
        "src_mac": arp.hwsrc,
        "dst_mac": arp.hwdst,
        "arp_op": "request" if arp.op == 1 else "reply",
        "pkt_len": len(pkt),
        "src_port": None,
        "dst_port": None,
    }


def compute_entropy(data: bytes) -> float:
    """计算字节序列的香农熵"""
    import math
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / len(data)
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def analyze_pcap(file_path: str) -> list:
    """离线 PCAP 文件分析"""
    packets = rdpcap(file_path)
    results = []
    for i, pkt in enumerate(packets):
        parsed = parse_packet(pkt, i)
        if parsed:
            results.append(parsed)
    return results


async def capture_live(
    interface: str,
    duration: int = 10,
    packet_count: int = 100
) -> list:
    """实时网卡抓包（需在 WSL 中以 sudo 运行后端）"""
    loop = asyncio.get_event_loop()
    packets = await loop.run_in_executor(
        None,
        lambda: sniff(iface=interface, timeout=duration, count=packet_count)
    )
    results = []
    for i, pkt in enumerate(packets):
        parsed = parse_packet(pkt, i)
        if parsed:
            results.append(parsed)
    return results


def start_live_capture(interface: str) -> tuple:
    """开始后台抓包（无时长限制），由用户手动停止。返回 (success: bool, message: str)。"""
    global _live_capture_thread, _live_capture_result, _live_capture_interface
    if _live_capture_thread is not None and _live_capture_thread.is_alive():
        return False, "已在抓包中，请先停止"
    _live_stop_event.clear()
    _live_capture_result = []
    _live_capture_interface = interface

    def _run():
        global _live_capture_result
        try:
            def _on_packet(pkt):
                idx = len(_live_capture_result)
                parsed = parse_packet(pkt, idx)
                if parsed:
                    _live_capture_result.append(parsed)

            sniff(
                iface=interface,
                store=False,
                prn=_on_packet,
                stop_filter=lambda _: _live_stop_event.is_set(),
            )
        except Exception:
            pass

    _live_capture_thread = threading.Thread(target=_run, daemon=True)
    _live_capture_thread.start()
    return True, "已开始抓包，点击「停止并检测」结束"


def stop_live_capture() -> tuple:
    """停止后台抓包并返回已解析的数据包。返回 (packets: list, message: str)。"""
    global _live_capture_thread, _live_capture_result
    if _live_capture_thread is None or not _live_capture_thread.is_alive():
        return [], "当前未在抓包"
    _live_stop_event.set()
    _live_capture_thread.join(timeout=10)
    _live_capture_thread = None
    result = list(_live_capture_result)
    _live_capture_result = []
    return result, "已停止抓包"


def is_live_capturing() -> bool:
    """当前是否正在后台抓包"""
    return _live_capture_thread is not None and _live_capture_thread.is_alive()


def get_live_capture_packets() -> list:
    """获取当前已抓取的包副本（抓包进行中时可调用，用于实时检测预览）。"""
    return list(_live_capture_result)


def save_json_log(records: list, output_path: str):
    """输出结构化 JSON 日志"""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
