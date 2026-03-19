"""
模块三：威胁检测引擎
- 规则检测：端口扫描、暴力破解、异常 DNS
- ARP 全类型检测（必选）
- 统计检测：突发大流量、周期性心跳
- AI 检测：随机森林 + DeepSeek LLM（选作/已实现）
"""

import time
from collections import defaultdict, deque
from datetime import datetime
from typing import List, Dict
import numpy as np


def make_alert(
    alert_type: str,
    severity: str,
    src_ip: str,
    description: str,
    evidence: dict = None,
    timestamp: float = None
) -> dict:
    return {
        "id": f"{int(time.time() * 1000)}_{alert_type}",
        "alert_type": alert_type,
        "severity": severity,
        "src_ip": src_ip,
        "description": description,
        "evidence": evidence or {},
        "timestamp": timestamp or time.time(),
        "datetime": datetime.now().isoformat(),
        "mitigated": False,
    }


class RuleBasedDetector:
    """经典规则检测：端口扫描、暴力破解、异常 DNS、ARP 全类型"""

    def __init__(self):
        self._port_scan_tracker: Dict[str, set] = defaultdict(set)
        self._brute_force_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._dns_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._arp_table: Dict[str, str] = {}
        self._arp_request_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._gratuitous_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        # 同一 IP 近期出现过的 (mac, ts)，用于检测「先见到的 reply 即欺骗」或「同 IP 多 MAC」
        self._arp_ip_mac_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        # 全局 ARP 包计数（泛洪多为随机 MAC，按源 MAC 计数会漏检）
        self._arp_global_timestamps: deque = deque(maxlen=2000)
        # 同一 MAC 在 reply 中声称的 IP 列表，用于检测 MITM（同一 MAC 声称多个 IP）
        self._arp_mac_claimed_ips: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))

        self.PORT_SCAN_THRESHOLD = 15
        self.BRUTE_FORCE_THRESHOLD = 20
        self.BRUTE_FORCE_WINDOW = 60
        self.DNS_QUERY_THRESHOLD = 50
        self.DNS_WINDOW = 60
        self.ARP_FLOOD_THRESHOLD = 100
        self.ARP_FLOOD_WINDOW = 10
        # 泛洪：任意源在窗口内 ARP 包总数（应对随机 MAC 的泛洪）
        self.ARP_FLOOD_GLOBAL_THRESHOLD = 50
        self.ARP_SCAN_THRESHOLD = 20
        self.ARP_SPOOF_SAME_IP_DIFF_MAC_WINDOW = 120  # 秒内同一 IP 出现不同 MAC 即可疑

    def detect(self, packets: List[dict]) -> List[dict]:
        alerts = []
        for pkt in packets:
            proto = pkt.get("protocol", "")
            if proto == "ARP":
                alerts.extend(self._check_arp(pkt))
            elif proto == "TCP":
                alerts.extend(self._check_port_scan(pkt))
                alerts.extend(self._check_brute_force(pkt))
            elif proto == "DNS":
                alerts.extend(self._check_dns(pkt))
        return alerts

    def _check_port_scan(self, pkt: dict) -> List[dict]:
        alerts = []
        src = pkt.get("src_ip")
        dst_port = pkt.get("dst_port")
        tcp_flags = pkt.get("tcp_flags", "")
        if src and dst_port and "S" in str(tcp_flags) and "A" not in str(tcp_flags):
            self._port_scan_tracker[src].add(dst_port)
            if len(self._port_scan_tracker[src]) >= self.PORT_SCAN_THRESHOLD:
                alerts.append(make_alert(
                    alert_type="PORT_SCAN",
                    severity="high",
                    src_ip=src,
                    description=f"检测到端口扫描：{src} 已探测 {len(self._port_scan_tracker[src])} 个端口",
                    evidence={"scanned_ports": list(self._port_scan_tracker[src])[:20]},
                    timestamp=pkt.get("timestamp")
                ))
                self._port_scan_tracker[src].clear()
        return alerts

    def _check_brute_force(self, pkt: dict) -> List[dict]:
        alerts = []
        src = pkt.get("src_ip")
        dst_port = pkt.get("dst_port")
        ts = pkt.get("timestamp", time.time())
        tcp_flags = str(pkt.get("tcp_flags", ""))
        if dst_port in (22, 21, 3389, 23, 445) and "S" in tcp_flags:
            tracker = self._brute_force_tracker[f"{src}:{dst_port}"]
            tracker.append(ts)
            while tracker and ts - tracker[0] > self.BRUTE_FORCE_WINDOW:
                tracker.popleft()
            if len(tracker) >= self.BRUTE_FORCE_THRESHOLD:
                service = {22: "SSH", 21: "FTP", 3389: "RDP", 23: "Telnet", 445: "SMB"}.get(dst_port, str(dst_port))
                alerts.append(make_alert(
                    alert_type="BRUTE_FORCE",
                    severity="critical",
                    src_ip=src,
                    description=f"检测到暴力破解：{src} 在 {self.BRUTE_FORCE_WINDOW}s 内对 {service} 发起 {len(tracker)} 次连接尝试",
                    evidence={"service": service, "attempt_count": len(tracker), "dst_port": dst_port},
                    timestamp=ts
                ))
                tracker.clear()
        return alerts

    def _check_dns(self, pkt: dict) -> List[dict]:
        alerts = []
        src = pkt.get("src_ip")
        ts = pkt.get("timestamp", time.time())
        dns_query = pkt.get("dns_query", "")
        if not src:
            return alerts
        tracker = self._dns_tracker[src]
        tracker.append(ts)
        while tracker and ts - tracker[0] > self.DNS_WINDOW:
            tracker.popleft()
        if len(tracker) >= self.DNS_QUERY_THRESHOLD:
            alerts.append(make_alert(
                alert_type="ABNORMAL_DNS",
                severity="medium",
                src_ip=src,
                description=f"异常 DNS：{src} 在 {self.DNS_WINDOW}s 内发起 {len(tracker)} 次 DNS 查询，疑似 DNS 隧道或 DGA",
                evidence={"query_count": len(tracker), "sample_query": dns_query},
                timestamp=ts
            ))
            tracker.clear()
        if dns_query and len(dns_query) > 60:
            alerts.append(make_alert(
                alert_type="DNS_TUNNEL",
                severity="high",
                src_ip=src,
                description=f"疑似 DNS 隧道：查询域名长度异常（{len(dns_query)} 字符）",
                evidence={"query": dns_query, "length": len(dns_query)},
                timestamp=ts
            ))
        return alerts

    def _check_arp(self, pkt: dict) -> List[dict]:
        alerts = []
        src_ip = pkt.get("src_ip", "")
        src_mac = pkt.get("src_mac", "")
        dst_ip = pkt.get("dst_ip", "")
        arp_op = pkt.get("arp_op", "")
        ts = pkt.get("timestamp", time.time())

        # ----- ARP Reply：欺骗与 MITM -----
        if src_ip and src_mac and arp_op == "reply":
            # 1) 经典欺骗：表中已有该 IP 且 MAC 变化
            if src_ip in self._arp_table:
                if self._arp_table[src_ip] != src_mac:
                    alerts.append(make_alert(
                        alert_type="ARP_SPOOFING",
                        severity="critical",
                        src_ip=src_ip,
                        description=f"ARP 欺骗：IP {src_ip} 的 MAC 映射从 {self._arp_table[src_ip]} 变更为 {src_mac}",
                        evidence={
                            "ip": src_ip,
                            "original_mac": self._arp_table[src_ip],
                            "new_mac": src_mac
                        },
                        timestamp=ts
                    ))
                    self._arp_ip_mac_history[src_ip].clear()
            else:
                self._arp_table[src_ip] = src_mac

            # 2) 同 IP 短时内出现不同 MAC（无需“先有正确绑定”）：首次抓到的 reply 也可能是欺骗
            history = self._arp_ip_mac_history[src_ip]
            history.append((src_mac, ts))
            while history and ts - history[0][1] > self.ARP_SPOOF_SAME_IP_DIFF_MAC_WINDOW:
                history.popleft()
            seen_macs = {m for m, _ in history}
            if len(seen_macs) >= 2:
                alerts.append(make_alert(
                    alert_type="ARP_SPOOFING",
                    severity="critical",
                    src_ip=src_ip,
                    description=f"ARP 欺骗：IP {src_ip} 在短时间内被多个 MAC 声称（{', '.join(seen_macs)}），疑似伪造 ARP",
                    evidence={"ip": src_ip, "claimed_macs": list(seen_macs)},
                    timestamp=ts
                ))
                history.clear()

            # 3) MITM：同一 MAC 在 reply 中声称多个不同 IP（典型中间人：攻击者 MAC 同时伪装成网关和受害机）
            mac_ips = self._arp_mac_claimed_ips[src_mac]
            mac_ips.append((src_ip, ts))
            while mac_ips and ts - mac_ips[0][1] > 60:
                mac_ips.popleft()
            claimed = list({ip for ip, _ in mac_ips})
            if len(claimed) >= 2:
                alerts.append(make_alert(
                    alert_type="ARP_MITM",
                    severity="critical",
                    src_ip=src_ip,
                    description=f"ARP 中间人：同一 MAC {src_mac} 声称多个 IP（{', '.join(claimed)}），疑似双向欺骗",
                    evidence={"attacker_mac": src_mac, "claimed_ips": claimed},
                    timestamp=ts
                ))
                mac_ips.clear()

        # ----- 泛洪：按 MAC 计数（同源大量） + 全局计数（随机 MAC 泛洪） -----
        self._arp_global_timestamps.append(ts)
        while self._arp_global_timestamps and ts - self._arp_global_timestamps[0] > self.ARP_FLOOD_WINDOW:
            self._arp_global_timestamps.popleft()
        if len(self._arp_global_timestamps) >= self.ARP_FLOOD_GLOBAL_THRESHOLD:
            alerts.append(make_alert(
                alert_type="ARP_FLOODING",
                severity="critical",
                src_ip=src_ip or "multiple",
                description=f"ARP 泛洪：在 {self.ARP_FLOOD_WINDOW}s 内共收到 {len(self._arp_global_timestamps)} 个 ARP 包，疑似泛洪攻击",
                evidence={"pkt_count": len(self._arp_global_timestamps), "window_sec": self.ARP_FLOOD_WINDOW},
                timestamp=ts
            ))
            self._arp_global_timestamps.clear()

        if src_mac:
            self._arp_request_tracker[src_mac].append(ts)
            tracker = self._arp_request_tracker[src_mac]
            while tracker and ts - tracker[0] > self.ARP_FLOOD_WINDOW:
                tracker.popleft()
            if len(tracker) >= self.ARP_FLOOD_THRESHOLD:
                alerts.append(make_alert(
                    alert_type="ARP_FLOODING",
                    severity="critical",
                    src_ip=src_ip,
                    description=f"ARP 泛洪：MAC {src_mac} 在 {self.ARP_FLOOD_WINDOW}s 内发送 {len(tracker)} 个 ARP 包",
                    evidence={"src_mac": src_mac, "pkt_count": len(tracker)},
                    timestamp=ts
                ))
                tracker.clear()

        # ----- 扫描：同源 IP 探测多目标 -----
        if arp_op == "request" and src_ip:
            scan_key = f"scan_{src_ip}"
            self._arp_request_tracker[scan_key].append(dst_ip)
            unique_targets = set(self._arp_request_tracker[scan_key])
            if len(unique_targets) >= self.ARP_SCAN_THRESHOLD:
                alerts.append(make_alert(
                    alert_type="ARP_SCANNING",
                    severity="high",
                    src_ip=src_ip,
                    description=f"ARP 扫描：{src_ip} 探测了 {len(unique_targets)} 个不同 IP 地址",
                    evidence={"target_count": len(unique_targets), "sample_targets": list(unique_targets)[:10]},
                    timestamp=ts
                ))
                self._arp_request_tracker[scan_key].clear()

        # ----- 无故 ARP 滥用 -----
        if src_ip and dst_ip and src_ip == dst_ip and arp_op == "request":
            self._gratuitous_tracker[src_ip].append(ts)
            while self._gratuitous_tracker[src_ip] and ts - self._gratuitous_tracker[src_ip][0] > 60:
                self._gratuitous_tracker[src_ip].popleft()
            count = len(self._gratuitous_tracker[src_ip])
            if count >= 5:
                alerts.append(make_alert(
                    alert_type="GRATUITOUS_ARP_ABUSE",
                    severity="medium",
                    src_ip=src_ip,
                    description=f"无故 ARP 滥用：{src_ip} 在 60s 内发送 {count} 次 Gratuitous ARP，疑似 ARP 缓存投毒",
                    evidence={"ip": src_ip, "count": count},
                    timestamp=ts
                ))
        return alerts


class StatisticalDetector:
    """基于阈值和基线的统计异常检测"""

    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self._traffic_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self._baseline: Dict[str, float] = {}
        self.BURST_MULTIPLIER = 5.0
        self.HEARTBEAT_INTERVAL_TOLERANCE = 0.1

    def detect(self, packets: List[dict]) -> List[dict]:
        alerts = []
        ip_packets: Dict[str, list] = defaultdict(list)
        for pkt in packets:
            ip = pkt.get("src_ip")
            if ip:
                ip_packets[ip].append(pkt)
        for src_ip, pkts in ip_packets.items():
            alerts.extend(self._check_burst(src_ip, pkts))
            alerts.extend(self._check_heartbeat(src_ip, pkts))
        return alerts

    def _check_burst(self, src_ip: str, packets: list) -> List[dict]:
        alerts = []
        total_bytes = sum(pkt.get("pkt_len", 0) for pkt in packets)
        if src_ip in self._baseline:
            self._baseline[src_ip] = 0.9 * self._baseline[src_ip] + 0.1 * total_bytes
            if total_bytes > self._baseline[src_ip] * self.BURST_MULTIPLIER and total_bytes > 10000:
                alerts.append(make_alert(
                    alert_type="TRAFFIC_BURST",
                    severity="medium",
                    src_ip=src_ip,
                    description=f"突发大流量：{src_ip} 当前流量 {total_bytes} bytes，超过基线 {self._baseline[src_ip]:.0f} 的 {self.BURST_MULTIPLIER} 倍",
                    evidence={"current_bytes": total_bytes, "baseline": self._baseline[src_ip]},
                ))
        else:
            self._baseline[src_ip] = float(total_bytes)
        return alerts

    def _check_heartbeat(self, src_ip: str, packets: list) -> List[dict]:
        alerts = []
        if len(packets) < 10:
            return alerts
        timestamps = sorted([pkt.get("timestamp", 0) for pkt in packets])
        intervals = np.diff(timestamps)
        if len(intervals) < 5:
            return alerts
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        cv = std_interval / mean_interval if mean_interval > 0 else 1.0
        if cv < self.HEARTBEAT_INTERVAL_TOLERANCE and 0.5 < mean_interval < 300:
            alerts.append(make_alert(
                alert_type="PERIODIC_HEARTBEAT",
                severity="high",
                src_ip=src_ip,
                description=f"疑似 C&C 心跳包：{src_ip} 每 {mean_interval:.2f}s 发送一次数据包（变异系数 {cv:.4f}），疑似僵尸网络心跳",
                evidence={
                    "mean_interval_sec": round(mean_interval, 3),
                    "std_interval_sec": round(std_interval, 3),
                    "coefficient_of_variation": round(cv, 4),
                    "packet_count": len(packets)
                }
            ))
        return alerts
