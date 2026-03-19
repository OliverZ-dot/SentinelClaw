"""
模块四：AI 智能分析中心（业务入口）
实际实现见 agents/threat_agent.py
"""
from agents.threat_agent import (
    build_threat_agent,
    reconstruct_attack_chain,
    generate_security_report,
    update_alert_store,
)

__all__ = [
    "build_threat_agent",
    "reconstruct_attack_chain",
    "generate_security_report",
    "update_alert_store",
]
