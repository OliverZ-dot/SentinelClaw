"""态势大屏聚合数据：告警、攻击记录、抓包状态等"""
from fastapi import APIRouter
from core.attack_log import get_logs
from core.capture import is_live_capturing
from agents.threat_agent import get_recent_alerts_list

router = APIRouter()


@router.get("/overview")
def dashboard_overview(alert_limit: int = 100, attack_limit: int = 50):
    """一次获取大屏所需：最近告警、攻击记录、抓包状态及统计"""
    alerts = get_recent_alerts_list(limit=alert_limit)
    logs = get_logs(limit=attack_limit)
    critical_count = sum(1 for a in alerts if a.get("severity") == "critical")
    high_count = sum(1 for a in alerts if a.get("severity") == "high")
    return {
        "alerts": alerts,
        "attack_logs": logs,
        "capturing": is_live_capturing(),
        "stats": {
            "alerts_total": len(alerts),
            "alerts_critical": critical_count,
            "alerts_high": high_count,
            "attacks_total": len(logs),
        },
    }
