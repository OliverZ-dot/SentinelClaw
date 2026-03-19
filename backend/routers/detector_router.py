from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
from core.detector import RuleBasedDetector, StatisticalDetector
from core.capture import (
    capture_live,
    start_live_capture,
    stop_live_capture,
    is_live_capturing,
    get_live_capture_packets,
)
import asyncio

router = APIRouter()
_rule_detector = RuleBasedDetector()
_stat_detector = StatisticalDetector()


class DetectRequest(BaseModel):
    packets: List[dict]


@router.post("/analyze")
def detect_threats(req: DetectRequest):
    rule_alerts = _rule_detector.detect(req.packets)
    stat_alerts = _stat_detector.detect(req.packets)
    all_alerts = rule_alerts + stat_alerts
    return {
        "total_alerts": len(all_alerts),
        "rule_alerts": len(rule_alerts),
        "stat_alerts": len(stat_alerts),
        "alerts": all_alerts
    }


@router.get("/live")
async def live_capture_and_detect(interface: str = "eth0", duration: int = 5):
    """
    自动抓包并检测（固定时长）：对当前网络进行指定时长抓包，并立即运行威胁检测。
    若无时长限制、需手动启停，请使用 POST /live/start 与 POST /live/stop。
    """
    try:
        packets = await capture_live(interface, duration=duration, packet_count=2000)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"抓包失败（可能需要 sudo）: {str(e)}")
    rule_alerts = _rule_detector.detect(packets)
    stat_alerts = _stat_detector.detect(packets)
    all_alerts = rule_alerts + stat_alerts
    return {
        "packets_count": len(packets),
        "packets": packets[:500],
        "total_alerts": len(all_alerts),
        "rule_alerts": len(rule_alerts),
        "stat_alerts": len(stat_alerts),
        "alerts": all_alerts,
    }


@router.post("/live/start")
def live_capture_start(interface: str = "eth0"):
    """开始后台抓包（无时长限制），由用户手动调用 /live/stop 停止。"""
    ok, msg = start_live_capture(interface)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"ok": True, "message": msg, "capturing": True}


@router.post("/live/stop")
def live_capture_stop():
    """停止后台抓包，对已抓取的包运行威胁检测并返回结果。"""
    if not is_live_capturing():
        raise HTTPException(status_code=400, detail="当前未在抓包")
    packets, msg = stop_live_capture()
    rule_alerts = _rule_detector.detect(packets)
    stat_alerts = _stat_detector.detect(packets)
    all_alerts = rule_alerts + stat_alerts
    return {
        "packets_count": len(packets),
        "packets": packets[:500],
        "total_alerts": len(all_alerts),
        "rule_alerts": len(rule_alerts),
        "stat_alerts": len(stat_alerts),
        "alerts": all_alerts,
        "message": msg,
    }


@router.get("/live/status")
def live_capture_status():
    """查询当前是否正在后台抓包。"""
    return {"capturing": is_live_capturing()}


@router.get("/live/current-alerts")
def live_current_alerts():
    """
    抓包进行中时，对当前已抓取的包做一次检测并返回告警，供前端实时更新告警时间线。
    未在抓包时返回空告警。
    """
    if not is_live_capturing():
        return {"alerts": [], "packets_count": 0}
    packets = get_live_capture_packets()
    if not packets:
        return {"alerts": [], "packets_count": 0}
    rule_d = RuleBasedDetector()
    stat_d = StatisticalDetector()
    rule_alerts = rule_d.detect(packets)
    stat_alerts = stat_d.detect(packets)
    all_alerts = rule_alerts + stat_alerts
    return {"alerts": all_alerts, "packets_count": len(packets)}
