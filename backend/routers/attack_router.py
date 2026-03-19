from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from pathlib import Path

from core.attack_runner import run_attack
from core.attack_log import get_logs

router = APIRouter()

_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_ATTACKS_DIR = _BASE_DIR / "data" / "logs" / "attacks"


class RunAttackRequest(BaseModel):
    attack_type: str  # arp_spoof | arp_flood | arp_scan | gratuitous_arp | arp_mitm
    params: Dict[str, Any] = {}
    real_send: bool = False
    iface: str = "eth0"


@router.post("/run")
def run_attack_endpoint(req: RunAttackRequest):
    """执行一次攻击（默认仅模拟并写 pcap，real_send=True 时真实发包，需 root）"""
    try:
        record = run_attack(
            attack_type=req.attack_type,
            params=req.params,
            real_send=req.real_send,
            iface=req.iface,
        )
        return record
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logs")
def attack_logs(limit: int = 50):
    """获取攻击记录列表"""
    return {"logs": get_logs(limit=limit)}


@router.get("/pcap/{filename}")
def download_pcap(filename: str):
    """下载某次攻击生成的 pcap 文件"""
    path = _ATTACKS_DIR / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="文件不存在")
    return FileResponse(path, filename=filename, media_type="application/vnd.tcpdump.pcap")
