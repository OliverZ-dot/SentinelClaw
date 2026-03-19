"""Pydantic 数据模型（API 请求/响应）"""
from pydantic import BaseModel
from typing import List, Optional, Any


class PacketRecord(BaseModel):
    """流量解析后的单条记录"""
    index: int
    timestamp: float
    datetime: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    pkt_len: int
    ttl: Optional[int] = None
    payload_len: Optional[int] = 0
    payload_entropy: Optional[float] = None


class AlertRecord(BaseModel):
    """威胁告警记录"""
    id: str
    alert_type: str
    severity: str
    src_ip: str
    description: str
    evidence: dict = {}
    timestamp: float
    datetime: str
    mitigated: bool = False
