from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
from agents.threat_agent import (
    build_threat_agent,
    build_attack_agent,
    reconstruct_attack_chain,
    generate_security_report,
    update_alert_store,
    get_recent_alerts_list,
)

router = APIRouter()
_agent_executor = None
_attack_agent_executor = None


def get_agent():
    global _agent_executor
    if _agent_executor is None:
        _agent_executor = build_threat_agent()
    return _agent_executor


def get_attack_agent():
    global _attack_agent_executor
    if _attack_agent_executor is None:
        _attack_agent_executor = build_attack_agent()
    return _attack_agent_executor


class ChatRequest(BaseModel):
    message: str
    history: List[dict] = []


class AnalyzeRequest(BaseModel):
    alerts: List[dict]


@router.post("/chat")
async def ai_chat(req: ChatRequest):
    """与 AI 安全分析师对话"""
    try:
        agent = get_agent()
        result = await agent.ainvoke({
            "input": req.message,
            "chat_history": req.history
        })
        return {"response": result["output"], "status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack-chat")
async def attack_chat(req: ChatRequest):
    """与攻击执行 Agent 对话：只执行攻击并汇报，不提供分析选项"""
    try:
        agent = get_attack_agent()
        result = await agent.ainvoke({
            "input": req.message,
            "chat_history": req.history
        })
        return {"response": result["output"], "status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reconstruct-chain")
async def reconstruct_chain(req: AnalyzeRequest):
    """重构攻击链"""
    try:
        result = await reconstruct_attack_chain(req.alerts)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate-report")
async def gen_report(req: AnalyzeRequest):
    """生成完整安全报告"""
    try:
        chain = await reconstruct_attack_chain(req.alerts)
        risk_score = min(len(req.alerts) * 5 + 20, 100)
        report = await generate_security_report(req.alerts, chain, risk_score)
        return {"report": report, "attack_chain": chain, "risk_score": risk_score}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sync-alerts")
def sync_alerts(req: AnalyzeRequest):
    """同步告警到 AI 分析上下文"""
    update_alert_store(req.alerts)
    return {"synced": len(req.alerts)}


@router.get("/alerts")
def get_alerts(limit: int = 100):
    """获取最近告警列表，供态势大屏等使用"""
    return {"alerts": get_recent_alerts_list(limit=limit)}
