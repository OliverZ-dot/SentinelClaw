"""
AI 智能分析中心 —— 基于 DeepSeek API + LangChain Agent
实现：
  1. 告警关联分析
  2. 攻击链自动重构
  3. 风险评估评分
  4. 处置决策建议
  5. 自然语言交互查询
"""

import json
from openai import AsyncOpenAI
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import tool
from typing import List
import sys
from pathlib import Path
# 确保 backend 在 path 中
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import settings


# 代理仅用于 search_web（上网检索），不写入 os.environ，避免 DeepSeek 等请求被强制走代理导致连不上时报 500




_alert_store: List[dict] = []


@tool
def get_recent_alerts(limit: int = 20) -> str:
    """获取最近的安全告警列表，用于关联分析"""
    recent = _alert_store[-limit:] if _alert_store else []
    return json.dumps(recent, ensure_ascii=False, indent=2)


@tool
def analyze_ip_reputation(ip_address: str) -> str:
    """分析某个 IP 地址的威胁情报，返回历史行为摘要"""
    behaviors = [a for a in _alert_store if a.get("src_ip") == ip_address]
    if not behaviors:
        return f"IP {ip_address} 在本地告警库中无记录，无法判断历史行为"
    summary = {
        "ip": ip_address,
        "alert_count": len(behaviors),
        "alert_types": list(set(a["alert_type"] for a in behaviors)),
        "max_severity": max(
            (a["severity"] for a in behaviors),
            key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0),
            default="unknown"
        )
    }
    return json.dumps(summary, ensure_ascii=False)


def _run_web_search(query: str, proxy: str | None, timeout: int):
    """执行网页检索，先主站再 lite 后端，均走代理与超时。"""
    from duckduckgo_search import DDGS
    with DDGS(proxy=proxy, timeout=timeout) as ddgs:
        results = list(ddgs.text(query, max_results=5))
    return results


def _run_web_search_lite(query: str, proxy: str | None, timeout: int):
    """使用 DuckDuckGo Lite 后端检索（有时在主站不可达时可用）。"""
    from duckduckgo_search import DDGS
    with DDGS(proxy=proxy, timeout=timeout) as ddgs:
        results = list(ddgs.text(query, max_results=5, backend="lite"))
    return results


def _run_instant_answer(query: str, proxy: str | None, timeout: int) -> list[dict]:
    """DuckDuckGo 即时答案 API，作为检索兜底（结果较少但接口简单）。"""
    import httpx
    url = "https://api.duckduckgo.com/"
    params = {"q": query, "format": "json", "no_redirect": 1}
    with httpx.Client(proxy=proxy, timeout=timeout) as client:
        resp = client.get(url, params=params)
        resp.raise_for_status()
    data = resp.json()
    out = []
    if data.get("AbstractText"):
        out.append({
            "title": data.get("Heading", query),
            "body": data.get("AbstractText", ""),
            "href": data.get("AbstractURL", ""),
        })
    for r in data.get("RelatedTopics", [])[:4]:
        if isinstance(r, dict) and r.get("Text"):
            out.append({"title": r.get("Text", "")[:80], "body": r.get("Text", ""), "href": r.get("FirstURL", "")})
    return out


@tool
def search_web(query: str) -> str:
    """上网检索：根据关键词搜索网络，获取最新信息。当用户问天气、新闻、实时信息或需要查资料时，请调用此工具。"""
    proxy = settings.get_effective_proxy()
    timeout = settings.search_timeout
    results = []
    last_error = None

    # 1) 主站检索
    try:
        results = _run_web_search(query, proxy, timeout)
    except Exception as e:
        last_error = e
        try:
            results = _run_web_search_lite(query, proxy, timeout)
        except Exception as e2:
            last_error = e2

    # 2) 若仍无结果，尝试即时答案 API 作为兜底
    if not results:
        try:
            results = _run_instant_answer(query, proxy, timeout)
        except Exception:
            pass

    if results:
        parts = []
        for i, r in enumerate(results, 1):
            title = r.get("title", "")
            body = r.get("body", "")
            href = r.get("href", "")
            parts.append(f"[{i}] {title}\n{body}\n来源: {href}")
        return "\n\n".join(parts)

    msg = str(last_error).strip() if last_error else "无结果"
    if "timeout" in msg.lower() or "connect" in msg.lower() or "network" in msg.lower() or "proxy" in msg.lower():
        return (
            f"上网检索失败（{msg}）。请在本机开启可访问外网的代理（如 Clash、V2Ray 等），"
            "在 backend 目录的 .env 中设置 HTTP_PROXY 与 HTTPS_PROXY（例如：HTTP_PROXY=http://127.0.0.1:7890），"
            "然后重启后端服务再试。"
        )
    return f"检索失败: {msg}"


@tool
def execute_attack(attack_type: str, params: str, real_send: bool = False, iface: str = "eth0") -> str:
    """
    执行一次网络攻击（由 Agent 代理调用）。仅用于授权测试环境。
    attack_type 可选: arp_spoof, arp_flood, arp_scan, gratuitous_arp, arp_mitm。
    params 为 JSON 字符串，例如 arp_scan 时为 {"network":"192.168.1","start":1,"end":50}；
    arp_spoof 为 {"target_ip":"...","target_mac":"...","spoof_ip":"...","attacker_mac":"..."}；
    arp_flood 为 {"count":100,"src_ip_base":"192.168.1"}；
    gratuitous_arp 为 {"ip":"...","mac":"...","count":10}；
    arp_mitm 为 {"victim1_ip","victim1_mac","victim2_ip","victim2_mac","attacker_mac"}。
    real_send: 为 True 时真实从网卡发包（需 root/sudo）；用户明确要求「真实发包」「真的发」「实际发送」时传 True，否则传 False。
    """
    try:
        from core.attack_runner import run_attack
        params_dict = json.loads(params) if isinstance(params, str) else params
        record = run_attack(attack_type=attack_type, params=params_dict, real_send=real_send, iface=iface)
        return json.dumps(record, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"执行攻击失败: {str(e)}"


@tool
def calculate_risk_score(alert_types: list, severity_levels: list) -> str:
    """根据告警类型和严重程度计算综合风险评分（0-100）"""
    severity_weights = {"critical": 40, "high": 20, "medium": 10, "low": 5}
    type_weights = {
        "ARP_SPOOFING": 35, "BRUTE_FORCE": 30, "PORT_SCAN": 20,
        "ARP_MITM": 40, "PERIODIC_HEARTBEAT": 35, "DNS_TUNNEL": 30,
        "ARP_FLOODING": 25, "ABNORMAL_DNS": 20, "TRAFFIC_BURST": 15,
    }
    score = 0
    for st in set(severity_levels):
        score += severity_weights.get(st, 0)
    for at in set(alert_types):
        score += type_weights.get(at, 10)
    score = min(score, 100)
    level = "严重" if score >= 80 else "高危" if score >= 60 else "中危" if score >= 40 else "低危"
    return json.dumps({"risk_score": score, "risk_level": level})


THREAT_AGENT_SYSTEM_PROMPT = """你是 SentinelAI 网络安全分析平台的核心 AI 分析师。
使用你的人名字叫张庭赫，是来自东北大学软件学院信息安全专业的大三学生，你是他实训课程的产品，这门课的老师叫杨巍。
你拥有深厚的网络安全专业知识，擅长：
- 攻击链重构与入侵路径分析
- 告警关联与 APT 攻击溯源
- 风险评估与优先级排序
- 安全事件处置决策

当分析安全告警时，你应该：
1. 调用工具获取最新告警数据
2. 识别告警之间的关联关系，重构攻击链
3. 评估风险等级和业务影响
4. 给出具体可行的处置建议
5. 用清晰的中文输出分析报告

输出格式要求：使用结构化 Markdown，包含【攻击链分析】【风险评估】【处置建议】三个核心章节。

当用户询问天气、新闻、日期时间或需要最新/实时信息时，请先调用 search_web 工具进行网络检索，再根据检索结果用中文回答。

当用户要求「执行攻击」「由 Agent 执行攻击」或描述某种网络攻击（如对某网段做 ARP 扫描、ARP 泛洪、ARP 欺骗等）时，请根据描述推断 attack_type 和 params（JSON），调用 execute_attack 工具执行，然后汇报执行结果（包数、pcap 是否已保存、是否真实发包等）。若用户明确要求「真实发包」「真的发出去」「实际发送」等，则 execute_attack 的 real_send 参数传 True，否则传 False。"""


# 攻击执行专用 Agent：只做执行攻击，不提供分析/风险评估等选项
ATTACK_AGENT_SYSTEM_PROMPT = """你是 SentinelAI 的「攻击执行 Agent」，负责执行网络攻击（模拟或真实）并汇报结果。你要有主见、能自主决策。

重要：不要反问用户「请提供具体参数」「您想执行什么类型」等。一旦用户表达要执行攻击（包括「按你自己的想法」「你自己决定」「随便执行一个」或描述不清时），你应自主选择一种攻击类型和合理默认参数，直接调用 execute_attack 执行，再汇报。

可选攻击类型与默认参数示例（你可自行选用或微调）：
- arp_scan: {{"network":"192.168.1","start":1,"end":50}}
- arp_flood: {{"count":100,"src_ip_base":"192.168.1"}}
- arp_spoof: {{"target_ip":"192.168.1.100","target_mac":"00:11:22:33:44:55","spoof_ip":"192.168.1.1","attacker_mac":"aa:bb:cc:dd:ee:ff"}}
- gratuitous_arp: {{"ip":"192.168.1.1","mac":"aa:bb:cc:dd:ee:ff","count":5}}
- arp_mitm: {{"victim1_ip":"192.168.1.10","victim1_mac":"00:11:22:33:44:55","victim2_ip":"192.168.1.20","victim2_mac":"66:77:88:99:aa:bb"}}

流程：1）根据用户意图推断或自主选择 attack_type 和 params；2）若用户明确要求「真实发包」「真的发」「实际发送」则 real_send=true，否则 real_send=false；3）调用 execute_attack(attack_type, params 的 JSON 字符串, real_send, iface)；4）用简短中文汇报执行结果（是否真实发包、包数、pcap 等）。不要提供分析选项，不要向用户索要参数。"""


def build_threat_agent():
    llm = ChatOpenAI(
        model=settings.deepseek_model,
        api_key=settings.deepseek_api_key,
        base_url=settings.deepseek_base_url,
        temperature=0.1,
        request_timeout=settings.deepseek_timeout,
    )
    tools = [get_recent_alerts, analyze_ip_reputation, calculate_risk_score, search_web, execute_attack]
    prompt = ChatPromptTemplate.from_messages([
        ("system", THREAT_AGENT_SYSTEM_PROMPT),
        MessagesPlaceholder("chat_history", optional=True),
        ("human", "{input}"),
        MessagesPlaceholder("agent_scratchpad"),
    ])
    agent = create_tool_calling_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, verbose=True, max_iterations=15)


def build_attack_agent():
    """仅用于攻击执行的 Agent，只暴露 execute_attack，不做分析"""
    llm = ChatOpenAI(
        model=settings.deepseek_model,
        api_key=settings.deepseek_api_key,
        base_url=settings.deepseek_base_url,
        temperature=0.1,
        request_timeout=settings.deepseek_timeout,
    )
    tools = [execute_attack]
    prompt = ChatPromptTemplate.from_messages([
        ("system", ATTACK_AGENT_SYSTEM_PROMPT),
        MessagesPlaceholder("chat_history", optional=True),
        ("human", "{input}"),
        MessagesPlaceholder("agent_scratchpad"),
    ])
    agent = create_tool_calling_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, verbose=True, max_iterations=15)


async def reconstruct_attack_chain(alerts: List[dict]) -> dict:
    """输入告警列表，使用 DeepSeek 重构完整攻击链"""
    client = AsyncOpenAI(
        api_key=settings.deepseek_api_key,
        base_url=settings.deepseek_base_url,
        timeout=float(settings.deepseek_timeout),
    )
    alerts_json = json.dumps(alerts, ensure_ascii=False, indent=2)
    prompt = f"""以下是从网络流量中检测到的安全告警序列：

{alerts_json}

请根据 MITRE ATT&CK 框架，对上述告警进行攻击链重构分析，输出严格的 JSON 格式：

{{
  "attack_phases": [
    {{
      "phase": "侦察",
      "mitre_tactic": "TA0043",
      "related_alerts": ["alert_id1"],
      "description": "攻击者行为描述"
    }}
  ],
  "attack_path": "攻击入侵路径的简洁描述",
  "involved_ips": {{"attacker": [], "victim": [], "pivot": []}},
  "attack_type": "攻击类型（如APT、内网横移等）",
  "confidence": 0.85,
  "summary": "整体攻击事件摘要（2-3句话）"
}}

只输出 JSON，不要有任何多余文字。"""

    try:
        response = await client.chat.completions.create(
            model=settings.deepseek_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        content = response.choices[0].message.content
        # 兼容无 response_format 的 API
        content = content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        return json.loads(content)
    except json.JSONDecodeError:
        return {
            "attack_phases": [],
            "attack_path": "解析失败",
            "involved_ips": {"attacker": [], "victim": [], "pivot": []},
            "attack_type": "未知",
            "confidence": 0,
            "summary": "LLM 返回非 JSON，无法解析。"
        }


async def generate_security_report(
    alerts: List[dict],
    attack_chain: dict,
    risk_score: int
) -> str:
    """自动生成完整安全事件报告（Markdown 格式）"""
    client = AsyncOpenAI(
        api_key=settings.deepseek_api_key,
        base_url=settings.deepseek_base_url,
        timeout=float(settings.deepseek_timeout),
    )
    prompt = f"""请根据以下安全事件数据，生成一份专业的网络安全事件分析报告（Markdown 格式）。

告警数据：{json.dumps(alerts[:10], ensure_ascii=False)}
攻击链：{json.dumps(attack_chain, ensure_ascii=False)}
风险评分：{risk_score}/100

报告应包含：
# 安全事件分析报告
## 执行摘要
## 事件时间线
## 攻击链分析（结合 MITRE ATT&CK）
## 影响评估
## 处置建议
## 预防措施

要求：专业、具体、可操作，使用中文。"""

    response = await client.chat.completions.create(
        model=settings.deepseek_model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
        max_tokens=3000
    )
    return response.choices[0].message.content


def update_alert_store(new_alerts: List[dict]):
    """更新全局告警缓存（供 Agent 工具调用）"""
    global _alert_store
    _alert_store.extend(new_alerts)
    if len(_alert_store) > 10000:
        _alert_store = _alert_store[-5000:]


def get_recent_alerts_list(limit: int = 100) -> List[dict]:
    """获取最近告警列表（供态势大屏等接口使用）"""
    recent = _alert_store[-limit:] if _alert_store else []
    return list(reversed(recent))
