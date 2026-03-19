import { useState, useEffect, useRef, useCallback } from "react";
import axios from "axios";
import { useAttackAgent } from "../contexts/AttackAgentContext";
import { Ghost, Waves, ScanSearch, Radio, Shuffle, Zap, CheckCircle2, XCircle, Clock } from "lucide-react";

const API_ATTACK = "/api/attack";

/* ── attack type definitions ─────────────────────────────────────────────── */
const ATTACK_TYPES = [
  {
    value: "arp_spoof", label: "ARP 欺骗", en: "SPOOF",
    icon: <Ghost className="w-5 h-5" />,
    desc: "伪造 ARP Reply，劫持目标流量",
    defaultParams: { target_ip: "192.168.1.100", target_mac: "00:11:22:33:44:55", spoof_ip: "192.168.1.1", attacker_mac: "aa:bb:cc:dd:ee:ff" },
  },
  {
    value: "arp_flood", label: "ARP 泛洪", en: "FLOOD",
    icon: <Waves className="w-5 h-5" />,
    desc: "大量伪造 ARP 包，耗尽 CAM 表",
    defaultParams: { count: 100, src_ip_base: "192.168.1" },
  },
  {
    value: "arp_scan", label: "ARP 扫描", en: "SCAN",
    icon: <ScanSearch className="w-5 h-5" />,
    desc: "枚举网段存活主机 MAC 地址",
    defaultParams: { network: "192.168.1", start: 1, end: 50 },
  },
  {
    value: "gratuitous_arp", label: "无故 ARP", en: "GRATUITOUS",
    icon: <Radio className="w-5 h-5" />,
    desc: "广播 ARP 映射，投毒缓存表",
    defaultParams: { ip: "192.168.1.1", mac: "aa:bb:cc:dd:ee:ff", count: 10 },
  },
  {
    value: "arp_mitm", label: "ARP 中间人", en: "MITM",
    icon: <Shuffle className="w-5 h-5" />,
    desc: "双向欺骗，截获完整会话流量",
    defaultParams: { victim1_ip: "192.168.1.10", victim1_mac: "00:11:22:33:44:55", victim2_ip: "192.168.1.20", victim2_mac: "66:77:88:99:aa:bb" },
  },
];

/* ── attack flow configs for diagram ─────────────────────────────────────── */
const FLOW_CONFIGS = {
  arp_spoof: {
    nodes: [
      { id: "att", label: "ATTACKER", sub: "攻击者", x: 75,  y: 110, color: "#ff2060" },
      { id: "vic", label: "VICTIM",   sub: "受害者", x: 325, y: 55,  color: "#f59e0b" },
      { id: "gw",  label: "GATEWAY",  sub: "网关",   x: 325, y: 165, color: "#7aa8cc" },
    ],
    steps: [
      { phase: "①", from: "att", to: "vic", pkt: "Fake ARP Reply →", detail: "Gateway IP 绑定到攻击者 MAC",   color: "#ff2060" },
      { phase: "②", from: "att", to: "gw",  pkt: "Fake ARP Reply →", detail: "Victim IP 绑定到攻击者 MAC",   color: "#ff2060" },
      { phase: "③", from: "vic", to: "att", pkt: "← Traffic",        detail: "受害者流量重定向到攻击者",       color: "#f59e0b", dashed: true },
      { phase: "④", from: "att", to: "gw",  pkt: "Forward →",        detail: "攻击者转发，中间人建立",        color: "#00e5ff", dashed: true },
    ],
    result: "中间人成立 · 可窃听 / 篡改 / 注入所有报文",
  },
  arp_flood: {
    nodes: [
      { id: "att", label: "ATTACKER", sub: "攻击者", x: 75,  y: 110, color: "#ff2060" },
      { id: "sw",  label: "SWITCH",   sub: "交换机", x: 200, y: 110, color: "#b44dff" },
      { id: "net", label: "NETWORK",  sub: "全网",   x: 325, y: 110, color: "#7aa8cc" },
    ],
    steps: [
      { phase: "①", from: "att", to: "sw",  pkt: "Fake ARP ×N →",  detail: "构造随机源 MAC/IP 的 ARP 请求",   color: "#f59e0b" },
      { phase: "②", from: "att", to: "sw",  pkt: "持续泛洪 →",      detail: "大量包填满交换机 CAM 表",          color: "#ff2060" },
      { phase: "③", from: "sw",  to: "net", pkt: "Broadcast All →", detail: "CAM 溢出，退化为全端口广播",       color: "#ff2060" },
    ],
    result: "网络瘫痪 · 所有帧对攻击者可见",
  },
  arp_scan: {
    nodes: [
      { id: "att", label: "ATTACKER",    sub: "攻击者", x: 75,  y: 110, color: "#00e5ff" },
      { id: "brd", label: "192.168.1.x", sub: "广播",   x: 200, y: 55,  color: "#7aa8cc" },
      { id: "hos", label: "LIVE HOST",   sub: "存活主机", x: 325, y: 110, color: "#22c55e" },
    ],
    steps: [
      { phase: "①", from: "att", to: "brd", pkt: "Who-Has? →",    detail: "对每个 IP 发送 ARP 请求广播",    color: "#00e5ff" },
      { phase: "②", from: "hos", to: "att", pkt: "← ARP Reply",   detail: "存活主机回复自身 MAC 地址",      color: "#22c55e" },
      { phase: "③", from: "att", to: "att", pkt: "MAP IP→MAC",    detail: "建立完整拓扑表，获取全部主机",   color: "#00e5ff" },
    ],
    result: "侦察完成 · 获取 IP→MAC 完整映射",
  },
  gratuitous_arp: {
    nodes: [
      { id: "att", label: "ATTACKER",  sub: "攻击者", x: 75,  y: 110, color: "#b44dff" },
      { id: "brd", label: "BROADCAST", sub: "广播域", x: 200, y: 55,  color: "#7aa8cc" },
      { id: "vic", label: "ALL HOSTS", sub: "所有主机", x: 325, y: 110, color: "#f59e0b" },
    ],
    steps: [
      { phase: "①", from: "att", to: "brd", pkt: "GARP →",          detail: "无需请求，主动广播伪造 IP-MAC",  color: "#b44dff" },
      { phase: "②", from: "brd", to: "vic", pkt: "Cache Poisoned →", detail: "所有主机自动刷新 ARP 缓存",     color: "#f59e0b" },
      { phase: "③", from: "vic", to: "att", pkt: "← Traffic",        detail: "目标流量被错误发往攻击者",      color: "#ff2060", dashed: true },
    ],
    result: "隐蔽投毒 · 无需等待请求触发",
  },
  arp_mitm: {
    nodes: [
      { id: "att", label: "ATTACKER", sub: "攻击者", x: 75,  y: 110, color: "#ff2060" },
      { id: "vic", label: "VICTIM",   sub: "受害者", x: 325, y: 55,  color: "#f59e0b" },
      { id: "gw",  label: "GATEWAY",  sub: "网关",   x: 325, y: 165, color: "#7aa8cc" },
    ],
    steps: [
      { phase: "①", from: "att", to: "vic", pkt: "I am Gateway →", detail: "向受害者声称自己是网关",          color: "#ff2060" },
      { phase: "②", from: "att", to: "gw",  pkt: "I am Victim →",  detail: "向网关声称自己是受害者",          color: "#ff2060" },
      { phase: "③", from: "vic", to: "att", pkt: "→ me →",          detail: "受害者→攻击者→网关 双向中继",    color: "#f59e0b", dashed: true },
      { phase: "④", from: "att", to: "att", pkt: "INTERCEPT",       detail: "窃听 / 注入 / 篡改任意报文",     color: "#b44dff" },
    ],
    result: "完全控制会话 · 可实施降级 / 注入 / DoS",
  },
};

/* ── SVG attack flow diagram ─────────────────────────────────────────────── */
function getLinePts(fromNode, toNode) {
  if (!fromNode || !toNode || fromNode.id === toNode.id) return null;
  const dx = toNode.x - fromNode.x;
  const dy = toNode.y - fromNode.y;
  const dist = Math.sqrt(dx * dx + dy * dy);
  const r = 34;
  return {
    x1: fromNode.x + (dx / dist) * r, y1: fromNode.y + (dy / dist) * r,
    x2: toNode.x  - (dx / dist) * r, y2: toNode.y  - (dy / dist) * r,
  };
}

function AttackFlowDiagram({ type }) {
  const config = FLOW_CONFIGS[type];
  const [activeStep, setActiveStep] = useState(0);

  useEffect(() => {
    setActiveStep(0);
    const t = setInterval(() => setActiveStep((s) => (s + 1) % config.steps.length), 2200);
    return () => clearInterval(t);
  }, [type, config.steps.length]);

  const nodeMap = Object.fromEntries(config.nodes.map((n) => [n.id, n]));
  const uid = type; // stable unique prefix for SVG IDs

  return (
    <div className="space-y-3">
      {/* topology SVG */}
      <div className="rounded" style={{ background: "rgba(0,0,0,0.25)", border: "1px solid rgba(0,229,255,0.1)" }}>
        <svg viewBox="0 0 400 220" width="100%" style={{ display: "block" }}>
          <defs>
            {config.steps.map((step, i) => (
              <marker key={i} id={`arr-${uid}-${i}`} markerWidth="7" markerHeight="5" refX="6" refY="2.5" orient="auto">
                <path d="M 0 0 L 7 2.5 L 0 5 Z" fill={step.color} opacity={i === activeStep ? 1 : 0.25} />
              </marker>
            ))}
          </defs>

          {/* subtle grid */}
          <defs>
            <pattern id={`grid-${uid}`} width="20" height="20" patternUnits="userSpaceOnUse">
              <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(0,229,255,0.04)" strokeWidth="0.5" />
            </pattern>
          </defs>
          <rect width="400" height="220" fill={`url(#grid-${uid})`} />

          {/* edges */}
          {config.steps.map((step, i) => {
            const pts = getLinePts(nodeMap[step.from], nodeMap[step.to]);
            if (!pts) return null;
            const active = i === activeStep;
            const id = `path-${uid}-${i}`;
            return (
              <g key={i}>
                <path
                  id={id}
                  d={`M ${pts.x1} ${pts.y1} L ${pts.x2} ${pts.y2}`}
                  stroke={step.color}
                  strokeWidth={active ? 2 : 0.8}
                  strokeDasharray={step.dashed ? "6 4" : undefined}
                  strokeOpacity={active ? 1 : 0.2}
                  fill="none"
                  markerEnd={`url(#arr-${uid}-${i})`}
                />
                {active && (
                  <circle r="5" fill={step.color} style={{ filter: `drop-shadow(0 0 5px ${step.color})` }}>
                    <animateMotion dur="0.85s" repeatCount="indefinite">
                      <mpath href={`#${id}`} />
                    </animateMotion>
                  </circle>
                )}
              </g>
            );
          })}

          {/* self-loop for "att→att" steps */}
          {config.steps.map((step, i) => {
            if (step.from !== step.to) return null;
            const node = nodeMap[step.from];
            if (!node) return null;
            const active = i === activeStep;
            return (
              <g key={`loop-${i}`}>
                <path
                  d={`M ${node.x - 20} ${node.y - 32} A 22 22 0 1 1 ${node.x + 20} ${node.y - 32}`}
                  stroke={step.color} strokeWidth={active ? 2 : 0.8}
                  strokeOpacity={active ? 1 : 0.2}
                  fill="none"
                />
                {active && (
                  <circle cx={node.x} cy={node.y - 54} r="5" fill={step.color}
                    style={{ filter: `drop-shadow(0 0 5px ${step.color})`, animation: "glow-pulse 0.85s ease-in-out infinite" }} />
                )}
              </g>
            );
          })}

          {/* nodes */}
          {config.nodes.map((node) => (
            <g key={node.id}>
              {/* glow ring */}
              <circle cx={node.x} cy={node.y} r="34" fill="none" stroke={node.color} strokeWidth="0.5" opacity="0.2" />
              {/* body */}
              <circle cx={node.x} cy={node.y} r="28"
                fill="rgba(6,11,24,0.9)" stroke={node.color} strokeWidth="1.5" />
              {/* label */}
              <text x={node.x} y={node.y - 3} textAnchor="middle"
                fill={node.color} fontSize="7.5" fontWeight="700"
                fontFamily="JetBrains Mono, monospace" letterSpacing="0.04em">
                {node.label}
              </text>
              <text x={node.x} y={node.y + 9} textAnchor="middle"
                fill={node.color} fontSize="6.5" opacity="0.65"
                fontFamily="JetBrains Mono, monospace">
                {node.sub}
              </text>
            </g>
          ))}
        </svg>
      </div>

      {/* step list */}
      <div className="space-y-1.5">
        {config.steps.map((step, i) => {
          const active = i === activeStep;
          return (
            <div key={i} className="flex items-center gap-2 px-3 py-2 rounded font-mono text-xs transition-all duration-200"
              style={{
                background: active ? `${step.color}12` : "transparent",
                border: `1px solid ${active ? step.color + "50" : "rgba(0,229,255,0.06)"}`,
              }}>
              <span className="font-bold w-5 shrink-0" style={{ color: step.color }}>{step.phase}</span>
              <span className="shrink-0 font-semibold" style={{ color: active ? step.color : "var(--text-faint)" }}>
                {step.pkt}
              </span>
              <span style={{ color: active ? "var(--text)" : "var(--text-faint)" }}>{step.detail}</span>
            </div>
          );
        })}
        {/* result */}
        <div className="px-3 py-1.5 rounded font-mono text-xs mt-1"
          style={{ background: "rgba(0,229,255,0.05)", border: "1px solid rgba(0,229,255,0.18)", color: "var(--accent)" }}>
          ⟹ {config.result}
        </div>
      </div>
    </div>
  );
}

/* ── main page ───────────────────────────────────────────────────────────── */
export default function ARPForge() {
  const [selectedType, setSelectedType]   = useState("arp_scan");
  const [iface, setIface]                 = useState("eth0");
  const [realSend, setRealSend]           = useState(false);
  const [runLoading, setRunLoading]       = useState(false);
  const [lastRunResult, setLastRunResult] = useState(null);
  const [attackLogs, setAttackLogs]       = useState([]);
  const [latestLogId, setLatestLogId]     = useState(null);

  const { messages: agentMsgs, input: agentInput, setInput: setAgentInput, loading: agentLoading, sendMessage: sendAgentMsg } = useAttackAgent();
  const agentEndRef = useRef(null);

  useEffect(() => { agentEndRef.current?.scrollIntoView({ behavior: "smooth" }); }, [agentMsgs]);

  const fetchLogs = useCallback(async () => {
    try {
      const res = await axios.get(`${API_ATTACK}/logs`, { params: { limit: 20 } });
      setAttackLogs(res.data.logs || []);
    } catch (_) {}
  }, []);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  const runAttack = async () => {
    setRunLoading(true);
    setLastRunResult(null);
    setLatestLogId(null);
    const entry = ATTACK_TYPES.find((t) => t.value === selectedType);
    try {
      const res = await axios.post(`${API_ATTACK}/run`, {
        attack_type: selectedType,
        params: entry?.defaultParams || {},
        real_send: realSend,
        iface,
      });
      setLastRunResult(res.data);
      setLatestLogId(res.data.id || null);
      await fetchLogs();
    } catch (e) {
      setLastRunResult({ status: "error", message: e.response?.data?.detail || e.message, steps: [] });
    } finally {
      setRunLoading(false);
    }
  };

  const runAgent = () => sendAgentMsg(agentInput, fetchLogs);
  const currentType = ATTACK_TYPES.find((t) => t.value === selectedType);

  return (
    <div className="space-y-5">
      <h1 className="cyber-title">ARP 攻击构造</h1>

      {/* ── attack type selection cards ────────────── */}
      <div className="grid grid-cols-5 gap-3">
        {ATTACK_TYPES.map((t) => {
          const active = selectedType === t.value;
          return (
            <button key={t.value} onClick={() => setSelectedType(t.value)}
              className="panel-cyber p-3 text-left transition-all duration-150 hover:scale-[1.02]"
              style={active ? { borderColor: "rgba(0,229,255,0.6)", background: "rgba(0,229,255,0.08)", boxShadow: "0 0 16px rgba(0,229,255,0.2)" } : {}}>
              <div className="flex items-center gap-2 mb-1.5" style={{ color: active ? "var(--accent)" : "var(--text-dim)" }}>
                {t.icon}
                <span className="font-mono font-bold text-xs tracking-wider">{t.en}</span>
              </div>
              <p className="font-mono text-xs font-semibold mb-0.5" style={{ color: active ? "var(--text)" : "var(--text-dim)" }}>{t.label}</p>
              <p className="font-mono leading-relaxed" style={{ color: "var(--text-faint)", fontSize: "0.62rem" }}>{t.desc}</p>
            </button>
          );
        })}
      </div>

      {/* ── main row: agent + execute ──────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">

        {/* Agent — 3 cols */}
        <section className="lg:col-span-3 panel-cyber p-4 flex flex-col">
          <h2 className="cyber-title mb-3">Agent 自然语言执行</h2>
          <div className="rounded flex-1 overflow-hidden flex flex-col"
            style={{ border: "1px solid rgba(0,229,255,0.15)", background: "rgba(0,229,255,0.02)", minHeight: 200 }}>
            <div className="overflow-y-auto flex-1 p-3 space-y-3">
              {agentMsgs.length === 0 && (
                <p className="font-mono text-xs" style={{ color: "var(--text-faint)" }}>
                  例：「对 192.168.1.0/24 做 ARP 扫描」「发起一次 ARP 中间人攻击」
                </p>
              )}
              {agentMsgs.map((msg, i) => (
                <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                  <div className="max-w-[88%] rounded px-3 py-2 text-xs font-mono whitespace-pre-wrap"
                    style={msg.role === "user"
                      ? { background: "rgba(0,229,255,0.1)", border: "1px solid rgba(0,229,255,0.35)", color: "var(--accent)" }
                      : { background: "rgba(0,229,255,0.04)", border: "1px solid rgba(0,229,255,0.12)", color: "var(--text)" }}>
                    {msg.role === "assistant" && <span className="section-label block mb-1">AGENT</span>}
                    {msg.content}
                  </div>
                </div>
              ))}
              {agentLoading && (
                <div className="flex justify-start">
                  <div className="rounded px-3 py-2 text-xs font-mono animate-pulse"
                    style={{ background: "rgba(0,229,255,0.06)", border: "1px solid rgba(0,229,255,0.2)", color: "var(--accent)" }}>
                    RUNNING…
                  </div>
                </div>
              )}
              <div ref={agentEndRef} />
            </div>
            <div className="flex gap-2 p-3" style={{ borderTop: "1px solid rgba(0,229,255,0.12)" }}>
              <input className="cyber-input flex-1" placeholder="描述攻击指令…"
                value={agentInput} onChange={(e) => setAgentInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && runAgent()} />
              <button onClick={runAgent} disabled={agentLoading} className="btn-cyber-solid shrink-0">发送</button>
            </div>
          </div>
        </section>

        {/* Execute + pipeline — 2 cols */}
        <section className="lg:col-span-2 panel-cyber p-4 flex flex-col gap-4">
          <h2 className="cyber-title">手动执行</h2>

          <div className="space-y-2">
            <div className="flex gap-2 items-center">
              <div className="flex-1">
                <label className="section-label block mb-1">IFACE</label>
                <input className="cyber-input w-full" value={iface} onChange={(e) => setIface(e.target.value)} />
              </div>
              <label className="flex items-center gap-1.5 font-mono text-xs pt-5" style={{ color: "var(--text-dim)" }}>
                <input type="checkbox" checked={realSend} onChange={(e) => setRealSend(e.target.checked)} />
                真实发包
              </label>
            </div>

            <div className="flex items-center gap-2 rounded px-3 py-2"
              style={{ background: "rgba(0,229,255,0.06)", border: "1px solid rgba(0,229,255,0.2)" }}>
              <span style={{ color: "var(--accent)" }}>{currentType?.icon}</span>
              <span className="font-mono text-xs font-semibold" style={{ color: "var(--text)" }}>{currentType?.label}</span>
              <span className="font-mono text-xs ml-auto" style={{ color: "var(--text-faint)" }}>{currentType?.en}</span>
            </div>

            <button onClick={runAttack} disabled={runLoading} className="btn-cyber-solid w-full flex items-center justify-center gap-2">
              <Zap className="w-3.5 h-3.5" />
              {runLoading ? "EXECUTING…" : "发起攻击"}
            </button>
          </div>

          {/* pipeline result */}
          {lastRunResult && (
            <div className="rounded p-3 space-y-2" style={{ background: "rgba(0,229,255,0.03)", border: "1px solid rgba(0,229,255,0.12)" }}>
              <p className="section-label mb-2">EXECUTION PIPELINE</p>
              {lastRunResult.steps?.map((step, idx) => (
                <div key={idx} className="flex items-center gap-2 font-mono text-xs">
                  <span className="shrink-0">
                    {step.status === "ok"
                      ? <CheckCircle2 className="w-3.5 h-3.5" style={{ color: "var(--accent)" }} />
                      : step.status === "failed"
                        ? <XCircle className="w-3.5 h-3.5" style={{ color: "#ff2060" }} />
                        : <Clock className="w-3.5 h-3.5" style={{ color: "var(--text-faint)" }} />}
                  </span>
                  <span style={{ color: "var(--text)" }}>{step.name}</span>
                  {step.detail && <span className="truncate" style={{ color: "var(--text-faint)" }}>{step.detail}</span>}
                </div>
              ))}
              <div className="flex items-center justify-between pt-1 border-t" style={{ borderColor: "rgba(0,229,255,0.1)" }}>
                <span className="font-mono text-xs" style={{ color: lastRunResult.status === "ok" ? "var(--accent)" : "#ff2060" }}>
                  {lastRunResult.status === "ok" ? "✓ SUCCESS" : "✗ FAILED"} — {lastRunResult.message}
                </span>
                {lastRunResult.pcap_path && (
                  <a href={`${API_ATTACK}/pcap/${lastRunResult.pcap_path}`} download className="font-mono text-xs" style={{ color: "var(--accent)" }}>↓ pcap</a>
                )}
              </div>
            </div>
          )}
        </section>
      </div>

      {/* ── bottom: flow diagram + history ─────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

        {/* animated attack flow diagram */}
        <div className="panel-cyber p-4">
          <h2 className="cyber-title mb-3">攻击流程可视化</h2>
          <AttackFlowDiagram type={selectedType} />
        </div>

        {/* attack history */}
        <div className="panel-cyber p-4">
          <h2 className="cyber-title mb-3">攻击记录</h2>
          <div className="overflow-x-auto max-h-[420px] overflow-y-auto">
            <table className="w-full font-mono text-xs">
              <thead>
                <tr style={{ color: "var(--text-faint)", borderBottom: "1px solid rgba(0,229,255,0.15)" }}>
                  {["时间", "类型", "状态", "包数", "发包"].map((h) => (
                    <th key={h} className="px-2 py-1.5 text-left font-semibold tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {attackLogs.length === 0 && (
                  <tr><td colSpan={5} className="px-2 py-4 section-label">无记录</td></tr>
                )}
                {attackLogs.map((log) => (
                  <tr key={log.id} style={{
                    borderBottom: "1px solid rgba(0,229,255,0.06)",
                    background: log.id === latestLogId ? "rgba(0,229,255,0.08)" : "transparent",
                    color: "var(--text-dim)",
                  }}>
                    <td className="px-2 py-1.5">{log.finished_at?.slice(0, 19)}</td>
                    <td className="px-2 py-1.5">{log.attack_type}</td>
                    <td className="px-2 py-1.5" style={{ color: log.status === "ok" ? "var(--accent)" : "#ff2060" }}>
                      {log.status === "ok" ? "✓" : "✗"}
                    </td>
                    <td className="px-2 py-1.5">{log.packets_count ?? "—"}</td>
                    <td className="px-2 py-1.5" style={{ color: log.real_send ? "#ff2060" : "var(--text-faint)" }}>
                      {log.real_send ? "LIVE" : "SIM"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
