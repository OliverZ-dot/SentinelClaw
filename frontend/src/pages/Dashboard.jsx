import { useState, useEffect, useMemo, useRef } from "react";
import {
  Activity,
  AlertTriangle,
  Radio,
  Siren,
  Swords,
  Shield,
  Eye,
  Cpu,
  Network,
  Crosshair,
  Wifi,
} from "lucide-react";
import axios from "axios";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
  AreaChart, Area, RadarChart, Radar, PolarGrid, PolarAngleAxis,
} from "recharts";

const API = "/api";
const DASHBOARD_POLL_MS = 1500;

const SEVERITY_COLORS = {
  critical: "#ff2060",
  high:     "#f59e0b",
  medium:   "#eab308",
  low:      "#22c55e",
};

const ATTACK_TYPE_LABELS = {
  arp_spoof:      "ARP 欺骗",
  arp_flood:      "ARP 泛洪",
  arp_scan:       "ARP 扫描",
  gratuitous_arp: "无故 ARP",
  arp_mitm:       "ARP 中间人",
};

const ALERT_LABELS = {
  ARP_SPOOFING:         "ARP 欺骗",
  ARP_FLOODING:         "ARP 泛洪",
  ARP_SCANNING:         "ARP 扫描",
  ARP_MITM:             "ARP 中间人",
  GRATUITOUS_ARP_ABUSE: "无故 ARP",
  PORT_SCAN:            "端口扫描",
  BRUTE_FORCE:          "暴力破解",
  ABNORMAL_DNS:         "异常 DNS",
  DNS_TUNNEL:           "DNS 隧道",
  TRAFFIC_BURST:        "流量突发",
  PERIODIC_HEARTBEAT:   "周期心跳",
};

function useDashboard() {
  const [data, setData] = useState({
    alerts: [], attack_logs: [], capturing: false,
    stats: { alerts_total: 0, alerts_critical: 0, alerts_high: 0, attacks_total: 0 },
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [flashKeys, setFlashKeys] = useState({});
  const prevStatsRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    const fetchData = async () => {
      try {
        const res = await axios.get(`${API}/dashboard/overview`, {
          params: { alert_limit: 100, attack_limit: 50 },
        });
        if (!cancelled) {
          const newStats = res.data.stats || {};
          if (prevStatsRef.current) {
            const changed = {};
            Object.keys(newStats).forEach((k) => {
              if (newStats[k] !== prevStatsRef.current[k]) changed[k] = true;
            });
            if (Object.keys(changed).length > 0) {
              setFlashKeys(changed);
              setTimeout(() => setFlashKeys({}), 700);
            }
          }
          prevStatsRef.current = newStats;
          setData(res.data);
          setLastUpdated(Date.now());
        }
      } catch (e) {
        if (!cancelled) setError(e.message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    fetchData();
    const t = setInterval(fetchData, DASHBOARD_POLL_MS);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  return { data, loading, error, lastUpdated, flashKeys };
}

/* ── data helpers ───────────────────────────────────── */
function alertTypeData(alerts) {
  const map = {};
  alerts.forEach((a) => { const t = a.alert_type || "OTHER"; map[t] = (map[t] || 0) + 1; });
  const entries = Object.entries(map).map(([name, count]) => ({ name: ALERT_LABELS[name] || name, count })).sort((a, b) => b.count - a.count);
  if (entries.length <= 5) return entries;
  const top5 = entries.slice(0, 5);
  const otherCount = entries.slice(5).reduce((s, e) => s + e.count, 0);
  return [...top5, { name: "其他", count: otherCount }];
}

function attackTypeData(logs) {
  const map = {};
  logs.forEach((l) => { const label = ATTACK_TYPE_LABELS[l.attack_type] || l.attack_type; map[label] = (map[label] || 0) + 1; });
  return Object.entries(map).map(([name, value]) => ({ name, value }));
}

// 30-second buckets × 12 = last 6 minutes — shows attack changes within ~30 seconds
function trendData(alerts, attackLogs, buckets = 12, bucketSecs = 30) {
  const now = Date.now() / 1000;
  return Array.from({ length: buckets }, (_, i) => {
    const offset = buckets - 1 - i;
    const start = now - (offset + 1) * bucketSecs;
    const end   = now - offset * bucketSecs;
    const label = new Date((end - bucketSecs / 2) * 1000).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    return {
      time: label,
      告警: alerts.filter((a) => a.timestamp >= start && a.timestamp < end).length,
      攻击: attackLogs.filter((l) => { const ts = l.finished_at ? new Date(l.finished_at).getTime() / 1000 : 0; return ts >= start && ts < end; }).length,
    };
  });
}

function recentActivity(alerts, attackLogs, limit = 12) {
  const items = [];
  alerts.forEach((a) => items.push({ type: "alert", severity: a.severity, text: a.description || a.alert_type, time: a.timestamp ? a.timestamp * 1000 : null, iso: a.datetime }));
  attackLogs.forEach((l) => items.push({ type: "attack", text: `${ATTACK_TYPE_LABELS[l.attack_type] || l.attack_type} · ${l.message || ""}`, time: l.finished_at ? new Date(l.finished_at).getTime() : null, iso: l.finished_at, real_send: l.real_send }));
  items.sort((a, b) => (b.time || 0) - (a.time || 0));
  return items.slice(0, limit);
}

function topSourceIPs(alerts, limit = 6) {
  const map = {};
  alerts.forEach((a) => { if (a.src_ip) map[a.src_ip] = (map[a.src_ip] || 0) + 1; });
  return Object.entries(map).map(([ip, count]) => ({ ip, count })).sort((a, b) => b.count - a.count).slice(0, limit);
}

function severityBreakdown(alerts) {
  const map = { critical: 0, high: 0, medium: 0, low: 0 };
  alerts.forEach((a) => { if (map[a.severity] !== undefined) map[a.severity]++; });
  return [
    { name: "严重", value: map.critical, color: "#ff2060" },
    { name: "高危", value: map.high,     color: "#f59e0b" },
    { name: "中危", value: map.medium,   color: "#eab308" },
    { name: "低危", value: map.low,      color: "#22c55e" },
  ];
}

function computeThreatScore(stats) {
  const s = Math.min(100, (stats.alerts_critical || 0) * 20 + (stats.alerts_high || 0) * 6 + ((stats.alerts_total || 0) - (stats.alerts_critical || 0) - (stats.alerts_high || 0)) * 1);
  return Math.round(s);
}

function getThreatLevel(score) {
  if (score >= 75) return { label: "CRITICAL", color: "#ff2060", bg: "rgba(255,32,96,0.12)" };
  if (score >= 50) return { label: "HIGH",     color: "#f59e0b", bg: "rgba(245,158,11,0.12)" };
  if (score >= 25) return { label: "MEDIUM",   color: "#eab308", bg: "rgba(234,179,8,0.1)" };
  return               { label: "LOW",      color: "#22c55e", bg: "rgba(34,197,94,0.1)" };
}

const PIE_COLORS = ["#00e5ff", "#f59e0b", "#7c3aed", "#ff2060", "#22c55e", "#3d6080"];

/* ── tooltip style ───────────────────────────────────── */
const TT_STYLE = {
  backgroundColor: "#0c1628",
  border: "1px solid rgba(0,229,255,0.25)",
  borderRadius: "4px",
  boxShadow: "0 0 16px rgba(0,229,255,0.15)",
  fontFamily: "JetBrains Mono, monospace",
  fontSize: 12,
  color: "#cce4ff",
};

/* ── component ─────────────────────────────────────── */
export default function Dashboard() {
  const { data, loading, error, lastUpdated, flashKeys } = useDashboard();
  const { alerts, attack_logs, capturing, stats } = data;

  const alertByType  = useMemo(() => alertTypeData(alerts).map((item, i) => ({ ...item, fill: PIE_COLORS[i % PIE_COLORS.length] })), [alerts]);
  const attackByType = useMemo(() => attackTypeData(attack_logs), [attack_logs]);
  const trend        = useMemo(() => trendData(alerts, attack_logs, 10), [alerts, attack_logs]);
  const activity     = useMemo(() => recentActivity(alerts, attack_logs, 12), [alerts, attack_logs]);
  const topIPs       = useMemo(() => topSourceIPs(alerts), [alerts]);
  const sevBreak     = useMemo(() => severityBreakdown(alerts), [alerts]);
  const threatScore  = useMemo(() => computeThreatScore(stats), [stats]);
  const threatLevel  = useMemo(() => getThreatLevel(threatScore), [threatScore]);

  const recentCritical = useMemo(() =>
    alerts.filter((a) => a.severity === "critical" || a.severity === "high")
      .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
      .slice(0, 8),
    [alerts]
  );

  /* ── Radar chart data (攻击类型多维画像) */
  const radarData = useMemo(() => {
    const typeCount = {};
    alerts.forEach((a) => { typeCount[a.alert_type] = (typeCount[a.alert_type] || 0) + 1; });
    const keys = Object.keys(ALERT_LABELS).slice(0, 6);
    return keys.map((k) => ({ subject: ALERT_LABELS[k], A: typeCount[k] || 0 }));
  }, [alerts]);

  return (
    <div className="min-h-full space-y-5">

      {/* ── header ──────────────────────────────────── */}
      <div className="panel-cyber px-5 py-3 flex items-center gap-6">
        <h1 className="cyber-title shrink-0">实时态势感知</h1>

        {/* threat level bar */}
        <div className="flex-1 flex items-center gap-3 min-w-0">
          <span className="section-label shrink-0">THREAT</span>
          <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: "rgba(0,229,255,0.08)", border: "1px solid rgba(0,229,255,0.12)" }}>
            <div
              className="h-full rounded-full transition-all duration-1000"
              style={{
                width: `${threatScore}%`,
                background: `linear-gradient(90deg, var(--accent), ${threatLevel.color})`,
                boxShadow: `0 0 8px ${threatLevel.color}60`,
              }}
            />
          </div>
          <span className="font-mono font-bold text-xs shrink-0" style={{ color: threatLevel.color, textShadow: `0 0 8px ${threatLevel.color}` }}>
            {loading ? "—" : `${threatScore} / ${threatLevel.label}`}
          </span>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          {capturing && (
            <span className="badge-live">
              <Radio className="w-2.5 h-2.5 animate-pulse" />
              CAPTURING
            </span>
          )}
          <span className="section-label flex items-center gap-1.5">
            <span className="inline-block w-1.5 h-1.5 rounded-full" style={{ background: "var(--accent)", boxShadow: "0 0 4px var(--accent)", animation: "glow-pulse 1.5s ease-in-out infinite" }} />
            {lastUpdated ? new Date(lastUpdated).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—"}
          </span>
        </div>
      </div>

      {error && (
        <div className="panel px-4 py-2 text-xs font-mono" style={{ borderColor: "rgba(255,32,96,0.4)", color: "#ff6080" }}>
          ERR: {error}
        </div>
      )}

      {/* ── row 1: stat cards + threat score ──────── */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {[
          { icon: <Activity className="w-5 h-5" />, label: "告警总数",   value: stats.alerts_total,    color: "var(--accent)", fk: "alerts_total" },
          { icon: <AlertTriangle className="w-5 h-5" />, label: "高危",  value: stats.alerts_high,     color: "#f59e0b",       fk: "alerts_high" },
          { icon: <Siren className="w-5 h-5" />,   label: "严重",        value: stats.alerts_critical, color: "#ff2060",       fk: "alerts_critical" },
          { icon: <Swords className="w-5 h-5" />,  label: "攻击次数",    value: stats.attacks_total,   color: "var(--accent)", fk: "attacks_total" },
        ].map(({ icon, label, value, color, fk }) => {
          const flashing = !!flashKeys[fk];
          return (
          <div key={label} className="panel-cyber p-4 flex items-center gap-3"
            style={flashing ? { boxShadow: `0 0 22px ${color}70` } : {}}>
            <div className="p-2 rounded shrink-0" style={{ border: `1px solid ${color}40`, color }}>
              {icon}
            </div>
            <div className="min-w-0">
              <p className="section-label">{label}</p>
              <p className="stat-number"
                style={{ fontSize: "1.5rem", textShadow: `0 0 14px ${color}60`,
                  animation: flashing ? "statUpdate 0.55s ease-out" : undefined }}>
                {loading ? "—" : value}
              </p>
            </div>
          </div>
          );
        })}

        {/* threat score gauge */}
        <div
          className="panel-cyber p-4 flex flex-col items-center justify-center text-center"
          style={{ background: threatLevel.bg }}
        >
          <p className="section-label mb-1">威胁评分</p>
          <p className="font-mono font-black" style={{ fontSize: "2rem", color: threatLevel.color, textShadow: `0 0 16px ${threatLevel.color}` }}>
            {loading ? "—" : threatScore}
          </p>
          <p className="font-mono font-bold text-xs mt-1 tracking-widest" style={{ color: threatLevel.color }}>
            {threatLevel.label}
          </p>
        </div>
      </div>

      {/* ── row 2: top IPs + critical feed + severity ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* top attacker IPs */}
        <div className="panel-cyber p-4">
          <h2 className="cyber-title mb-3 flex items-center gap-2">
            <Crosshair className="w-3.5 h-3.5" />
            攻击源排行
          </h2>
          {topIPs.length === 0 ? (
            <div className="py-6 section-label text-center">无数据</div>
          ) : (
            <div className="space-y-2">
              {topIPs.map((item, i) => {
                const pct = topIPs[0].count > 0 ? (item.count / topIPs[0].count) * 100 : 0;
                return (
                  <div key={item.ip} className="flex items-center gap-2">
                    <span className="font-mono text-xs w-4 shrink-0" style={{ color: "var(--text-faint)" }}>#{i + 1}</span>
                    <span className="font-mono text-xs flex-1 truncate" style={{ color: "var(--text)" }}>{item.ip}</span>
                    <div className="w-16 h-1.5 rounded-full overflow-hidden shrink-0" style={{ background: "rgba(0,229,255,0.08)" }}>
                      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: i === 0 ? "#ff2060" : "var(--accent)" }} />
                    </div>
                    <span className="font-mono text-xs w-6 text-right shrink-0" style={{ color: "var(--accent)" }}>{item.count}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* recent critical/high alerts */}
        <div className="panel-cyber p-4">
          <h2 className="cyber-title mb-3 flex items-center gap-2">
            <Siren className="w-3.5 h-3.5" style={{ color: "#ff2060" }} />
            高危告警
          </h2>
          <div className="space-y-1.5 max-h-52 overflow-y-auto">
            {recentCritical.length === 0 ? (
              <div className="py-6 section-label text-center">无高危告警</div>
            ) : (
              recentCritical.map((a, i) => (
                <div key={a.id || i} className="flex items-start gap-2 text-xs font-mono rounded px-2 py-1.5"
                  style={{ background: a.severity === "critical" ? "rgba(255,32,96,0.06)" : "rgba(245,158,11,0.06)", border: `1px solid ${SEVERITY_COLORS[a.severity] || "#3d6080"}30` }}>
                  <span className="shrink-0 font-bold" style={{ color: SEVERITY_COLORS[a.severity] }}>
                    {a.severity === "critical" ? "!!!" : "!!"}
                  </span>
                  <span className="flex-1 truncate" style={{ color: "var(--text-dim)" }}>
                    {ALERT_LABELS[a.alert_type] || a.alert_type} — {a.src_ip}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* severity breakdown */}
        <div className="panel-cyber p-4">
          <h2 className="cyber-title mb-3 flex items-center gap-2">
            <Shield className="w-3.5 h-3.5" />
            告警分级
          </h2>
          <div className="space-y-3">
            {sevBreak.map((item) => {
              const pct = stats.alerts_total > 0 ? (item.value / stats.alerts_total) * 100 : 0;
              return (
                <div key={item.name}>
                  <div className="flex justify-between items-center mb-1">
                    <span className="font-mono text-xs" style={{ color: item.color }}>{item.name}</span>
                    <span className="font-mono text-xs" style={{ color: "var(--text-dim)" }}>{item.value}</span>
                  </div>
                  <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.05)" }}>
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${pct}%`, background: item.color, boxShadow: `0 0 6px ${item.color}80` }} />
                  </div>
                </div>
              );
            })}
          </div>
          {stats.alerts_total === 0 && <div className="mt-4 section-label text-center">无数据</div>}
        </div>
      </div>

      {/* ── row 3: trend + alert pie ─────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        <div className="xl:col-span-2 panel-cyber p-5">
          <h2 className="cyber-title mb-4 flex items-center gap-2">
            <Activity className="w-3.5 h-3.5" />
            近 10 分钟趋势
          </h2>
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend}>
                <defs>
                  <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#7aa8cc" stopOpacity={0.45} />
                    <stop offset="100%" stopColor="#7aa8cc" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="attackGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00e5ff" stopOpacity={0.45} />
                    <stop offset="100%" stopColor="#00e5ff" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#3d6080" tick={{ fill: "#7aa8cc", fontSize: 10 }} />
                <YAxis stroke="#3d6080" tick={{ fill: "#7aa8cc", fontSize: 10 }} allowDecimals={false} />
                <Tooltip contentStyle={TT_STYLE} labelStyle={{ color: "#7aa8cc" }} />
                <Area type="monotone" dataKey="告警" stroke="#7aa8cc" fill="url(#alertGrad)" strokeWidth={1.5} />
                <Area type="monotone" dataKey="攻击" stroke="#00e5ff" fill="url(#attackGrad)" strokeWidth={2}
                  style={{ filter: "drop-shadow(0 0 4px rgba(0,229,255,0.6))" }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="panel-cyber p-5">
          <h2 className="cyber-title mb-4">告警类型</h2>
          <div className="h-52">
            {alertByType.length === 0 ? (
              <div className="h-full flex items-center justify-center section-label">无数据</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={alertByType} dataKey="count" nameKey="name" cx="50%" cy="42%" outerRadius={62}
                    label={({ name, count }) => `${name} ${count}`} labelLine={false}
                    style={{ fontSize: 10 }}
                  >
                    {alertByType.map((entry, i) => (
                      <Cell key={entry.name} fill={entry.fill ?? PIE_COLORS[i % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Legend layout="horizontal" align="center" verticalAlign="bottom"
                    formatter={(value) => <span style={{ color: "#7aa8cc", fontSize: 10 }}>{value}</span>}
                  />
                  <Tooltip contentStyle={TT_STYLE} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* ── row 4: attack bar + radar + activity ─────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="panel-cyber p-5">
          <h2 className="cyber-title mb-4 flex items-center gap-2">
            <Swords className="w-3.5 h-3.5" />
            攻击类型分布
          </h2>
          <div className="h-48">
            {attackByType.length === 0 ? (
              <div className="h-full flex items-center justify-center section-label">无数据</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={attackByType} layout="vertical" margin={{ left: 8 }}>
                  <defs>
                    <linearGradient id="barGrad0" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#0060aa" />
                      <stop offset="100%" stopColor="#00e5ff" />
                    </linearGradient>
                    <linearGradient id="barGrad1" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#770030" />
                      <stop offset="100%" stopColor="#ff2060" />
                    </linearGradient>
                  </defs>
                  <XAxis type="number" stroke="#3d6080" tick={{ fill: "#7aa8cc", fontSize: 10 }} />
                  <YAxis type="category" dataKey="name" stroke="#3d6080" tick={{ fill: "#7aa8cc", fontSize: 10 }} width={70} />
                  <Tooltip contentStyle={TT_STYLE} />
                  <Bar dataKey="value" radius={[0, 3, 3, 0]} name="次数">
                    {attackByType.map((_, i) => (
                      <Cell key={i} fill={`url(#barGrad${i % 2})`} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* radar: attack type coverage */}
        <div className="panel-cyber p-5">
          <h2 className="cyber-title mb-4 flex items-center gap-2">
            <Cpu className="w-3.5 h-3.5" />
            威胁面覆盖
          </h2>
          <div className="h-48">
            {alerts.length === 0 ? (
              <div className="h-full flex items-center justify-center section-label">无数据</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart data={radarData} cx="50%" cy="50%" outerRadius={60}>
                  <PolarGrid stroke="rgba(0,229,255,0.15)" />
                  <PolarAngleAxis dataKey="subject" tick={{ fill: "#7aa8cc", fontSize: 9 }} />
                  <Radar dataKey="A" stroke="var(--accent)" fill="var(--accent)" fillOpacity={0.15} strokeWidth={1.5} />
                  <Tooltip contentStyle={TT_STYLE} />
                </RadarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* activity feed */}
        <div className="panel-cyber p-5">
          <h2 className="cyber-title mb-3 flex items-center gap-2">
            <Eye className="w-3.5 h-3.5" />
            实时动态
          </h2>
          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {activity.length === 0 ? (
              <p className="section-label">无</p>
            ) : (
              activity.map((item, i) => (
                <div key={i} className="flex items-start gap-2 px-2.5 py-1.5 text-xs rounded font-mono"
                  style={{ background: "rgba(0,229,255,0.03)", border: "1px solid rgba(0,229,255,0.07)" }}>
                  <span className="shrink-0 font-semibold"
                    style={{ color: item.type === "alert" ? (SEVERITY_COLORS[item.severity] || "#7aa8cc") : "var(--accent)" }}>
                    {item.type === "alert" ? "ALT" : "ATK"}
                  </span>
                  <span className="flex-1 truncate" style={{ color: "var(--text-dim)" }}>{item.text}</span>
                  <span className="shrink-0 text-right" style={{ color: "var(--text-faint)" }}>
                    {item.iso ? new Date(item.iso).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—"}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
