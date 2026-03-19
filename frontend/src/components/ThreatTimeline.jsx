const ALERT_TYPE_LABELS = {
  ARP_SPOOFING: "ARP 欺骗",
  ARP_FLOODING: "ARP 泛洪",
  ARP_SCANNING: "ARP 扫描",
  ARP_MITM: "ARP 中间人",
  GRATUITOUS_ARP_ABUSE: "无故 ARP 滥用",
  PORT_SCAN: "端口扫描",
  BRUTE_FORCE: "暴力破解",
  ABNORMAL_DNS: "异常 DNS",
  DNS_TUNNEL: "DNS 隧道",
  TRAFFIC_BURST: "流量突发",
  PERIODIC_HEARTBEAT: "周期心跳",
};

export default function ThreatTimeline({ alerts = [] }) {
  if (alerts.length === 0) {
    return (
      <div className="text-zinc-500 text-xs font-mono py-8 text-center">无</div>
    );
  }
  const severityColor = (s) => {
    if (s === "critical") return "bg-red-950/70 border-red-500/60 text-red-400";
    if (s === "high") return "bg-amber-950/50 border-accent/50 text-accent";
    if (s === "medium") return "bg-yellow-950/40 border-yellow-500/50 text-yellow-400";
    return "bg-surface-muted border-surface-border text-zinc-400";
  };
  return (
    <div className="space-y-3">
      {alerts.map((a, i) => (
        <div
          key={a.id || i}
          className={`rounded-lg border-l-4 p-3 ${severityColor(a.severity)}`}
        >
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs">{a.datetime}</span>
            <span className="px-2 py-0.5 rounded text-xs font-medium bg-accent/20 text-accent font-mono">
              {ALERT_TYPE_LABELS[a.alert_type] ?? a.alert_type}
            </span>
            <span className="text-xs opacity-80">{a.src_ip}</span>
          </div>
          <p className="text-sm mt-1">{a.description}</p>
          {a.evidence && Object.keys(a.evidence).length > 0 && (
            <pre className="text-xs mt-2 opacity-80 overflow-x-auto">
              {JSON.stringify(a.evidence, null, 0)}
            </pre>
          )}
        </div>
      ))}
    </div>
  );
}
