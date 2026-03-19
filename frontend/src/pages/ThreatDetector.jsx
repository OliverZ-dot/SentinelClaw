import { useState, useEffect } from "react";
import axios from "axios";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import ThreatTimeline from "../components/ThreatTimeline";
import AttackChainGraph from "../components/AttackChainGraph";

const API_DETECT = "/api/detect";
const API_AI = "/api/ai";
const STORAGE_ALERTS = "sentinelai_detect_alerts";
const STORAGE_ATTACK_CHAIN = "sentinelai_detect_attack_chain";
const STORAGE_REPORT = "sentinelai_detect_report";
const LIVE_ALERTS_POLL_MS = 2000;

export default function ThreatDetector() {
  const [alerts, setAlerts] = useState(() => {
    try {
      const raw = sessionStorage.getItem(STORAGE_ALERTS);
      return raw ? JSON.parse(raw) : [];
    } catch {
      return [];
    }
  });
  const [attackChain, setAttackChain] = useState(() => {
    try {
      const raw = sessionStorage.getItem(STORAGE_ATTACK_CHAIN);
      return raw ? JSON.parse(raw) : {};
    } catch {
      return {};
    }
  });
  const [report, setReport] = useState(() => {
    try {
      return sessionStorage.getItem(STORAGE_REPORT) || "";
    } catch {
      return "";
    }
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [autoInterface, setAutoInterface] = useState("eth0");
  const [capturing, setCapturing] = useState(false);
  const [stopLoading, setStopLoading] = useState(false);
  const [packetsCount, setPacketsCount] = useState(0);

  useEffect(() => {
    sessionStorage.setItem(STORAGE_ALERTS, JSON.stringify(alerts));
  }, [alerts]);
  useEffect(() => {
    sessionStorage.setItem(STORAGE_ATTACK_CHAIN, JSON.stringify(attackChain));
  }, [attackChain]);
  useEffect(() => {
    sessionStorage.setItem(STORAGE_REPORT, report);
  }, [report]);


  const syncCaptureStatus = async () => {
    try {
      const res = await axios.get(`${API_DETECT}/live/status`);
      setCapturing(Boolean(res.data?.capturing));
    } catch {
      setCapturing(false);
    }
  };

  useEffect(() => {
    syncCaptureStatus();
    const onFocus = () => syncCaptureStatus();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, []);

  // 抓包进行中时轮询当前缓冲区告警与包数，实时更新告警时间线
  useEffect(() => {
    if (!capturing) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const res = await axios.get(`${API_DETECT}/live/current-alerts`);
        if (!cancelled) {
          setAlerts(res.data.alerts || []);
          setPacketsCount(res.data.packets_count ?? 0);
        }
      } catch {
        if (!cancelled) {
          setAlerts([]);
          setPacketsCount(0);
        }
      }
    };
    poll();
    const t = setInterval(poll, LIVE_ALERTS_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [capturing]);

  const handleStartCapture = async () => {
    setError("");
    try {
      await axios.post(`${API_DETECT}/live/start`, null, {
        params: { interface: autoInterface },
      });
      setCapturing(true);
      setAlerts([]);
      setPacketsCount(0);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    }
  };

  const handleStopCaptureAndDetect = async () => {
    setError("");
    setStopLoading(true);
    try {
      const res = await axios.post(`${API_DETECT}/live/stop`);
      setAlerts(res.data.alerts || []);
      setCapturing(false);
      if ((res.data.alerts || []).length > 0) {
        await axios.post(`${API_AI}/sync-alerts`, { alerts: res.data.alerts });
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
      setCapturing(false);
      setAlerts([]);
    } finally {
      setStopLoading(false);
    }
  };

  const handleReconstructChain = async () => {
    if (alerts.length === 0) {
      setError("无告警");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const res = await axios.post(`${API_AI}/reconstruct-chain`, { alerts });
      setAttackChain(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async () => {
    if (alerts.length === 0) {
      setError("无告警");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const res = await axios.post(`${API_AI}/generate-report`, { alerts });
      setAttackChain(res.data.attack_chain || {});
      setReport(res.data.report || "");
    } catch (err) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <h1 className="cyber-title">威胁检测</h1>

      <section className="panel-cyber p-5">
        <h2 className="cyber-title mb-3">捕获</h2>
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="section-label block mb-1">IFACE</label>
            <input
              className="cyber-input w-28"
              value={autoInterface}
              onChange={(e) => setAutoInterface(e.target.value)}
              disabled={capturing}
            />
          </div>
          <button onClick={handleStartCapture} disabled={capturing} className="btn-cyber">
            {capturing ? "CAPTURING…" : "开始抓包"}
          </button>
          <button onClick={handleStopCaptureAndDetect} disabled={!capturing || stopLoading} className="btn-cyber-solid">
            {stopLoading ? "检测中…" : "停止并检测"}
          </button>
          {capturing && (
            <span className="font-mono text-xs" style={{ color: "var(--accent)" }}>{packetsCount} pkts</span>
          )}
        </div>
      </section>

      <section className="panel-cyber p-5">
        <h2 className="cyber-title mb-3">分析</h2>
        <div className="flex flex-wrap gap-2">
          <button onClick={handleReconstructChain} disabled={loading || alerts.length === 0} className="btn-cyber">
            重构攻击链
          </button>
          <button onClick={handleGenerateReport} disabled={loading || alerts.length === 0} className="btn-cyber-solid">
            生成报告
          </button>
        </div>
      </section>

      {error && (
        <div className="panel px-4 py-2 font-mono text-xs" style={{ borderColor: "rgba(255,32,96,0.5)", color: "#ff6080" }}>
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="panel-cyber p-5">
          <h2 className="cyber-title mb-3">告警</h2>
          <ThreatTimeline alerts={alerts} />
        </div>
        <div className="panel-cyber p-5">
          <h2 className="cyber-title mb-3">攻击链</h2>
          <AttackChainGraph attackChain={attackChain} />
        </div>
      </div>

      {report && (
        <div className="panel-cyber p-5">
          <h2 className="cyber-title mb-3">报告</h2>
          <div className="report-markdown">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{report}</ReactMarkdown>
          </div>
        </div>
      )}
    </div>
  );
}
