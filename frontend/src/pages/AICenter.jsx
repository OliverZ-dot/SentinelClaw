import { useState, useRef, useEffect } from "react";
import axios from "axios";
import ReactMarkdown from "react-markdown";

const API = "/api/ai";

export default function AICenter() {
  const [messages, setMessages] = useState([
    { role: "assistant", content: "告警分析、攻击链重构、报告生成。" },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendMessage = async () => {
    if (!input.trim() || loading) return;
    const userMsg = { role: "user", content: input };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);
    try {
      const history = messages.map((m) => ({ role: m.role, content: m.content }));
      const res = await axios.post(`${API}/chat`, { message: input, history });
      setMessages((prev) => [...prev, { role: "assistant", content: res.data.response }]);
    } catch (e) {
      setMessages((prev) => [...prev, { role: "assistant", content: `ERR: ${e.message}` }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full max-w-4xl mx-auto space-y-4">
      <h1 className="cyber-title">AI 分析</h1>

      {/* chat window */}
      <div
        className="panel-cyber p-4 overflow-y-auto min-h-96 max-h-[60vh] space-y-4"
        style={{ scrollbarWidth: "thin", scrollbarColor: "rgba(0,229,255,0.2) transparent" }}
      >
        {messages.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className="max-w-2xl rounded px-4 py-3 text-sm"
              style={
                msg.role === "user"
                  ? {
                      background: "rgba(0,229,255,0.1)",
                      border: "1px solid rgba(0,229,255,0.35)",
                      color: "var(--accent)",
                      fontFamily: "JetBrains Mono, monospace",
                    }
                  : {
                      background: "rgba(0,229,255,0.04)",
                      border: "1px solid rgba(0,229,255,0.12)",
                      color: "var(--text)",
                    }
              }
            >
              {msg.role === "assistant" && (
                <span className="section-label block mb-2">SENTINEL</span>
              )}
              {msg.role === "assistant" ? (
                <div
                  className="prose prose-sm max-w-none"
                  style={{ color: "var(--text-dim)" }}
                >
                  <ReactMarkdown>{msg.content}</ReactMarkdown>
                </div>
              ) : (
                msg.content
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div
              className="rounded px-4 py-3 text-xs font-mono animate-pulse"
              style={{ background: "rgba(0,229,255,0.06)", border: "1px solid rgba(0,229,255,0.2)", color: "var(--accent)" }}
            >
              PROCESSING…
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>

      {/* quick commands */}
      <div className="flex gap-2 flex-wrap">
        {["重构攻击链", "风险评估", "生成报告", "高危威胁"].map((cmd) => (
          <button
            key={cmd}
            onClick={() => setInput(cmd)}
            className="font-mono text-xs px-3 py-1 rounded transition-colors"
            style={{
              background: "rgba(0,229,255,0.05)",
              border: "1px solid rgba(0,229,255,0.2)",
              color: "var(--text-dim)",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.borderColor = "rgba(0,229,255,0.5)"; e.currentTarget.style.color = "var(--accent)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.borderColor = "rgba(0,229,255,0.2)"; e.currentTarget.style.color = "var(--text-dim)"; }}
          >
            {cmd}
          </button>
        ))}
      </div>

      {/* input row */}
      <div className="flex gap-3">
        <input
          className="cyber-input flex-1"
          style={{ padding: "10px 14px" }}
          placeholder="提问…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && sendMessage()}
        />
        <button onClick={sendMessage} disabled={loading} className="btn-cyber-solid px-6">
          发送
        </button>
      </div>
    </div>
  );
}
