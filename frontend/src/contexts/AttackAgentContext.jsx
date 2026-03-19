import { createContext, useContext, useState, useCallback, useRef } from "react";
import axios from "axios";

const AttackAgentContext = createContext(null);

export function AttackAgentProvider({ children }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesRef = useRef([]);
  messagesRef.current = messages;

  const sendMessage = useCallback(async (userMsg, fetchLogs) => {
    if (!userMsg?.trim()) return;
    const trimmed = userMsg.trim();
    const history = messagesRef.current.map((m) => ({ role: m.role, content: m.content }));
    setMessages((prev) => [...prev, { role: "user", content: trimmed }]);
    setInput("");
    setLoading(true);
    try {
      const res = await axios.post("/api/ai/attack-chat", {
        message: trimmed,
        history,
      });
      setMessages((prev) => [...prev, { role: "assistant", content: res.data.response || "" }]);
      if (typeof fetchLogs === "function") await fetchLogs();
    } catch (e) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "请求失败: " + (e.response?.data?.detail || e.message) },
      ]);
    } finally {
      setLoading(false);
    }
  }, []);

  const value = {
    messages,
    setMessages,
    input,
    setInput,
    loading,
    sendMessage,
  };

  return (
    <AttackAgentContext.Provider value={value}>
      {children}
    </AttackAgentContext.Provider>
  );
}

export function useAttackAgent() {
  const ctx = useContext(AttackAgentContext);
  if (!ctx) throw new Error("useAttackAgent must be used within AttackAgentProvider");
  return ctx;
}
