import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { AttackAgentProvider } from "./contexts/AttackAgentContext";
import Dashboard from "./pages/Dashboard";
import ARPForge from "./pages/ARPForge";
import ThreatDetector from "./pages/ThreatDetector";
import AICenter from "./pages/AICenter";

const navItems = [
  { to: "/",       label: "态势感知" },
  { to: "/arp",    label: "ARP构造" },
  { to: "/detect", label: "威胁检测" },
  { to: "/ai",     label: "AI分析" },
];

export default function App() {
  return (
    <AttackAgentProvider>
      <BrowserRouter>
        <div className="min-h-screen flex flex-col" style={{ color: "var(--text)", background: "var(--canvas)" }}>

          {/* ── top nav ────────────────────────────────────────── */}
          <nav
            className="relative flex items-center gap-8 px-6 py-0"
            style={{
              background: "var(--surface)",
              borderBottom: "1px solid var(--border)",
              boxShadow: "0 1px 0 rgba(0,229,255,0.12), 0 4px 24px rgba(0,0,0,0.6)",
              height: "44px",
            }}
          >
            {/* accent line gradient – top edge */}
            <div className="nav-glow-line absolute inset-x-0 top-0" aria-hidden />

            {/* brand */}
            <span
              className="font-mono font-bold tracking-[0.35em] uppercase select-none"
              style={{ fontSize: "0.8rem", color: "var(--accent)", textShadow: "0 0 12px rgba(0,229,255,0.6)" }}
            >
              S E N T I N E L C L A W
            </span>

            {/* nav links */}
            <div className="flex items-center gap-7 h-full">
              {navItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === "/"}
                  className={({ isActive }) =>
                    `font-mono text-xs tracking-wider transition-colors duration-150 h-full flex items-center border-b-2 ${
                      isActive
                        ? "text-accent border-accent"
                        : "text-ink-dim border-transparent hover:text-accent hover:border-accent/40"
                    }`
                  }
                  style={({ isActive }) =>
                    isActive
                      ? { textShadow: "0 0 8px rgba(0,229,255,0.5)" }
                      : {}
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </div>

            {/* right: status dot */}
            <div className="ml-auto flex items-center gap-2">
              <span
                className="w-2 h-2 rounded-full animate-glow-pulse"
                style={{ background: "var(--accent)", boxShadow: "0 0 6px var(--accent)" }}
              />
              <span className="font-mono text-xs tracking-widest uppercase" style={{ color: "var(--text-dim)" }}>
                SYS:ONLINE
              </span>
            </div>
          </nav>

          {/* ── page content ───────────────────────────────────── */}
          <main className="flex-1 p-6">
            <Routes>
              <Route path="/"       element={<Dashboard />} />
              <Route path="/arp"    element={<ARPForge />} />
              <Route path="/detect" element={<ThreatDetector />} />
              <Route path="/ai"     element={<AICenter />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </AttackAgentProvider>
  );
}
