/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ["DM Sans", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
      colors: {
        canvas: {
          DEFAULT: "#060b18",
          lighter: "#0a1020",
          muted: "#0d1526",
        },
        surface: {
          DEFAULT: "#0c1628",
          elevated: "#112030",
          muted: "#0f1b2e",
          border: "#1c3050",
        },
        accent: {
          DEFAULT: "#00e5ff",
          light: "#40eeff",
          muted: "#00b8cc",
          dim: "rgba(0, 229, 255, 0.12)",
          glow: "rgba(0, 229, 255, 0.3)",
        },
        cyber: {
          pink: "#ff2060",
          green: "#00ff41",
          orange: "#ff6b00",
          purple: "#b44dff",
        },
        ink: {
          DEFAULT: "#cce4ff",
          dim: "#7aa8cc",
          faint: "#3d6080",
        },
      },
      boxShadow: {
        card:      "0 0 0 1px rgba(0,229,255,0.10), 0 2px 12px rgba(0,0,0,0.6)",
        "card-hover": "0 0 0 1px rgba(0,229,255,0.22), 0 4px 20px rgba(0,0,0,0.7)",
        nav:       "0 1px 0 0 rgba(0,229,255,0.15), 0 4px 24px rgba(0,0,0,0.5)",
        glow:      "0 0 24px rgba(0,229,255,0.35)",
        "glow-sm": "0 0 10px rgba(0,229,255,0.25)",
        "glow-pink":"0 0 18px rgba(255,32,96,0.4)",
      },
      animation: {
        "glow-pulse": "glow-pulse 2.4s ease-in-out infinite",
        "scan": "scan 4s linear infinite",
        "flicker": "flicker 8s step-end infinite",
      },
      keyframes: {
        "glow-pulse": {
          "0%,100%": { opacity: "1",   boxShadow: "0 0 8px rgba(0,229,255,0.2)" },
          "50%":      { opacity: "0.8", boxShadow: "0 0 22px rgba(0,229,255,0.4)" },
        },
        "scan": {
          "0%":   { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        "flicker": {
          "0%,95%,100%": { opacity: "1" },
          "96%":          { opacity: "0.85" },
          "97%":          { opacity: "1" },
          "98%":          { opacity: "0.7" },
          "99%":          { opacity: "1" },
        },
      },
    },
  },
  plugins: [],
}
