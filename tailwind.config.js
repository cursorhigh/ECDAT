/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./**/templates/**/*.html",
    "./**/static/**/*.js",
  ],
  theme: {
    extend: {
      colors: {
        ecdat: {
          primary: "#38bdf8",
          "primary-dark": "#2a9fe0",
          success: "#34d399",
          warn: "#fbbf24",
          danger: "#f87171",
        },
        sidebar: {
          bg: "#0b0e14",
          "bg-top": "#111623",
          "bg-bottom": "#06070b",
          text: "#e3ebf6",
          muted: "#99a4b8",
          subtle: "#8f9db5",
          brand: "#f5f8fd",
          glass: "rgba(255,255,255,0.06)",
          "glass-strong": "rgba(255,255,255,0.10)",
          cyan: "#22d3ee",
          navy: "#0e1a30",
        },
        "glass-cyan": "#38bdf8",
        "glass-teal": "#2dd4bf",
      },
      backgroundImage: {
        "ecdat-gradient": "linear-gradient(180deg, #3d82f7 0%, #2f6fed 100%)",
        "ecdat-gradient-hover": "linear-gradient(180deg, #4b8bf8 0%, #2f6fed 100%)",
        "sidebar-angular":
          "conic-gradient(from 130deg at 20% -10%, #0e1a30 0deg, #22d3ee 60deg, #05070c 160deg, #0b1220 230deg, #22d3ee 300deg, #05070c 360deg)",
        "brand-glow": "radial-gradient(600px 300px at 85% -60px, rgba(47,111,237,0.12), transparent 70%)",
      },
      boxShadow: {
        modal: "0 20px 40px rgba(0, 0, 0, 0.2)",
        glass: "0 8px 32px rgba(0,0,0,0.45)",
        "node-active":
          "inset 0 1px 0 rgba(255,255,255,0.4), 0 4px 16px -4px rgba(34,211,238,0.8)",
        "glass-item":
          "inset 0 1px 0 rgba(255,255,255,0.28), inset 0 -1px 0 rgba(0,0,0,0.18), 0 8px 22px -8px rgba(6,20,40,0.65), 0 0 20px -6px rgba(56,200,255,0.35)",
      },
    },
  },
  plugins: [],
};
