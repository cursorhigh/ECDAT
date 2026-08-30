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
          primary: "#2f6fed",
          "primary-dark": "#2459c4",
          success: "#16a34a",
          warn: "#d97706",
          danger: "#dc2626",
        },
        sidebar: {
          bg: "#14181d",
          text: "#c8cdd4",
          muted: "#5c6470",
        },
      },
      boxShadow: {
        modal: "0 20px 40px rgba(0, 0, 0, 0.2)",
      },
    },
  },
  plugins: [],
};
