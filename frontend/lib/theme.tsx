"use client";

import { createContext, useContext, useEffect, useState } from "react";

type Theme = "dark" | "light";

type ThemeContextValue = {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: Readonly<{ children: React.ReactNode }>) {
  const [theme, setTheme] = useState<Theme>("dark");

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const saved = window.localStorage.getItem("ecdat.theme");
      const next: Theme = saved === "light" || saved === "dark" ? saved : "dark";
      setTheme(next);
      document.documentElement.classList.toggle("dark", next === "dark");
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  const setNextTheme = (next: Theme) => {
    setTheme(next);
    window.localStorage.setItem("ecdat.theme", next);
    document.documentElement.classList.toggle("dark", next === "dark");
  };

  return (
    <ThemeContext.Provider value={{ theme, setTheme: setNextTheme, toggleTheme: () => setNextTheme(theme === "dark" ? "light" : "dark") }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const value = useContext(ThemeContext);
  if (!value) throw new Error("useTheme must be used inside ThemeProvider");
  return value;
}
