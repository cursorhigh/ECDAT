"use client";

import { Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { NavTooltip } from "@/components/ui/nav-tooltip";
import { useTheme } from "@/lib/theme";

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();
  const next = theme === "dark" ? "light" : "dark";
  return (
    <NavTooltip title={`Switch to ${next} theme`} description="Applies immediately and is remembered on this device.">
      <Button type="button" variant="ghost" size="icon" onClick={toggleTheme} aria-label={`Switch to ${next} theme`}>
        {theme === "dark" ? <Sun className="h-4 w-4" aria-hidden="true" /> : <Moon className="h-4 w-4" aria-hidden="true" />}
      </Button>
    </NavTooltip>
  );
}
