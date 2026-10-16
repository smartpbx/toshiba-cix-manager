import { Monitor, Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useStore } from "@/store/useStore";

export function ThemeToggle() {
  const { theme, setTheme } = useStore((s) => ({
    theme: s.theme,
    setTheme: s.setTheme,
  }));
  const next = theme === "system" ? "light" : theme === "light" ? "dark" : "system";
  const Icon = theme === "dark" ? Moon : theme === "light" ? Sun : Monitor;
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setTheme(next)}
      title={`Theme: ${theme} (click for ${next})`}
    >
      <Icon className="h-4 w-4" />
    </Button>
  );
}
