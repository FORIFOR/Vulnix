export type Theme = "system" | "light" | "dark";
export const THEME_KEY = "aegis-theme";

/** Runs before paint (injected as a string) to avoid a flash of the wrong theme. */
export const THEME_SCRIPT = `(function(){try{
  var t=localStorage.getItem("${THEME_KEY}")||"system";
  var dark=t==="dark"||(t==="system"&&matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark",dark);
}catch(e){}})();`;

export function applyTheme(theme: Theme): void {
  const dark = theme === "dark" ||
    (theme === "system" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* private mode / storage blocked: theme still applies for this session */
  }
}

export function readTheme(): Theme {
  try {
    const t = localStorage.getItem(THEME_KEY);
    if (t === "light" || t === "dark" || t === "system") return t;
  } catch {
    /* ignore */
  }
  return "system";
}

// Minimal external store so components read the preference with
// useSyncExternalStore (SSR-safe, no setState-in-effect).
const listeners = new Set<() => void>();

export function subscribeTheme(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export const getThemeSnapshot = readTheme;
export const getThemeServerSnapshot = (): Theme => "system";

export function setTheme(theme: Theme): void {
  applyTheme(theme);
  listeners.forEach((cb) => cb());
}
