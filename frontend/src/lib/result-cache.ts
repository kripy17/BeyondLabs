import { useCallback, useState } from "react";

const PREFIX = "ba.rc.";

export function useResultCache<T>(key: string) {
  const cached = sessionStorage.getItem(PREFIX + key);
  const [data, setData] = useState<T | null>(cached ? (() => { try { return JSON.parse(cached); } catch { return null; } })() : null);
  const [ts, setTs] = useState<number>(data ? (() => { try { return JSON.parse(sessionStorage.getItem(PREFIX + key + ".ts") ?? "0"); } catch { return 0; } })() : 0);

  const save = useCallback((d: T) => {
    setData(d);
    setTs(Date.now());
    try { sessionStorage.setItem(PREFIX + key, JSON.stringify(d)); sessionStorage.setItem(PREFIX + key + ".ts", String(Date.now())); } catch {}
  }, [key]);

  const clear = useCallback(() => {
    setData(null); setTs(0);
    try { sessionStorage.removeItem(PREFIX + key); sessionStorage.removeItem(PREFIX + key + ".ts"); } catch {}
  }, [key]);

  const ago = ts ? Math.round((Date.now() - ts) / 1000) : 0;
  const agoLabel = ts ? (ago < 60 ? `${ago}s ago` : ago < 3600 ? `${Math.round(ago / 60)}m ago` : `${Math.round(ago / 3600)}h ago`) : "";

  return { data, save, clear, ts, agoLabel };
}
