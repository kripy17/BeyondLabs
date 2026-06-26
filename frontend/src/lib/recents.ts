import { useEffect, useState } from "react";
import { useRouterState } from "@tanstack/react-router";
import { findItem } from "./workspaces";

const KEY = "ba.recents.v1";
const MAX = 8;
const EVT = "ba:recents";

export function readRecents(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as string[]) : [];
  } catch { return []; }
}

function write(urls: string[]) {
  try {
    localStorage.setItem(KEY, JSON.stringify(urls));
    window.dispatchEvent(new Event(EVT));
  } catch { /* ignore */ }
}

export function pushRecent(url: string) {
  if (!findItem(url) || url === "/") return;
  const cur = readRecents().filter((u) => u !== url);
  write([url, ...cur].slice(0, MAX));
}

export function clearRecents() { write([]); }

export function useRecents(): string[] {
  const [list, setList] = useState<string[]>([]);
  useEffect(() => {
    setList(readRecents());
    const sync = () => setList(readRecents());
    window.addEventListener(EVT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(EVT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);
  return list;
}

export function useRouteRecorder() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  useEffect(() => { pushRecent(pathname); }, [pathname]);
}
