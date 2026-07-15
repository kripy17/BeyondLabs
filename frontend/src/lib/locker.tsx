import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { storageGet, storageSet } from "@/lib/storage";

const STORAGE_KEY = "ba.locker.v1";

export type LockerItem = {
  id: string;
  value: string;
  type: "ipv4" | "ipv6" | "domain" | "url" | "sha256" | "sha1" | "md5" | "email" | "file" | "cve" | "ja3" | "ua" | "text" | "unknown";
  source: string;
  note?: string;
  ts: number;
};

type Ctx = {
  items: LockerItem[];
  add: (item: Omit<LockerItem, "id" | "ts">) => void;
  remove: (id: string) => void;
  clear: () => void;
  updateNote: (id: string, note: string) => void;
  count: number;
};

const LockerCtx = createContext<Ctx>({
  items: [],
  add: () => {},
  remove: () => {},
  clear: () => {},
  updateNote: () => {},
  count: 0,
});

export function guessType(value: string): LockerItem["type"] {
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) return "ipv4";
  if (/^[0-9a-f:]+:[0-9a-f:]+$/i.test(value)) return "ipv6";
  if (/^[0-9a-f]{64}$/i.test(value)) return "sha256";
  if (/^[0-9a-f]{40}$/i.test(value)) return "sha1";
  if (/^[0-9a-f]{32}$/i.test(value)) return "md5";
  if (/^https?:\/\//i.test(value)) return "url";
  if (/^[\w.+-]+@[\w-]+\.[\w.]+$/.test(value)) return "email";
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(value) && value.includes(".")) return "domain";
  if (value.includes(".") && value.length > 3) return "file";
  return "unknown";
}

export function LockerProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<LockerItem[]>([]);
  const loaded = useRef(false);

  useEffect(() => {
    const raw = storageGet<LockerItem[] | null>(STORAGE_KEY, null);
    if (raw) setItems(raw);
    loaded.current = true;
  }, []);

  useEffect(() => {
    if (!loaded.current) return;
    storageSet(STORAGE_KEY, items);
  }, [items]);

  const add = useCallback((item: Omit<LockerItem, "id" | "ts">) => {
    setItems((prev) => {
      const dup = prev.find((i) => i.value === item.value && i.source === item.source);
      if (dup) return prev;
      const next: LockerItem = { ...item, id: crypto.randomUUID(), ts: Date.now() };
      return [next, ...prev];
    });
  }, []);

  const remove = useCallback((id: string) => {
    setItems((prev) => prev.filter((i) => i.id !== id));
  }, []);

  const clear = useCallback(() => setItems([]), []);

  const updateNote = useCallback((id: string, note: string) => {
    setItems((prev) => prev.map((i) => (i.id === id ? { ...i, note } : i)));
  }, []);

  const value = useMemo<Ctx>(() => ({ items, add, remove, clear, updateNote, count: items.length }), [items, add, remove, clear, updateNote]);

  return <LockerCtx.Provider value={value}>{children}</LockerCtx.Provider>;
}

export const useLocker = () => useContext(LockerCtx);
