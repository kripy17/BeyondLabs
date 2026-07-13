import { useState, useCallback } from "react";

const MAX = 20;

function lsKey(route: string) {
  return `ba.recent_inputs:${route}`;
}

function load(route: string): string[] {
  try {
    const raw = localStorage.getItem(lsKey(route));
    return raw ? (JSON.parse(raw) as string[]) : [];
  } catch {
    return [];
  }
}

function save(route: string, items: string[]) {
  try {
    localStorage.setItem(lsKey(route), JSON.stringify(items.slice(0, MAX)));
  } catch {}
}

export function useRecentInputs(route: string) {
  const [items, setItems] = useState<string[]>(() => load(route));

  const push = useCallback(
    (input: string) => {
      const trimmed = input.trim();
      if (!trimmed) return;
      setItems((prev) => {
        const next = [trimmed, ...prev.filter((i) => i !== trimmed)].slice(0, MAX);
        save(route, next);
        return next;
      });
    },
    [route],
  );

  const clear = useCallback(() => {
    setItems([]);
    save(route, []);
  }, [route]);

  return { items, push, clear };
}
