import { useState, useCallback, useEffect } from "react";

export type PanelNavAction = 
  | { key: "j" | "k"; label: "Next item" | "Previous item" }
  | { key: "y"; label: "Copy selected" }
  | { key: "e"; label: "Enrich selected IOC" }
  | { key: "c"; label: "Attach to case" }
  | { key: "."; label: "Context menu" };

export function usePanelNav<T>(items: T[], options?: {
  onCopy?: (item: T) => void;
  onEnrich?: (item: T) => void;
  onAttach?: (item: T) => void;
  onContext?: (item: T) => void;
}) {
  const [index, setIndex] = useState(0);

  useEffect(() => {
    if (index >= items.length) setIndex(Math.max(0, items.length - 1));
  }, [items.length, index]);

  const handleKey = useCallback((e: KeyboardEvent) => {
    if (!items.length) return;
    const tag = (e.target as HTMLElement)?.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

    const item = items[index];
    switch (e.key) {
      case "j": e.preventDefault(); setIndex((i) => Math.min(i + 1, items.length - 1)); break;
      case "k": e.preventDefault(); setIndex((i) => Math.max(i - 1, 0)); break;
      case "y": e.preventDefault(); options?.onCopy?.(item); break;
      case "e": e.preventDefault(); options?.onEnrich?.(item); break;
      case "c": e.preventDefault(); options?.onAttach?.(item); break;
      case ".": e.preventDefault(); options?.onContext?.(item); break;
    }
  }, [items, index, options]);

  useEffect(() => {
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [handleKey]);

  const selected = items[index] ?? null;

  return { index, setIndex, selected };
}
