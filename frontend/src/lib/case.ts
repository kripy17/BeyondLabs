import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { storageGet, storageSet } from "@/lib/storage";

export type EntryKind = "note" | "evidence" | "decision" | "action" | "ioc";
export type Entry = { id: string; ts: string; kind: EntryKind; body: string };
export type Case = {
  id: string;
  title: string;
  tags: string[];
  createdAt: string;
  state: "active" | "closed";
  entries: Entry[];
};

const LS_KEY = "ba.cases.v2";
const LS_ACTIVE = "ba.cases.active";
const MAX_BODY = 5000;

function newId(prefix: string) { return `${prefix}-${crypto.randomUUID().slice(0, 8)}`; }

function loadAll(): Case[] { return storageGet<Case[]>(LS_KEY, []); }
function saveAll(list: Case[]) { storageSet(LS_KEY, list); }

export function useActiveCase() {
  const [active, setActive] = useState<Case | null>(null);

  useEffect(() => {
    const list = loadAll();
    const remembered = storageGet<string | null>(LS_ACTIVE, null);
    const found = remembered ? list.find((c) => c.id === remembered) : null;
    setActive(found ?? list[0] ?? null);
  }, []);

  const setActiveId = useCallback((id: string) => {
    const list = loadAll();
    const found = list.find((c) => c.id === id) ?? null;
    setActive(found);
    if (found) storageSet(LS_ACTIVE, id);
  }, []);

  const addEntry = useCallback((body: string, kind: EntryKind, source?: string) => {
    if (!active) { toast.error("No active case"); return; }
    const prefix = source ? `[from ${source}] ` : "";
    const truncated = (prefix + body).slice(0, MAX_BODY);
    const entry: Entry = { id: newId("e"), ts: new Date().toISOString(), kind, body: truncated };
    const updated: Case = { ...active, entries: [...active.entries, entry] };
    setActive(updated);
    const list = loadAll();
    saveAll(list.map((c) => (c.id === active.id ? updated : c)));
    toast.success("Added to case");
  }, [active]);

  return { activeCase: active, setActiveId, addEntry };
}
