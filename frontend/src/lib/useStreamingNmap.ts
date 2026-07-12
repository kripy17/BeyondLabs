import { useState, useCallback } from "react";

export type StreamEvent = {
  type: "start" | "stdout" | "error" | "done";
  command?: string;
  line?: string;
  message?: string;
  returncode?: number;
};

export function useStreamingNmap() {
  const [lines, setLines] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [command, setCommand] = useState<string | null>(null);

  const start = useCallback(async (target: string, mode: string, flags?: string) => {
    setRunning(true);
    setError(null);
    setLines([]);
    setCommand(null);
    try {
      const res = await fetch("/api/network/nmap/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, mode, flags }),
      });
      if (!res.ok) { setError(`Server error: ${res.status}`); setRunning(false); return; }
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop() || "";
        for (const part of parts) {
          for (const line of part.split("\n")) {
            if (line.startsWith("data: ")) {
              try {
                const event: StreamEvent = JSON.parse(line.slice(6));
                if (event.type === "start") setCommand(event.command || null);
                else if (event.type === "stdout") setLines((prev) => [...prev, event.line!]);
                else if (event.type === "error") { setError(event.message || null); setRunning(false); }
                else if (event.type === "done") setRunning(false);
              } catch {}
            }
          }
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Connection failed");
      setRunning(false);
    }
  }, []);

  return { lines, running, error, command, start };
}
