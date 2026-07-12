export type TimelineEvent = {
  id: string;
  ts: string;
  source: string;
  verb: string;
  detail: string;
  target?: string;
  result?: string;
};

const STORAGE_KEY = "ba.timeline.v1";
const MAX_EVENTS = 500;

export function pushTimelineEvent(event: Omit<TimelineEvent, "id" | "ts">): void {
  const events = getTimelineEvents();
  events.unshift({
    ...event,
    id: crypto.randomUUID(),
    ts: new Date().toISOString(),
  });
  if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(events)); } catch {}
}

export function getTimelineEvents(): TimelineEvent[] {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
  } catch { return []; }
}

export function clearTimeline(): void {
  localStorage.removeItem(STORAGE_KEY);
}
