export type PortChange = {
  port: number;
  type: "added" | "removed" | "changed";
  oldState?: string;
  newState?: string;
  service?: string;
};

export function computeNmapDiff(
  prev: { ports: { port: number; state: string; service?: string }[] },
  curr: { ports: { port: number; state: string; service?: string }[] }
): PortChange[] {
  const changes: PortChange[] = [];
  const prevMap = new Map(prev.ports.map((p) => [p.port, p]));
  const currMap = new Map(curr.ports.map((p) => [p.port, p]));

  for (const [port, cp] of currMap) {
    const pp = prevMap.get(port);
    if (!pp) {
      changes.push({ port, type: "added", newState: cp.state, service: cp.service });
    } else if (pp.state !== cp.state) {
      changes.push({ port, type: "changed", oldState: pp.state, newState: cp.state, service: cp.service });
    }
  }
  for (const [port, pp] of prevMap) {
    if (!currMap.has(port)) {
      changes.push({ port, type: "removed", oldState: pp.state, service: pp.service });
    }
  }
  return changes.sort((a, b) => a.port - b.port);
}
