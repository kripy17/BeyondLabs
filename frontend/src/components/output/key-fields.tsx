import { type ReactNode } from "react";
import { Field } from "@/components/soc";

export function KeyFields({ items }: { items: { label: string; value: ReactNode; tone?: "default" | "primary" | "success" | "warning" | "destructive" | "muted" }[] }) {
  return (
    <div className="grid gap-x-6 gap-y-0 grid-cols-2">
      {items.map((f, i) => (
        <Field key={i} label={f.label} value={f.value} tone={f.tone} />
      ))}
    </div>
  );
}
