import { type ReactNode } from "react";

export function TwoColumnOutput({
  left,
  right,
  ratio = "1:1",
}: {
  left: ReactNode;
  right: ReactNode;
  ratio?: "1:1" | "2:1" | "1:2" | "3:2" | "2:3";
}) {
  const gridCls =
    ratio === "2:1" ? "lg:grid-cols-[2fr_1fr]" :
    ratio === "1:2" ? "lg:grid-cols-[1fr_2fr]" :
    ratio === "3:2" ? "lg:grid-cols-[3fr_2fr]" :
    ratio === "2:3" ? "lg:grid-cols-[2fr_3fr]" :
    "lg:grid-cols-2";
  return (
    <div className={"grid gap-3 " + gridCls}>
      {left}
      {right}
    </div>
  );
}
