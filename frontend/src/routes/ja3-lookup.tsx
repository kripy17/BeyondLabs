import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/ja3-lookup")({
  loader: () => { throw redirect({ to: "/intel" }); },
});
