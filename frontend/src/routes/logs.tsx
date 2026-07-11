import { createFileRoute, redirect } from "@tanstack/react-router";
export const Route = createFileRoute("/logs")({
  loader: () => { throw redirect({ to: "/siem" }); },
});
