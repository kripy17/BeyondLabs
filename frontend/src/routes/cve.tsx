import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/cve")({
  loader: () => { throw redirect({ to: "/intel" }); },
});
