import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/threat-actors")({
  loader: () => { throw redirect({ to: "/intel" }); },
});
