import { createFileRoute, redirect } from "@tanstack/react-router";

export const Route = createFileRoute("/hash-lookup")({
  loader: () => { throw redirect({ to: "/intel" }); },
});
