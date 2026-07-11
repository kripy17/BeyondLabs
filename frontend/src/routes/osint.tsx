import { createFileRoute, redirect } from "@tanstack/react-router";
export const Route = createFileRoute("/osint")({
  loader: () => { throw redirect({ to: "/recon" }); },
});
