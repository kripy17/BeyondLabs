import { Toaster as SonnerToaster } from "sonner";

export function Toaster() {
  return (
    <SonnerToaster
      position="bottom-right"
      toastOptions={{
        className: "border border-border bg-popover text-foreground text-mono text-xs shadow-lg",
        duration: 2000,
      }}
      closeButton
    />
  );
}
