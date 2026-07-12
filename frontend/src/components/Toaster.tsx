import { Toaster as SonnerToaster } from "sonner";
import { useEffect, useState } from "react";

export function Toaster() {
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const check = () => setIsMobile(window.innerWidth < 768);
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  return (
    <SonnerToaster
      position={isMobile ? "top-center" : "bottom-right"}
      toastOptions={{
        className:
          "group border border-divider-strong bg-popover text-mono ba-text-sm text-foreground elevation-raised [&_[data-icon]]:text-primary [&_[data-close-button]]:text-muted-foreground/60 [&_[data-close-button]:hover]:text-foreground",
        duration: 2000,
        style: {
          padding: "12px 14px",
          paddingLeft: "10px",
          borderLeft: "3px solid hsl(var(--primary) / 0.6)",
        },
      }}
      visibleToasts={4}
      gap={8}
      closeButton
    />
  );
}
