import { cn } from "@/lib/utils"

export function Banner({
  text,
  tone,
}: {
  text: string
  tone: "neutral" | "warning" | "danger"
}) {
  return (
    <div
      className={cn(
        "rounded-xl px-4 py-2.5 text-sm",
        tone === "danger" && "border border-destructive/25 bg-destructive/10 text-destructive",
        tone === "warning" && "border border-primary/25 bg-primary/10 text-primary",
        tone === "neutral" && "border border-border/70 bg-background/75 text-muted-foreground",
      )}
    >
      {text}
    </div>
  )
}
