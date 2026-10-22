import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { Severity, AlertStatus } from "@/lib/data";

const severityStyles: Record<Severity, string> = {
  critical:
    "bg-red-500/12 text-red-700 dark:bg-red-500/18 dark:text-red-300",
  high: "bg-orange-500/12 text-orange-700 dark:bg-orange-500/18 dark:text-orange-300",
  medium:
    "bg-amber-500/15 text-amber-700 dark:bg-amber-500/18 dark:text-amber-300",
  low: "bg-sky-500/12 text-sky-700 dark:bg-sky-500/18 dark:text-sky-300",
  info: "bg-muted text-muted-foreground",
};

/** Finding couvert par une exception de politique (règle ignorée). */
export function ExceptionBadge({ className }: { className?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn("border-violet-500/40 text-violet-700 dark:text-violet-300", className)}
      title="Couvert par une exception : exclu du score et du seuil de blocage"
    >
      Exception
    </Badge>
  );
}

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <Badge
      className={cn("capitalize", severityStyles[severity], className)}
      variant="secondary"
    >
      {severity}
    </Badge>
  );
}

const statusStyles: Record<AlertStatus, string> = {
  open: "bg-red-500/10 text-red-700 dark:text-red-300",
  acknowledged: "bg-amber-500/12 text-amber-700 dark:text-amber-300",
  resolved:
    "bg-emerald-500/12 text-emerald-700 dark:bg-emerald-500/18 dark:text-emerald-300",
  false_positive: "bg-muted text-muted-foreground",
};

const statusLabels: Record<AlertStatus, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  false_positive: "False positive",
};

export function StatusBadge({ status }: { status: AlertStatus }) {
  return (
    <Badge variant="outline" className={cn(statusStyles[status])}>
      {statusLabels[status]}
    </Badge>
  );
}
