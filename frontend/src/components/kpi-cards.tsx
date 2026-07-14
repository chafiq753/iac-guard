import { TrendingDown, TrendingUp } from "lucide-react";

import {
  Card,
  CardAction,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { Kpi } from "@/lib/data";

export function KpiCards({ kpis }: { kpis: Kpi[] }) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {kpis.map((kpi) => {
        const positive = kpi.delta >= 0;
        const Trend = positive ? TrendingUp : TrendingDown;
        return (
          <Card key={kpi.key}>
            <CardHeader>
              <CardDescription>{kpi.label}</CardDescription>
              <CardTitle className="text-2xl font-semibold tabular-nums">
                {kpi.value}
              </CardTitle>
              <CardAction>
                <Badge
                  variant="outline"
                  className={cn(
                    "gap-1",
                    positive
                      ? "text-emerald-700 dark:text-emerald-300"
                      : "text-red-700 dark:text-red-300"
                  )}
                >
                  <Trend className="size-3" />
                  {positive ? "+" : ""}
                  {kpi.delta}%
                </Badge>
              </CardAction>
            </CardHeader>
            <div className="px-6 pb-2 text-xs text-muted-foreground">
              {kpi.hint}
            </div>
          </Card>
        );
      })}
    </div>
  );
}
