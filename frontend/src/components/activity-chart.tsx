"use client";

import { Area, AreaChart, CartesianGrid, XAxis } from "recharts";

import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
  CardContent,
} from "@/components/ui/card";
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Badge } from "@/components/ui/badge";
import type { ActivityPoint } from "@/lib/data";

const chartConfig = {
  critical: { label: "Critical", color: "var(--chart-1)" },
  high: { label: "High", color: "var(--chart-2)" },
  medium: { label: "Medium", color: "var(--chart-3)" },
} satisfies ChartConfig;

export function ActivityChart({ series }: { series: ActivityPoint[] }) {
  return (
    <Card className="pt-0">
      <CardHeader className="flex flex-row items-center gap-2 space-y-0 border-b py-5">
        <div className="grid flex-1 gap-1">
          <CardTitle>Finding Activity</CardTitle>
          <CardDescription>
            New findings by severity across all repositories
          </CardDescription>
        </div>
        <Badge variant="outline">Last 7 days</Badge>
      </CardHeader>
      <CardContent className="px-2 pt-4 sm:px-6 sm:pt-6">
        <ChartContainer config={chartConfig} className="aspect-auto h-[260px] w-full">
          <AreaChart data={series}>
            <defs>
              {(["critical", "high", "medium"] as const).map((key) => (
                <linearGradient key={key} id={`fill-${key}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={`var(--color-${key})`} stopOpacity={0.8} />
                  <stop offset="95%" stopColor={`var(--color-${key})`} stopOpacity={0.08} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid vertical={false} />
            <XAxis
              dataKey="date"
              tickLine={false}
              axisLine={false}
              tickMargin={8}
              minTickGap={24}
              tickFormatter={(value) =>
                new Date(value).toLocaleDateString("en-US", {
                  month: "short",
                  day: "numeric",
                })
              }
            />
            <ChartTooltip
              cursor={false}
              content={
                <ChartTooltipContent
                  labelFormatter={(value) =>
                    new Date(value).toLocaleDateString("en-US", {
                      month: "short",
                      day: "numeric",
                    })
                  }
                  indicator="dot"
                />
              }
            />
            <Area dataKey="medium" type="natural" fill="url(#fill-medium)" stroke="var(--color-medium)" stackId="a" />
            <Area dataKey="high" type="natural" fill="url(#fill-high)" stroke="var(--color-high)" stackId="a" />
            <Area dataKey="critical" type="natural" fill="url(#fill-critical)" stroke="var(--color-critical)" stackId="a" />
            <ChartLegend content={<ChartLegendContent />} />
          </AreaChart>
        </ChartContainer>
      </CardContent>
    </Card>
  );
}
