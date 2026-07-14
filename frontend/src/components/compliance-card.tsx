import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { complianceFrameworks } from "@/lib/data";

/** Le score vient du dernier scan ; les référentiels restent illustratifs
    tant que le moteur de conformité n'est pas branché (étape suivante). */
export function ComplianceCard({
  score,
}: {
  score: { score: number; grade: string };
}) {
  return (
    <Card className="flex flex-col">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="grid gap-1">
            <CardTitle>Compliance</CardTitle>
            <CardDescription>Framework coverage</CardDescription>
          </div>
          <div className="flex size-14 flex-col items-center justify-center rounded-full border-2 border-primary/20">
            <span className="text-lg font-semibold leading-none">
              {score.grade}
            </span>
            <span className="text-[10px] text-muted-foreground">
              {score.score}/100
            </span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col justify-center gap-4">
        {complianceFrameworks.map((f) => {
          const pct = Math.round((f.passed / f.total) * 100);
          return (
            <div key={f.name} className="grid gap-1.5">
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium">{f.name}</span>
                <Badge variant="outline" className="tabular-nums">
                  {f.passed}/{f.total}
                </Badge>
              </div>
              <Progress value={pct} className="h-2" />
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
