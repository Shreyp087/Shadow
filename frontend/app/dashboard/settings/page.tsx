import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function SettingsPage() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Settings</CardTitle>
        <CardDescription>
          Environment, notification, and policy configuration controls can be added here as the product expands.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <p className="text-sm leading-7 text-muted-foreground">
          The current frontend is focused on scan orchestration, run monitoring, and backend contract coverage.
        </p>
      </CardContent>
    </Card>
  );
}
