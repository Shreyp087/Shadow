import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function TrustLedgerPage() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Trust Ledger</CardTitle>
        <CardDescription>
          Tamper-evident ledger views will live here once the backend exposes ledger retrieval endpoints.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <p className="text-sm leading-7 text-muted-foreground">
          ShadowLedger already appends hashed audit entries during scans. This workspace section is ready for the
          future chain viewer and verification tools.
        </p>
      </CardContent>
    </Card>
  );
}
