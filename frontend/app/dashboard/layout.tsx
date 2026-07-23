"use client";

import { UserButton } from "@clerk/nextjs";
import { Fingerprint, Radar, Settings2, Shield, Swords } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

import { useAppAuth } from "@/components/app-auth-provider";
import { cn } from "@/lib/utils";

const navigation = [
  {
    href: "/dashboard/systems",
    label: "Target Systems",
    icon: Radar
  },
  {
    href: "/dashboard",
    label: "Attack Runs",
    icon: Swords
  },
  {
    href: "/dashboard/trust-ledger",
    label: "Trust Ledger",
    icon: Fingerprint
  },
  {
    href: "/dashboard/settings",
    label: "Settings",
    icon: Settings2
  }
];

export default function DashboardLayout({
  children
}: Readonly<{
  children: ReactNode;
}>) {
  const pathname = usePathname();
  const { mode } = useAppAuth();

  return (
    <div className="min-h-screen py-6">
      <div className="container grid gap-6 lg:grid-cols-[280px_minmax(0,1fr)]">
        <aside className="flex min-h-[calc(100vh-3rem)] flex-col rounded-[2rem] border bg-white/85 p-6 shadow-[0_24px_70px_rgba(15,23,42,0.08)] backdrop-blur">
          <Link href="/dashboard" className="inline-flex items-center gap-3">
            <div className="rounded-2xl bg-primary p-3 text-primary-foreground shadow-lg">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <p className="font-[family-name:var(--font-heading)] text-xl font-semibold">ShadowLedger</p>
              <p className="text-xs uppercase tracking-[0.24em] text-muted-foreground">Protected workspace</p>
            </div>
          </Link>

          <div className="mt-10 space-y-2">
            {navigation.map(({ href, label, icon: Icon }) => {
              const isActive = href === "/dashboard" ? pathname === href || pathname.startsWith("/dashboard/runs") : pathname.startsWith(href);

              return (
                <Link
                  key={href}
                  href={href}
                  className={cn(
                    "flex items-center gap-3 rounded-2xl px-4 py-3 text-sm transition-colors",
                    isActive ? "bg-primary text-primary-foreground shadow-md" : "text-muted-foreground hover:bg-muted"
                  )}
                >
                  <Icon className="h-4 w-4" />
                  <span>{label}</span>
                </Link>
              );
            })}
          </div>

          <div className="mt-auto rounded-[1.75rem] bg-secondary p-5 text-secondary-foreground">
            <p className="text-xs uppercase tracking-[0.24em] opacity-70">Trust chain</p>
            <p className="mt-3 font-[family-name:var(--font-heading)] text-xl font-semibold">
              Every scored result is ready for ledger append.
            </p>
            <p className="mt-3 text-sm leading-7 opacity-80">
              Use the dashboard to launch a scan, then jump into a run detail page to inspect risk signals and
              the resulting evidence.
            </p>
          </div>
        </aside>

        <div className="min-w-0 rounded-[2rem] border bg-white/80 shadow-[0_24px_70px_rgba(15,23,42,0.08)] backdrop-blur">
          <header className="flex flex-col gap-4 border-b px-6 py-5 sm:flex-row sm:items-center sm:justify-between lg:px-8">
            <div>
              <p className="text-xs uppercase tracking-[0.26em] text-muted-foreground">Dashboard</p>
              <h1 className="mt-2 font-[family-name:var(--font-heading)] text-3xl font-semibold">
                Red-team orchestration for AI systems
              </h1>
            </div>
            {mode === "demo" ? (
              <span className="rounded-full bg-secondary px-3 py-2 text-xs font-medium text-secondary-foreground">
                Local demo
              </span>
            ) : (
              <UserButton afterSignOutUrl="/" />
            )}
          </header>

          <main className="min-w-0 p-6 lg:p-8">{children}</main>
        </div>
      </div>
    </div>
  );
}
