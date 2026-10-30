"use client";

import { SignInButton, SignedIn, SignedOut } from "@clerk/nextjs";
import { ArrowRight, Fingerprint, Orbit, ShieldAlert } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/ui/button";
import { useAppAuth } from "@/components/app-auth-provider";

const signals = [
  {
    title: "Adaptive red-team prompts",
    description: "Target-specific attack vectors are tuned before each scan instead of replaying generic payloads.",
    icon: Orbit
  },
  {
    title: "AI risk scoring",
    description: "Every response is analyzed for severity so teams can prioritize the moments that matter.",
    icon: ShieldAlert
  },
  {
    title: "Tamper-evident trust chain",
    description: "Each result is hashed into an append-only audit trail for defensible reporting.",
    icon: Fingerprint
  }
];

export default function HomePage() {
  const { mode } = useAppAuth();

  return (
    <main className="relative overflow-hidden">
      <div className="absolute inset-0 -z-20 bg-ledger-grid bg-[size:44px_44px] opacity-25" />
      <div className="absolute inset-x-0 top-0 -z-10 h-[520px] bg-[radial-gradient(circle_at_top,rgba(15,118,110,0.22),transparent_55%),radial-gradient(circle_at_80%_20%,rgba(249,115,22,0.18),transparent_30%)]" />

      <section className="container flex min-h-screen flex-col justify-center gap-14 py-20">
        <div className="grid items-center gap-10 lg:grid-cols-[minmax(0,1.15fr)_minmax(320px,0.85fr)]">
          <div className="max-w-4xl space-y-8">
            <span className="inline-flex items-center rounded-full border bg-white/85 px-4 py-2 text-xs uppercase tracking-[0.3em] text-muted-foreground shadow-sm backdrop-blur">
              ShadowLedger
            </span>
            <div className="space-y-5">
              <h1 className="max-w-3xl font-[family-name:var(--font-heading)] text-5xl font-bold leading-tight tracking-tight md:text-7xl">
                See how an AI system breaks before attackers do.
              </h1>
              <p className="max-w-2xl text-base leading-8 text-muted-foreground md:text-lg">
                ShadowLedger runs adversarial scans, scores the blast radius, and seals each result into a
                verifiable trust ledger so teams can move from hunches to evidence.
              </p>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row">
              {mode === "unavailable" ? (
                <Button disabled size="lg" aria-describedby="workspace-availability">
                  Get Started
                </Button>
              ) : mode === "demo" ? (
                <Button asChild size="lg" className="gap-2">
                  <Link href="/dashboard" prefetch={false}>
                    Get Started
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </Button>
              ) : (
                <>
                  <SignedOut>
                    <SignInButton mode="modal">
                      <Button size="lg" className="gap-2">
                        Get Started
                        <ArrowRight className="h-4 w-4" />
                      </Button>
                    </SignInButton>
                  </SignedOut>
                  <SignedIn>
                    <Button asChild size="lg" className="gap-2">
                      <Link href="/dashboard" prefetch={false}>
                        Get Started
                        <ArrowRight className="h-4 w-4" />
                      </Link>
                    </Button>
                  </SignedIn>
                </>
              )}
              {mode === "unavailable" ? (
                <Button disabled size="lg" variant="outline" aria-describedby="workspace-availability">
                  Open Workspace
                </Button>
              ) : (
                <Button asChild size="lg" variant="outline">
                  <Link href="/dashboard/systems" prefetch={false}>
                    Open Workspace
                  </Link>
                </Button>
              )}
            </div>
            {mode === "unavailable" ? (
              <p id="workspace-availability" className="text-sm text-muted-foreground">
                Workspace access will be available soon.
              </p>
            ) : null}
          </div>

          <div className="rounded-[2rem] border bg-white/85 p-6 shadow-[0_30px_90px_rgba(15,23,42,0.10)] backdrop-blur">
            <div className="rounded-[1.5rem] bg-slate-950 p-6 text-white shadow-inner">
              <div className="flex items-center justify-between border-b border-white/10 pb-4">
                <div>
                  <p className="text-xs uppercase tracking-[0.28em] text-teal-200/70">Live posture snapshot</p>
                  <h2 className="mt-2 font-[family-name:var(--font-heading)] text-2xl">ShadowLedger Console</h2>
                </div>
                <span className="inline-flex items-center rounded-full bg-teal-400/15 px-3 py-1 text-xs text-teal-200">
                  Audit Ready
                </span>
              </div>

              <div className="mt-6 grid gap-4 sm:grid-cols-3">
                <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Scan cadence</p>
                  <p className="mt-3 text-3xl font-semibold">24/7</p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Risk routing</p>
                  <p className="mt-3 text-3xl font-semibold">AI-scored</p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-400">Evidence trail</p>
                  <p className="mt-3 text-3xl font-semibold">Hashed</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="grid gap-5 md:grid-cols-3">
          {signals.map(({ title, description, icon: Icon }) => (
            <article
              key={title}
              className="rounded-[1.5rem] border bg-white/85 p-6 shadow-[0_20px_60px_rgba(15,23,42,0.08)] backdrop-blur"
            >
              <div className="mb-4 inline-flex rounded-2xl bg-secondary p-3 text-secondary-foreground">
                <Icon className="h-5 w-5" />
              </div>
              <h2 className="font-[family-name:var(--font-heading)] text-xl font-semibold">{title}</h2>
              <p className="mt-3 text-sm leading-7 text-muted-foreground">{description}</p>
            </article>
          ))}
        </div>
      </section>
    </main>
  );
}
