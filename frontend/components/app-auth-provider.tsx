"use client";

import { ClerkProvider, useAuth } from "@clerk/nextjs";
import { createContext, useContext, useMemo, type PropsWithChildren } from "react";

import { isLocalDemoAuthEnabled } from "@/lib/auth-mode";

type TokenGetter = ReturnType<typeof useAuth>["getToken"];

type AppAuthValue = {
  mode: "demo" | "clerk";
  getToken: TokenGetter;
};

const AppAuthContext = createContext<AppAuthValue | null>(null);
const demoGetToken: TokenGetter = async () => null;
const demoAuthValue: AppAuthValue = { mode: "demo", getToken: demoGetToken };

export function AppAuthProvider({ children }: PropsWithChildren) {
  if (isLocalDemoAuthEnabled()) {
    return <AppAuthContext.Provider value={demoAuthValue}>{children}</AppAuthContext.Provider>;
  }

  return (
    <ClerkProvider>
      <ClerkAuthBridge>{children}</ClerkAuthBridge>
    </ClerkProvider>
  );
}

function ClerkAuthBridge({ children }: PropsWithChildren) {
  const { getToken } = useAuth();
  const value = useMemo<AppAuthValue>(() => ({ mode: "clerk", getToken }), [getToken]);

  return <AppAuthContext.Provider value={value}>{children}</AppAuthContext.Provider>;
}

export function useAppAuth() {
  const context = useContext(AppAuthContext);

  if (!context) {
    throw new Error("useAppAuth must be used within AppAuthProvider");
  }

  return context;
}
