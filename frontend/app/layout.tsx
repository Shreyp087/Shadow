import type { Metadata } from "next";
import { IBM_Plex_Mono, Space_Grotesk } from "next/font/google";
import type { ReactNode } from "react";

import { AppAuthProvider } from "@/components/app-auth-provider";

import "./globals.css";

const headingFont = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-heading"
});

const bodyFont = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "700"],
  variable: "--font-body"
});

export const metadata: Metadata = {
  title: "ShadowLedger",
  description: "Continuous adversarial testing with a tamper-evident trust ledger."
};

export default function RootLayout({
  children
}: Readonly<{
  children: ReactNode;
}>) {
  const clerkConfigured = Boolean(
    process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY && process.env.CLERK_SECRET_KEY
  );

  return (
    <html lang="en" className={`${headingFont.variable} ${bodyFont.variable}`}>
      <body className="font-[family-name:var(--font-body)]">
        <AppAuthProvider clerkConfigured={clerkConfigured}>{children}</AppAuthProvider>
      </body>
    </html>
  );
}
