import { clerkMiddleware, createRouteMatcher } from "@clerk/nextjs/server";
import { type NextFetchEvent, type NextRequest, NextResponse } from "next/server";

import { isLocalDemoAuthEnabled } from "@/lib/auth-mode";

const isProtectedRoute = createRouteMatcher(["/dashboard(.*)"]);

const authenticatedMiddleware = clerkMiddleware(async (auth, request) => {
  if (isProtectedRoute(request)) {
    await auth.protect();
  }
});

export default function middleware(request: NextRequest, event: NextFetchEvent) {
  if (isLocalDemoAuthEnabled()) {
    return NextResponse.next();
  }

  if (!process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY || !process.env.CLERK_SECRET_KEY) {
    return isProtectedRoute(request)
      ? NextResponse.redirect(new URL("/", request.url))
      : NextResponse.next();
  }

  return authenticatedMiddleware(request, event);
}

export const config = {
  runtime: "nodejs",
  matcher: [
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    "/(api|trpc)(.*)"
  ]
};
