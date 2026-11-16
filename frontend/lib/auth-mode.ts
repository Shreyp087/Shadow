export function isLocalDemoAuthEnabled() {
  return process.env.NODE_ENV === "development" && process.env.NEXT_PUBLIC_DEMO_AUTH === "true";
}
