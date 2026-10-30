import { fileURLToPath } from "node:url";

/** @type {import('next').NextConfig} */
const configuredBackendUrl =
  process.env.BACKEND_URL || process.env.RAILWAY_BACKEND_URL || process.env.NEXT_PUBLIC_API_URL;
// Same-origin production API traffic is routed to Python by root vercel.json.
const backendUrl = configuredBackendUrl && /^https?:\/\//.test(configuredBackendUrl)
  ? configuredBackendUrl.replace(/\/$/, "")
  : undefined;

const nextConfig = {
  outputFileTracingRoot: fileURLToPath(new URL(".", import.meta.url)),
  experimental: {
    externalDir: true
  },
  async rewrites() {
    if (!backendUrl) {
      return [];
    }

    return [
      {
        source: "/api/:path*",
        destination: `${backendUrl}/api/:path*`
      }
    ];
  }
};

export default nextConfig;
