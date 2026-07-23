import { fileURLToPath } from "node:url";

/** @type {import('next').NextConfig} */
const isDevelopment = process.env.NODE_ENV !== "production";
const railwayBackendUrl = process.env.RAILWAY_BACKEND_URL;
const localApiUrl = process.env.NEXT_PUBLIC_API_URL;
const hasRealRailwayUrl =
  typeof railwayBackendUrl === "string" &&
  railwayBackendUrl.length > 0 &&
  !railwayBackendUrl.includes("your-shadowledger-backend");
const backendUrl = isDevelopment ? localApiUrl : railwayBackendUrl || localApiUrl;

const nextConfig = {
  outputFileTracingRoot: fileURLToPath(new URL(".", import.meta.url)),
  experimental: {
    externalDir: true
  },
  async rewrites() {
    if (!backendUrl && !hasRealRailwayUrl) {
      return [];
    }

    return [
      {
        source: "/api/:path*",
        destination: `${(hasRealRailwayUrl && !isDevelopment ? railwayBackendUrl : backendUrl).replace(/\/$/, "")}/api/:path*`
      }
    ];
  }
};

export default nextConfig;
