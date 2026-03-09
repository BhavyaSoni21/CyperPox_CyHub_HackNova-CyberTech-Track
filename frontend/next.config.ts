import type { NextConfig } from "next";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const nextConfig: NextConfig = {
  // allowedDevOrigins is development-only; remove for production
  ...(process.env.NODE_ENV === "development" && {
    allowedDevOrigins: ["localhost", "127.0.0.1", "10.48.78.135"],
  }),
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${API_BASE_URL}/:path*`,
      },
    ];
  },
};

export default nextConfig;
