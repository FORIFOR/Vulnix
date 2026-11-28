import type { NextConfig } from "next";

// The pinned production runtime supplies WebSocket. The other packages below
// serve Next.js build and development paths only in this release profile.
const releaseTraceExclusions = [
  "@vercel/nft", "@next/font", "babel-packages", "browserslist", "devalue",
  "loader-utils2", "loader-utils3", "lru-cache", "schema-utils3", "shell-quote",
  "source-map08", "tar", "ws",
].map((name) => `./node_modules/next/dist/compiled/${name}/**/*`).concat(
  // image optimization is off (images.unoptimized): sharp and its native libvips build (which
  // bundles expat, libpng, libheif, libxml2 ...) are never loaded, so they are not shipped
  "./node_modules/sharp/**/*", "./node_modules/@img/**/*",
);

const releaseSha = process.env.VULNIX_RELEASE_SHA;
if (process.env.VULNIX_RELEASE_BUILD === "1" && !/^[a-f0-9]{40}$/.test(releaseSha ?? "")) {
  throw new Error("A full Git commit SHA is required for the Vulnix release build");
}

const nextConfig: NextConfig = {
  compress: false, // keep SSE unbuffered
  ...(process.env.VULNIX_RELEASE_BUILD === "1" && releaseSha ? {
    output: "standalone",
    // The application serves its own static images and does not use next/image.
    images: { unoptimized: true },
    outputFileTracingExcludes: { "**": releaseTraceExclusions },
    generateBuildId: async () => releaseSha,
  } : {}),
};

export default nextConfig;
