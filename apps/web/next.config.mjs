// The dashboard runs in two modes:
//  - dev (:3000): proxies /api/* to the gateway via rewrites.
//  - agent bundle (BUILD_STATIC=1): static export served by the gateway itself
//    at localhost:4000, so /api/* and the WebSocket are same-origin.
const isStatic = process.env.BUILD_STATIC === '1';

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  transpilePackages: ['@netscanner/contracts'],
  ...(isStatic
    ? { output: 'export', trailingSlash: true, images: { unoptimized: true } }
    : {
        async rewrites() {
          const api = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';
          return [{ source: '/api/:path*', destination: `${api}/api/:path*` }];
        },
      }),
};

export default nextConfig;
