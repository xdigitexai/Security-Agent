import type { NextConfig } from 'next';

// Hosts allowed to reach the dev server's /_next/* resources when `next dev`
// runs behind a reverse proxy on a different hostname. Next blocks these by
// default and logs, for every visitor:
//
//   Blocked cross-origin request to Next.js dev resource /_next/hmr from "..."
//
// Comma-separated, e.g. ALLOWED_DEV_ORIGINS=app.example.com,other.example.com
// Unset by default, so a direct localhost run is unaffected.
const allowedDevOrigins = (process.env.ALLOWED_DEV_ORIGINS ?? '')
  .split(',')
  .map((host) => host.trim())
  .filter(Boolean);

const config: NextConfig = {
  transpilePackages: ['@xdigitex/database', '@xdigitex/shared', '@xdigitex/types', '@xdigitex/scanner-core'],
  poweredByHeader: false,
  experimental: { serverActions: { bodySizeLimit: '1mb' } },
  ...(allowedDevOrigins.length ? { allowedDevOrigins } : {}),
};

export default config;
