import { NextRequest, NextResponse } from 'next/server';

// Global same-origin CSRF barrier for state-changing API/form requests.
// Session cookies are also SameSite=Lax/Strict where appropriate.

/**
 * The host this request was actually addressed to.
 *
 * `req.nextUrl` is built from the address the server itself is listening on, so
 * behind a reverse proxy it reports the bind address (`0.0.0.0:3000`) rather
 * than the public hostname. Comparing `Origin` against that rejects every
 * state-changing request with 403 "Origin mismatch" even though the proxy
 * forwards the correct Host. Compare against the forwarded host instead, and
 * fall back through the plain Host header to nextUrl for direct access.
 */
function requestHost(req: NextRequest): string {
  const forwarded = req.headers.get('x-forwarded-host')?.split(',')[0]?.trim();
  return forwarded || req.headers.get('host') || req.nextUrl.host;
}

export function middleware(req: NextRequest) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return NextResponse.next();
  const origin = req.headers.get('origin');
  const fetchSite = req.headers.get('sec-fetch-site');
  if (fetchSite && !['same-origin', 'none'].includes(fetchSite)) {
    return new NextResponse('Cross-site request blocked', { status: 403 });
  }
  if (origin && new URL(origin).host !== requestHost(req)) {
    return new NextResponse('Origin mismatch', { status: 403 });
  }
  return NextResponse.next();
}

export const config = { matcher: ['/api/:path*'] };
