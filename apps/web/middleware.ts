import { NextRequest, NextResponse } from 'next/server';

// Global same-origin CSRF barrier for state-changing API/form requests.
// Session cookies are also SameSite=Lax/Strict where appropriate.
export function middleware(req: NextRequest) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return NextResponse.next();
  const origin = req.headers.get('origin');
  const fetchSite = req.headers.get('sec-fetch-site');
  if (fetchSite && !['same-origin', 'none'].includes(fetchSite)) {
    return new NextResponse('Cross-site request blocked', { status: 403 });
  }
  if (origin && new URL(origin).host !== req.nextUrl.host) {
    return new NextResponse('Origin mismatch', { status: 403 });
  }
  return NextResponse.next();
}

export const config = { matcher: ['/api/:path*'] };
