import { NextResponse, type NextRequest } from "next/server";

/**
 * Force the HTML shell and all app/API responses to `no-store` so a deploy is reflected on the
 * next normal reload — never a statically-cached shell pinning returning visitors to an old
 * build's chunks. Next's `headers()` config did not override the route-level cache headers here,
 * but middleware runs on every request and sets the final response headers.
 *
 * `/_next/static` is intentionally excluded: those chunks are content-addressed and safe to cache
 * long-term; the fresh shell always references the current build's chunk URLs.
 */
export function middleware(req: NextRequest) {
  if (req.nextUrl.pathname === "/" && req.nextUrl.searchParams.has("invite")) {
    return new Response("This kind of invite link is no longer accepted. Ask the vault creator for a new invite.", {
      status: 410,
      headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "Content-Type": "text/plain; charset=utf-8" },
    });
  }
  const res = NextResponse.next();
  res.headers.set("Cache-Control", "no-store, must-revalidate");
  return res;
}

export const config = {
  matcher: "/((?!_next/static|_next/image|favicon.ico).*)",
};
