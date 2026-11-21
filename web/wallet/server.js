// Custom production server: run instead of `next start`.
//
// Next serves /_next/static chunks as `immutable`, but Turbopack names the app/dynamic chunks
// stably — so a code change reuses a filename with new content, and returning visitors stay on
// stale JS after every deploy. Next's own levers (next.config headers(), route config, middleware)
// could not override the static handler's cache headers. This wrapper rewrites Cache-Control at
// the HTTP layer, below Next, which is the one place it can't be overridden:
//   - /_next/static : must-revalidate (ETag -> 304 if unchanged, fresh JS if a reused name changed)
//   - everything else: no-store (the HTML shell always reflects the latest build)
const { createServer } = require("http");
const next = require("next");

const port = parseInt(process.env.PORT || "3001", 10);
const bind = "127.0.0.1";
const origin = process.env.PUBLIC_ORIGIN ?? new URL(`http://localhost:${port}`).origin;
const publicUrl = new URL(origin);
const loopback = ["localhost", bind].includes(publicUrl.hostname);
const https = publicUrl.protocol === "https:";
if (publicUrl.origin !== origin || !(https || (loopback && publicUrl.protocol === "http:"))) {
  throw new Error("PUBLIC_ORIGIN must be a canonical HTTPS or loopback HTTP origin");
}
const publicPort = Number(publicUrl.port || (https ? 443 : 80));
const app = next({ dev: false, hostname: publicUrl.hostname, port: publicPort });
const handle = app.getRequestHandler();

const cacheFor = (url) =>
  url && url.startsWith("/_next/static")
    ? "public, max-age=0, must-revalidate"
    : "no-store, must-revalidate";

app.prepare().then(() => {
  createServer((req, res) => {
    // Registration signatures bind the public origin. Never infer it from client headers.
    req.headers["x-forwarded-proto"] = https ? "https" : "http";
    req.headers["x-forwarded-host"] = publicUrl.host;
    req.headers["x-forwarded-port"] = String(publicPort);
    const cc = cacheFor(req.url);
    const setHeader = res.setHeader.bind(res);
    // Coerce any Cache-Control Next tries to set to our value.
    res.setHeader = (name, value) =>
      String(name).toLowerCase() === "cache-control" ? setHeader(name, cc) : setHeader(name, value);
    const writeHead = res.writeHead.bind(res);
    res.writeHead = (...args) => {
      const headers = args.find((a) => a && typeof a === "object" && !Array.isArray(a));
      if (headers) {
        for (const k of Object.keys(headers)) {
          if (k.toLowerCase() === "cache-control") delete headers[k];
        }
      }
      setHeader("Cache-Control", cc);
      return writeHead(...args);
    };
    handle(req, res);
  }).listen(port, bind, () => console.log(`loki web on ${bind}:${port} for ${origin}`));
});
