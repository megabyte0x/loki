import { createServer } from "node:http";
import { connect } from "node:http2";
import { isIP } from "node:net";

const origin = process.env.ORIGIN;
if (!origin || new URL(origin).origin !== origin || !/^https?:\/\//.test(origin)) {
  throw new Error("set ORIGIN to the exact signer origin, e.g. http://localhost:3002");
}
const upstream = new URL(`https://${process.env.UPSTREAM || "testnet.zec.rocks:443"}`);
const listen = new URL(`http://${process.env.LISTEN || "127.0.0.1:9068"}`);
for (const address of [upstream, listen]) {
  if (address.href !== `${address.origin}/`) throw new Error("UPSTREAM and LISTEN must be host:port addresses");
}

const service = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/";
const latest = `${service}GetLatestBlock`, range = `${service}GetBlockRange`;
const mime = "application/grpc-web+proto";
const deadlineMs = 25_000;
const maxRequest = 23; // envelope + two height-only BlockIDs (uint32 height varints)
const maxResponse = 32 * 1024 * 1024;
const trustForwarded = process.env.TRUST_FORWARDED === "1";
const active = new Map();
let total = 0;

// Accept only the signer wire format, not hash selectors, extra protobuf fields, multiple
// messages, or compression. Pass the original bytes upstream only after proving the range.
function validRequest(path, bytes) {
  if (bytes.length < 5 || bytes[0] !== 0 || bytes.readUInt32BE(1) !== bytes.length - 5) return false;
  if (path === latest) return bytes.length === 5;
  let pos = 5;
  function height(tag) {
    if (bytes[pos++] !== tag) return NaN;
    const length = bytes[pos++], end = pos + length;
    if (length < 2 || length > 6 || end > bytes.length || bytes[pos++] !== 0x08) return NaN;
    let value = 0;
    for (let mul = 1; pos < end; mul *= 128) {
      const byte = bytes[pos++];
      value += (byte & 127) * mul;
      if ((byte & 128) === 0) return pos === end ? value : NaN;
    }
    return NaN;
  }
  const start = height(0x0a), end = height(0x12);
  return pos === bytes.length && start >= 1 && end <= 0xfffffffe && end >= start && end - start < 500;
}

const server = createServer({ headersTimeout: 5_000, requestTimeout: 30_000, connectionsCheckingInterval: 1_000 }, async (req, res) => {
  const reply = (code) => { res.writeHead(code, { connection: "close" }); res.end(); };
  const fail = (code) => {
    if (res.destroyed || res.writableEnded) return;
    if (res.headersSent) res.destroy();
    else reply(code);
  };
  res.setHeader("vary", "Origin");
  if (req.headers.origin === origin) res.setHeader("access-control-allow-origin", origin);
  if (req.url !== latest && req.url !== range) return reply(404);
  if (req.headers.origin && req.headers.origin !== origin) return reply(403);
  if (req.method === "OPTIONS") {
    if (req.headers.origin !== origin || req.headers["access-control-request-method"] !== "POST") return reply(403);
    res.setHeader("access-control-allow-methods", "POST, OPTIONS");
    res.setHeader("access-control-allow-headers", "content-type, x-grpc-web, x-user-agent, grpc-timeout");
    res.setHeader("access-control-max-age", "600");
    return reply(204);
  }
  if (req.method !== "POST") return reply(405);
  if (req.headers["content-type"] !== mime) return reply(415);
  if (Number(req.headers["content-length"]) > maxRequest) return reply(413);

  let session;
  const timer = setTimeout(() => fail(504), deadlineMs);
  res.once("close", () => {
    clearTimeout(timer);
    session?.destroy();
  });

  try {
    let length = 0;
    const chunks = [];
    for await (const chunk of req.iterator({ destroyOnReturn: false })) {
      length += chunk.length;
      if (length > maxRequest) return fail(413);
      chunks.push(chunk);
    }
    if (res.destroyed || res.writableEnded) return;
    const bytes = Buffer.concat(chunks, length);
    if (!validRequest(req.url, bytes)) return fail(400);

    // An opted-in loopback proxy must set or append the IP it actually accepted.
    const socketPeer = req.socket.remoteAddress;
    const forwarded = trustForwarded && ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(socketPeer)
      ? req.headers["x-forwarded-for"]?.split(",").at(-1)?.trim()
      : undefined;
    const family = forwarded && !forwarded.includes("%") ? isIP(forwarded) : 0;
    const peer = family === 6 ? new URL(`http://[${forwarded}]`).hostname : family === 4 ? forwarded : socketPeer;
    const inFlight = active.get(peer) ?? 0;
    if (inFlight >= 4 || total >= 32) return reply(429);
    active.set(peer, inFlight + 1);
    total++;
    res.once("close", () => {
      const left = active.get(peer) - 1;
      if (left) active.set(peer, left);
      else active.delete(peer);
      total--;
    });
    session = connect(upstream, { rejectUnauthorized: true, maxHeaderListPairs: 32 });
    session.on("error", () => fail(502));
    const stream = session.request({
      ":method": "POST", ":path": req.url,
      "content-type": "application/grpc", te: "trailers", "grpc-timeout": "25S",
    });
    let trailers, received = 0;
    stream.once("response", (headers) => {
      if (res.destroyed || res.writableEnded) return;
      if (headers[":status"] !== 200 || !/^application\/grpc(?:\+proto)?(?:;|$)/.test(headers["content-type"] ?? "")) return fail(502);
      if (headers["grpc-status"] !== undefined) trailers = headers; // trailers-only gRPC response
      res.writeHead(200, { "content-type": mime });
    });
    stream.once("trailers", (headers) => { trailers = headers; });
    stream.on("error", () => fail(502));
    stream.on("data", (chunk) => {
      if (res.destroyed || res.writableEnded) return;
      received += chunk.length;
      if (received > maxResponse) return fail(502);
      if (!res.write(chunk)) stream.pause();
    });
    res.on("drain", () => stream.resume());
    stream.once("end", () => {
      if (res.destroyed || res.writableEnded) return;
      const status = trailers?.["grpc-status"];
      if (!/^\d{1,2}$/.test(status ?? "")) return fail(502);
      const message = trailers["grpc-message"];
      const text = `grpc-status:${status}\r\n${typeof message === "string" && !/[\r\n]/.test(message) && message.length < 4096 ? `grpc-message:${message}\r\n` : ""}`;
      const body = Buffer.from(text), frame = Buffer.alloc(5 + body.length);
      frame[0] = 0x80;
      frame.writeUInt32BE(body.length, 1);
      body.copy(frame, 5);
      res.end(frame);
    });
    stream.end(bytes);
  } catch {
    fail(502);
  }
});
server.maxConnections = 128;
server.listen(Number(listen.port || 80), listen.hostname.replace(/^\[|\]$/g, ""), () => {
  console.log(`lightwalletd gRPC-web front: ${listen.origin} -> ${upstream.origin} (CORS origin: ${origin})`);
});
