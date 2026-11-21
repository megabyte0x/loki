// lightwalletd over gRPC-web (communication/deploy/lightwalletd-grpcweb.sh), for the signer's
// chain scan. Only the two calls the scan needs; each message is hand-encoded protobuf.

const varint = (n) => { const out = []; for (; n >= 0x80; n = Math.floor(n / 0x80)) out.push((n % 0x80) | 0x80); out.push(n); return out; };
const blockId = (height) => [0x08, ...varint(height)]; // BlockID { height = 1 }
const field = (tag, bytes) => [tag, ...varint(bytes.length), ...bytes];
const MAX_BLOCKS = 500;
const MAX_HEIGHT = 0xfffffffe;
const MAX_FRAME = 4 * 1024 * 1024;
const MAX_BODY = 32 * 1024 * 1024;

async function call(base, method, message, count) {
  const body = new Uint8Array(5 + message.length);
  new DataView(body.buffer).setUint32(1, message.length);
  body.set(message, 5);
  const abort = new AbortController();
  const deadline = setTimeout(() => abort.abort(new Error(`lightwalletd ${method}: deadline exceeded`)), 30_000);
  try {
    const res = await fetch(`${base.replace(/\/+$/, "")}/cash.z.wallet.sdk.rpc.CompactTxStreamer/${method}`, {
      method: "POST", headers: { "content-type": "application/grpc-web+proto", "x-grpc-web": "1" }, body,
      signal: abort.signal,
    });
    if (!res.ok) throw new Error(`lightwalletd ${method}: HTTP ${res.status}`);
    const parser = frameReader(method, res.headers, count);
    const reader = res.body?.getReader();
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        parser.push(value);
      }
    }
    const messages = parser.finish();
    if (messages.length !== count) throw new Error(`lightwalletd ${method}: expected ${count} messages, received ${messages.length}`);
    return messages;
  } finally {
    clearTimeout(deadline);
    abort.abort();
  }
}

function frameReader(method, headers, maxMessages) {
  const fail = (reason) => { throw new Error(`lightwalletd ${method}: ${reason}`); };
  const out = [];
  const header = new Uint8Array(5), view = new DataView(header.buffer);
  let total = 0, filled = 0, trailer = false, data;
  let status = headers.get("grpc-status"), message = headers.get("grpc-message");
  return {
    push(buf) {
      total += buf.length;
      if (total > MAX_BODY) fail("response exceeds the byte limit");
      for (let i = 0; i < buf.length;) {
        if (!data) {
          if (trailer || status !== null) fail("data after final gRPC status");
          const n = Math.min(5 - filled, buf.length - i);
          header.set(buf.subarray(i, i + n), filled);
          i += n;
          filled += n;
          if (filled !== 5) continue;
          const length = view.getUint32(1);
          if (header[0] !== 0 && header[0] !== 0x80) fail("unsupported gRPC-web frame flags");
          if (length > (header[0] === 0x80 ? 8192 : MAX_FRAME)) fail("frame exceeds the byte limit");
          if (header[0] === 0 && out.length >= maxMessages) fail("too many messages");
          data = new Uint8Array(length);
          filled = 0;
        }
        const n = Math.min(data.length - filled, buf.length - i);
        data.set(buf.subarray(i, i + n), filled);
        i += n;
        filled += n;
        if (filled !== data.length) continue;
        if (header[0] === 0x80) {
          trailer = true;
          for (const line of new TextDecoder().decode(data).split("\r\n")) {
            const [k, ...v] = line.split(":");
            if (k.toLowerCase() === "grpc-status") {
              if (status !== null) fail("duplicate grpc-status");
              status = v.join(":").trim();
            }
            if (k.toLowerCase() === "grpc-message") message = v.join(":").trim();
          }
        } else out.push(data);
        data = undefined;
        filled = 0;
      }
    },
    finish() {
      if (filled || data) fail("truncated frame");
      if (status === null) fail("missing grpc-status");
      if (status !== "0") fail(`grpc-status ${status} ${message ?? ""}`.trim());
      return out;
    },
  };
}

export function frames(buf, method = "call", headers = new Headers()) {
  const parser = frameReader(method, headers, MAX_BLOCKS);
  parser.push(buf);
  return parser.finish();
}

// The chain tip height (GetLatestBlock -> BlockID, height = field 1).
export async function latestHeight(base) {
  const [msg] = await call(base, "GetLatestBlock", [], 1);
  if (msg[0] !== 0x08) throw new Error("lightwalletd GetLatestBlock: no height");
  let height = 0;
  for (let i = 1, mul = 1; i < msg.length && i <= 5; i++, mul *= 0x80) {
    height += (msg[i] & 0x7f) * mul;
    if (!(msg[i] & 0x80) && height <= MAX_HEIGHT) return height;
  }
  throw new Error("lightwalletd GetLatestBlock: bad height");
}

// Compact blocks start..end inclusive, each as its protobuf bytes.
export function blockRange(base, start, end) {
  const count = end - start + 1;
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end > MAX_HEIGHT || count < 1 || count > MAX_BLOCKS) {
    throw new Error("lightwalletd GetBlockRange: invalid block range");
  }
  return call(base, "GetBlockRange", [...field(0x0a, blockId(start)), ...field(0x12, blockId(end))], count);
}
