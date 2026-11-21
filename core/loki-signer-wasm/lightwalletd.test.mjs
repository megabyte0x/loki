// node --test core/loki-signer-wasm/lightwalletd.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { blockRange, frames, latestHeight } from "./lightwalletd.js";

const frame = (flag, bytes) => [flag, 0, 0, 0, bytes.length, ...bytes];
const trailer = (text) => frame(0x80, [...new TextEncoder().encode(text)]);

test("data frames come back in order and the trailer status is checked", () => {
  const body = Uint8Array.from([...frame(0, [1, 2]), ...frame(0, [3]), ...trailer("grpc-status:0\r\n")]);
  assert.deepEqual(frames(body).map((f) => [...f]), [[1, 2], [3]]);
  assert.throws(() => frames(Uint8Array.from(trailer("grpc-status:5\r\ngrpc-message:not found\r\n"))), /grpc-status 5 not found/);
  assert.throws(() => frames(Uint8Array.from([0, 0, 0, 0, 9, 1])), /truncated/);
});

test("requests are gRPC-web protobuf and heights decode", async () => {
  const seen = [];
  globalThis.fetch = async (url, init) => {
    seen.push([url, [...init.body], init.headers["content-type"]]);
    // BlockID { height = 4639094 } -> 08 f6 92 9b 02
    const body = url.endsWith("GetLatestBlock") ? frame(0, [0x08, 0xf6, 0x92, 0x9b, 0x02]) : [0x8c, 0x8d, 0x8e].flatMap((lo) => frame(0, [0x10, lo, 0x92, 0x9b, 0x02]));
    return new Response(Uint8Array.from([...body, ...trailer("grpc-status:0\r\n")]), { status: 200 });
  };
  assert.equal(await latestHeight("http://lwd/"), 4639094);
  assert.equal((await blockRange("http://lwd", 4638988, 4638990)).length, 3);
  assert.equal(seen[0][0], "http://lwd/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock");
  assert.deepEqual(seen[0][1], [0, 0, 0, 0, 0]);
  assert.equal(seen[1][2], "application/grpc-web+proto");
  // BlockRange { start = BlockID{4638988}, end = BlockID{4638990} }
  assert.deepEqual(seen[1][1], [0, 0, 0, 0, 14, 0x0a, 5, 0x08, 0x8c, 0x92, 0x9b, 0x02, 0x12, 5, 0x08, 0x8e, 0x92, 0x9b, 0x02]);
});
