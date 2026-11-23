// Loopback regtest services on the deploy host. Overridable via env for other setups.
const THS = process.env.THS_URL ?? "http://127.0.0.1:32805";
const RPC = process.env.RPC_URL ?? "http://127.0.0.1:18232";
const RPC_AUTH = "Basic " + Buffer.from("unused:unused").toString("base64");
const confirmed = (reply: { block_hash?: unknown; status?: unknown } | null) =>
  reply?.status === "confirmed" || (typeof reply?.block_hash === "string" && /^[0-9a-f]{64}$/i.test(reply.block_hash));

/**
 * POST { address, idempotency_key } → send regtest test funds to a vault address from the local THS faucet, then
 * mine a few blocks so the note confirms. Opt-in local development only; accepts public addresses and no member credentials.
 */
export async function POST(req: Request) {
  const origin = new URL(req.url);
  if (process.env.LOKI_DEV_FAUCET !== "1" || !["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname)
    || req.headers.get("origin") !== origin.origin) {
    return Response.json({ error: "local development faucet is disabled" }, { status: 403 });
  }
  let address: unknown, idempotency_key: unknown;
  try {
    ({ address, idempotency_key } = await req.json());
  } catch { /* Handled by validation below. */ }
  if (typeof address !== "string" || !address.startsWith("uregtest1")) {
    return Response.json({ error: "a regtest vault address is required" }, { status: 400 });
  }
  if (typeof idempotency_key !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(idempotency_key)) {
    return Response.json({ error: "a valid funding attempt key is required" }, { status: 400 });
  }
  let mined: boolean;
  try {
    const faucet = await fetch(`${THS}/api/v1/faucet/address`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ address, amount_zatoshi: 500000000, idempotency_key }),
    });
    if (!faucet.ok) return Response.json({ error: "faucet declined" }, { status: 502 });
    mined = confirmed(await faucet.json());
  } catch (e) {
    return Response.json({ error: `funding failed: ${(e as Error).message}` }, { status: 502 });
  }

  // Generate confirmations for an accepted transfer, but block hashes from `generate`
  // do not themselves show that the faucet's particular transfer was included.
  try {
    const mining = await fetch(RPC, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: RPC_AUTH },
      body: JSON.stringify({ jsonrpc: "1.0", id: 1, method: "generate", params: [12] }),
    });
    await mining.body?.cancel();
  } catch { /* A mining failure must not turn acceptance into a failed transfer. */ }
  if (!mined) {
    try {
      const transfer = await fetch(`${THS}/api/v1/faucet/address?idempotency_key=${idempotency_key}`, { cache: "no-store" });
      mined = transfer.ok && confirmed(await transfer.json());
    } catch { /* The transfer is still pending verification. */ }
  }
  return Response.json({ ok: true, mined }, { status: mined ? 200 : 202 });
}
