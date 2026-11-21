// Loopback regtest services on the deploy host. Overridable via env for other setups.
const THS = process.env.THS_URL ?? "http://127.0.0.1:32805";
const RPC = process.env.RPC_URL ?? "http://127.0.0.1:18232";
const RPC_AUTH = "Basic " + Buffer.from("unused:unused").toString("base64");

/**
 * POST { address } → send regtest test funds to a vault address from the local THS faucet, then
 * mine a few blocks so the note confirms. Opt-in local development only; accepts public addresses and no member credentials.
 */
export async function POST(req: Request) {
  const origin = new URL(req.url);
  if (process.env.LOKI_DEV_FAUCET !== "1" || !["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname)
    || req.headers.get("origin") !== origin.origin) {
    return Response.json({ error: "local development faucet is disabled" }, { status: 403 });
  }
  let address: unknown;
  try {
    address = (await req.json()).address;
  } catch {
    address = undefined;
  }
  if (typeof address !== "string" || !address.startsWith("uregtest1")) {
    return Response.json({ error: "a regtest vault address is required" }, { status: 400 });
  }
  try {
    const faucet = await fetch(`${THS}/api/v1/faucet/address`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ address, amount_zatoshi: 500000000 }),
    });
    if (!faucet.ok) return Response.json({ error: "faucet declined" }, { status: 502 });
  } catch (e) {
    return Response.json({ error: `funding failed: ${(e as Error).message}` }, { status: 502 });
  }

  // The transfer was accepted; a mining failure must not turn it into a failed transfer.
  let mined = false;
  try {
    const blocks = 12;
    const mining = await fetch(RPC, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: RPC_AUTH },
      body: JSON.stringify({ jsonrpc: "1.0", id: 1, method: "generate", params: [blocks] }),
    });
    if (mining.ok) {
      const reply = await mining.json();
      mined = reply?.error == null && Array.isArray(reply?.result) && reply.result.length === blocks
        && reply.result.every((hash: unknown) => typeof hash === "string" && /^[0-9a-f]{64}$/i.test(hash));
    }
  } catch { /* Mining could not be verified. */ }
  return Response.json({ ok: true, mined }, { status: mined ? 200 : 202 });
}
