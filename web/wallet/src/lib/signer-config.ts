// The deployment's signer configuration for the native signer (LokiSigner), served by this
// coordinator at /api/signer-config. Its one source is the signer origin's own /config.json
// (core/loki-signer-wasm/serve.mjs), which the browser signer runs with; nothing is copied here.
// The witness configuration contains only routes and public pins.

export type WitnessConfig = { endpoint: string; key: number[]; run: number[]; mailbox: number[] };
export type SignerConfig = {
  network: "testnet" | "regtest";
  frostdUrl: string;
  lightwalletdUrl: string | null;
  /** The native `--nonce-witnesses` shape: 32-byte values as byte arrays. */
  nonceWitnesses: [WitnessConfig, WitnessConfig];
};

/** The configured signer origin. LOKI_SIGNER_ORIGIN is read on the server at request time, so a
 *  deploy can move the signer without rebuilding; NEXT_PUBLIC_SIGNER_ORIGIN, inlined at build, is
 *  the fallback. Only server configuration names it, never a request. */
export function configuredSignerOrigin(): string | undefined {
  return process.env.LOKI_SIGNER_ORIGIN || process.env.NEXT_PUBLIC_SIGNER_ORIGIN;
}

/** The signer origin the wallet embeds, or the local signer server under `next dev`. A production
 *  deploy without one has none. The page receives it from the server-rendered layout. */
export function signerOrigin(configured: string | undefined = configuredSignerOrigin(), mode: string | undefined = process.env.NODE_ENV): string {
  if (configured) return new URL(configured).origin;
  if (mode !== "production") return "http://localhost:3002";
  throw new Error("this coordinator has no signer origin (LOKI_SIGNER_ORIGIN or NEXT_PUBLIC_SIGNER_ORIGIN), so it serves no signer configuration");
}

/** Read and check the signer origin's configuration: no redirect, a timeout, never mainnet. */
export async function signerConfig(origin: string, timeoutMs = 10_000): Promise<SignerConfig> {
  let reply: Response;
  try {
    reply = await fetch(`${origin}/config.json`, { redirect: "manual", cache: "no-store", signal: AbortSignal.timeout(timeoutMs) });
  } catch {
    throw new Error(`the signer origin ${origin} is unreachable`);
  }
  if (reply.status !== 200) throw new Error(`the signer origin ${origin} answered ${reply.status} instead of its configuration`);
  const invalid = (what: string) => new Error(`the signer origin ${origin} serves an invalid ${what}`);
  const raw = await reply.json().catch(() => { throw invalid("configuration"); });
  if (!raw || typeof raw !== "object") throw invalid("configuration");
  const url = (value: unknown, what: string): string => {
    if (typeof value !== "string" || !URL.canParse(value) || !["https:", "http:"].includes(new URL(value).protocol)) throw invalid(what);
    return value;
  };
  const bytes = (value: unknown, what: string): number[] => {
    if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw invalid(`nonce witness ${what}`);
    return [...Buffer.from(value, "hex")];
  };
  if (raw.network !== "testnet" && raw.network !== "regtest") throw invalid("network");
  if (!Array.isArray(raw.nonceWitnesses) || raw.nonceWitnesses.length !== 2) throw invalid("nonce witness list");
  const witness = (w: Record<string, unknown>): WitnessConfig => ({
    endpoint: url(w?.endpoint, "nonce witness endpoint"),
    key: bytes(w.key, "key"), run: bytes(w.run, "run"), mailbox: bytes(w.mailbox, "mailbox"),
  });
  return {
    network: raw.network,
    frostdUrl: url(raw.frostdUrl, "frostd URL"),
    lightwalletdUrl: raw.lightwalletdUrl === "" || raw.lightwalletdUrl === undefined ? null : url(raw.lightwalletdUrl, "lightwalletd URL"),
    nonceWitnesses: [witness(raw.nonceWitnesses[0]), witness(raw.nonceWitnesses[1])],
  };
}

/** The /api/signer-config reply: the configuration, or a clear error; never cached. */
export async function signerConfigResponse(configured: string | undefined = configuredSignerOrigin(), mode: string | undefined = process.env.NODE_ENV): Promise<Response> {
  const headers = { "Cache-Control": "no-store" };
  try {
    return Response.json(await signerConfig(signerOrigin(configured, mode)), { headers });
  } catch (error) {
    return Response.json({ error: (error as Error).message }, { status: 502, headers });
  }
}
