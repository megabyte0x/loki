import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, timingSafeEqual } from "node:crypto";

const FIELD_PRIME = Buffer.from("7f" + "ff".repeat(30) + "ed", "hex");

export function newRelayChallenge(seed?: Buffer) {
  const privateKey = seed ? createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), seed]),
    format: "der", type: "pkcs8",
  }) : generateKeyPairSync("x25519").privateKey;
  const publicKey = createPublicKey(privateKey);
  return {
    publicKey: Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url").toString("hex"),
    privateKey: privateKey.export({ format: "der", type: "pkcs8" }).toString("hex"),
  };
}

export function verifyRelayProof(privateKey: string, proof: string, origin: string, signing: string, relay: string, challenge: string): boolean {
  // X25519 accepts aliases by masking/reducing u. The registry must bind a single encoding.
  if (Buffer.from(relay, "hex").reverse().compare(FIELD_PRIME) >= 0) return false;
  const publicKey = createPublicKey({ key: { kty: "OKP", crv: "X25519", x: Buffer.from(relay, "hex").toString("base64url") }, format: "jwk" });
  const key = createPrivateKey({ key: Buffer.from(privateKey, "hex"), format: "der", type: "pkcs8" });
  let shared: Buffer;
  try { shared = diffieHellman({ privateKey: key, publicKey }); }
  catch { return false; } // OpenSSL rejects low-order peer keys.
  try {
    const context = `loki-relay-registration-v1\n${origin}\n${signing}\n${relay}\n${challenge}`;
    const expected = Buffer.from(hkdfSync("sha256", shared, "", context, 32));
    return timingSafeEqual(expected, Buffer.from(proof, "hex"));
  } finally { shared.fill(0); }
}
