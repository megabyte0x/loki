import { retireMember } from "../src/lib/members.ts";

const [signing] = process.argv.slice(2);
if (!process.env.LOKI_REGISTRY || !signing) {
  throw new Error("usage: LOKI_REGISTRY=/path/to/registry.json node scripts/retire-member.ts <signing_pubkey>");
}
await retireMember(signing);
