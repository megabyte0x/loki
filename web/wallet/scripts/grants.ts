import { addOnboardingGrant, listOnboardingGrants, pruneOnboardingGrants, registerOnboardingGrant } from "../src/lib/members.ts";

// Onboarding grants live in the coordinator registry, so changes apply without a restart.
// The bearer string is printed once and never stored; only its SHA-256 digest is.
const usage = "usage: LOKI_REGISTRY=/path/to/registry.json node scripts/grants.ts add [--slot N] [--origin https://wallet.example] | register <sha256 digest> [--slot N] | list | prune";
const [command, ...rest] = process.argv.slice(2);
if (!process.env.LOKI_REGISTRY || !command) throw new Error(usage);

const option = (name: string) => {
  const at = rest.indexOf(name);
  return at === -1 ? undefined : rest[at + 1];
};

if (command === "add") {
  const slot = option("--slot");
  const origin = option("--origin");
  const grant = await addOnboardingGrant(slot === undefined ? undefined : Number(slot));
  // Share privately with the one new member. Don't paste it into tickets, chat logs or shell history.
  console.log(origin ? `${new URL(origin).origin}/#onboarding=${grant}` : grant);
} else if (command === "register") {
  // For scripts that generate their own bearer and pass only its digest.
  const slot = option("--slot");
  await registerOnboardingGrant(rest[0] ?? "", slot === undefined ? undefined : Number(slot));
} else if (command === "list") {
  for (const row of await listOnboardingGrants()) {
    console.log(`${row.digest.slice(0, 12)}…  slot ${row.slot ?? "auto"}  ${row.state}`);
  }
} else if (command === "prune") {
  console.log(`removed ${await pruneOnboardingGrants()} used grant(s)`);
} else {
  throw new Error(usage);
}
