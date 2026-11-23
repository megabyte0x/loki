import { readFileSync, writeFileSync } from 'node:fs';

// Admits a grant the way scripts/grants.ts does, by writing its digest into the registry.
export function admitGrant(digest, slot = null) {
  const file = process.env.LOKI_REGISTRY;
  let registry;
  try { registry = JSON.parse(readFileSync(file, 'utf8')); } catch { registry = { access: [] }; }
  if (registry.version !== 1) {
    // Like the coordinator's loader: a legacy roster keeps its device bindings from the side file.
    let legacy = [];
    try { legacy = JSON.parse(readFileSync(`${file}.devices`, 'utf8')); } catch {}
    const devices = legacy.map((d) => ({ ...d, generation: 1, retired: [] }));
    registry = { version: 1, access: registry.access ?? [], devices, challenges: [], grants: {}, retired: [] };
  }
  registry.onboarding = { ...registry.onboarding, [digest]: slot };
  writeFileSync(file, JSON.stringify(registry));
}
