import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";

const binary = fileURLToPath(new URL("../target/debug/loki_member_app", import.meta.url));
const relay = process.env.FROSTD_URL ?? "http://127.0.0.1:2744";

test("confirmed members tolerate delayed confirmations, creator outages and pre-DKG process restarts", { timeout: 150_000 }, async () => {
  const challenge = await fetch(`${relay}/challenge`, { method: "POST" });
  assert.equal(challenge.status, 200, "start frostd before running this live regression");
  const root = await mkdtemp(`${tmpdir()}/loki-confirmation-test-`);
  const children = new Set();
  const passphrase = "disposable confirmation regression profile";
  async function launch(slot, existing = false, port = 0) {
    const child = spawn(binary, ["--data", `${root}/${slot}`, "--port", String(port), "--network", "testnet", "--allow-loopback-peers", "--lightwalletd-url", "https://testnet.zec.rocks:443", "--frostd-url", relay]);
    children.add(child);
    let output = "";
    let errors = "";
    child.stdout.on("data", (chunk) => { output += chunk; });
    child.stderr.on("data", (chunk) => { errors += chunk; });
    child.on("error", (error) => { errors += error.message; });
    let link;
    for (let attempt = 0; attempt < 100; attempt++) {
      link = output.match(/http:\/\/127\.0\.0\.1:\d+\/#[A-Za-z0-9_-]+/)?.[0];
      if (link) break;
      assert.equal(child.exitCode, null, `member exited: ${errors}`);
      await delay(100);
    }
    assert.ok(link, `member did not start: ${errors}`);
    const url = new URL(link);
    const api = async (path, body) => {
      const response = await fetch(`${url.origin}/api/${path}`, {
        method: body === undefined ? "GET" : "POST",
        headers: { "X-Loki-Token": url.hash.slice(1), "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(15_000),
      });
      const result = await response.json();
      assert.equal(response.status, 200, `${path}: ${JSON.stringify(result)}`);
      return result;
    };
    await api(existing ? "unlock" : "profile-create", { name: `Member ${slot}`, passphrase });
    return { child, api, port: Number(url.port) };
  }
  async function stop(member) {
    const exited = new Promise((resolve) => member.child.once("exit", resolve));
    member.child.kill("SIGTERM");
    await exited;
    children.delete(member.child);
  }
  try {
    const members = await Promise.all([launch(1), launch(2), launch(3)]);
    const created = await members[0].api("create", { name: "Delayed confirmations", members: 3, threshold: 2 });
    const vault = created.vault;
    for (const slot of [2, 3]) {
      const invite = created.invites.find((item) => item.slot === slot).code;
      await members[slot - 1].api("join", { invite });
    }
    const status = (member) => member.api(`status?vault=${vault}`);
    const { fingerprint, roster_code } = await status(members[0]);
    await status(members[1]);
    await status(members[2]);
    await members[1].api("agree", { vault, fingerprint, roster_code });
    await delay(22_000);
    const waiting = await status(members[1]);
    assert.equal(waiting.phase, "compare_roster", `confirmation waiting must not time out: ${JSON.stringify(waiting)}`);
    assert.equal(waiting.confirmed, true);
    assert.equal((await status(members[0])).confirmations, 1);
    assert.equal((await status(members[2])).confirmed, false);
    await members[1].api("agree", { vault, fingerprint, roster_code });
    await members[0].api("lock", {});
    await delay(1500);
    assert.equal((await status(members[1])).phase, "compare_roster", "a locked creator must not invalidate a confirmed roster");
    await members[0].api("unlock", { passphrase });
    const creatorPort = members[0].port;
    await stop(members[0]);
    await delay(1500);
    assert.equal((await status(members[1])).phase, "compare_roster", "a creator restart must not invalidate a confirmed roster");
    members[0] = await launch(1, true, creatorPort);
    await stop(members[1]);
    members[1] = await launch(2, true);
    const restarted = await status(members[1]);
    assert.equal(restarted.phase, "compare_roster");
    assert.equal(restarted.confirmed, true, "restart must preserve this member's consent");
    await members[0].api("agree", { vault, fingerprint, roster_code });
    assert.equal((await status(members[1])).phase, "compare_roster");
    await members[2].api("agree", { vault, fingerprint, roster_code });
    let states;
    for (let attempt = 0; attempt < 160; attempt++) {
      states = await Promise.all(members.map(status));
      assert.ok(states.every((state) => state.phase !== "setup_interrupted"), JSON.stringify(states.map(({phase,error}) => ({phase,error}))));
      if (states.every((state) => state.phase === "active")) break;
      await delay(250);
    }
    assert.deepEqual(states.map((state) => state.phase), ["active", "active", "active"]);
    const addresses = await Promise.all(members.map((member) => member.api(`address?vault=${vault}`)));
    assert.equal(new Set(addresses.map((value) => value.address)).size, 1);
    assert.ok(addresses.every((value) => value.address.startsWith("utest1")));
  } finally {
    await Promise.all([...children].map(async (child) => {
      const exited = new Promise((resolve) => child.once("exit", resolve));
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGTERM");
        await exited;
      }
    }));
    await rm(root, { recursive: true, force: true });
  }
});
