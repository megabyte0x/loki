import { connection } from "next/server";
import { admitAttempt, clientAddress, refusal } from "@/lib/admission-limits";
import { memberPage, readRegistrationBody, registerMember, slots } from "@/lib/members";

const noStore = { "Cache-Control": "no-store" };
const bad = (error: string) => Response.json({ error }, { status: 400 });
const number = (raw: string) => /^(0|[1-9][0-9]{0,9})$/.test(raw) && Number(raw) <= 0xffffffff ? Number(raw) : null;

// The directory has no member cap, so it is never served whole: `signing_pubkey` or `slot`
// look up one member, and the plain listing is paged in slot order (`after` = the `next`
// cursor of the previous page).
export async function GET(req: Request) {
  await connection();
  const query = new URL(req.url).searchParams;
  const keys = [...query.keys()];
  if (keys.length > 1 || keys.some((key) => !["signing_pubkey", "slot", "after"].includes(key))) return bad("use one of signing_pubkey, slot or after");
  const signing = query.get("signing_pubkey");
  if (signing !== null) {
    if (!/^[0-9a-f]{64}$/.test(signing)) return bad("invalid signing key");
    const roster = slots().filter((member) => member.signing_pubkey === signing);
    if (roster.length > 1) throw new Error("duplicate registration identity");
    return Response.json({ slots: roster }, { headers: noStore });
  }
  const rawSlot = query.get("slot");
  if (rawSlot !== null) {
    const slot = number(rawSlot);
    if (slot === null || slot < 1) return bad("invalid slot");
    return Response.json({ slots: slots().filter((member) => member.slot === slot) }, { headers: noStore });
  }
  const after = number(query.get("after") ?? "0");
  if (after === null) return bad("invalid cursor");
  return Response.json(memberPage(after), { headers: noStore });
}

export async function POST(req: Request) {
  try {
    admitAttempt(clientAddress(req));
    const body = await readRegistrationBody(req);
    return Response.json({ member: await registerMember(body, new URL(req.url).origin) });
  } catch (error) {
    return refusal(error);
  }
}
