import { connection } from "next/server";
import { readRegistrationBody, registerMember, slots } from "@/lib/members";

export async function GET(req: Request) {
  await connection();
  const signing = new URL(req.url).searchParams.get("signing_pubkey");
  if (signing !== null && !/^[0-9a-f]{64}$/.test(signing)) return Response.json({ error: "invalid signing key" }, { status: 400 });
  const roster = slots().filter((member) => signing === null || member.signing_pubkey === signing);
  if (signing !== null && roster.length > 1) throw new Error("duplicate registration identity");
  return Response.json({ slots: roster }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(req: Request) {
  try {
    const body = await readRegistrationBody(req);
    return Response.json({ member: await registerMember(body, new URL(req.url).origin) });
  } catch (error) {
    return Response.json({ error: (error as Error).message }, { status: 400 });
  }
}
