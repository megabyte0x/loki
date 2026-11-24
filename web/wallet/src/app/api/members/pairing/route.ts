import { clientAddress, refusal } from "@/lib/admission-limits";
import { readRegistrationBody, issuePairingChallenge } from "@/lib/members";

export async function POST(req: Request) {
  try {
    const origin = new URL(req.url).origin;
    if (req.headers.has("origin") && req.headers.get("origin") !== origin) throw new Error("wrong pairing origin");
    const body = await readRegistrationBody(req);
    return Response.json(await issuePairingChallenge(body, origin, clientAddress(req)), { headers: { "Cache-Control": "no-store" } });
  } catch (error) {
    return refusal(error);
  }
}
