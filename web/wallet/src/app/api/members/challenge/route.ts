import { clientAddress, refusal } from "@/lib/admission-limits";
import { readRegistrationBody, issueRegistrationChallenge } from "@/lib/members";

export async function POST(req: Request) {
  try {
    const body = await readRegistrationBody(req);
    // Per-address limits apply only if this enrollment would admit a new identity.
    return Response.json(await issueRegistrationChallenge(body, new URL(req.url).origin, clientAddress(req)));
  } catch (error) {
    return refusal(error);
  }
}
