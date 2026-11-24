import { admitAttempt, clientAddress, refusal } from "@/lib/admission-limits";
import { readRegistrationBody, issueRegistrationChallenge } from "@/lib/members";

export async function POST(req: Request) {
  try {
    // Every attempt counts here, before any registry access. The stricter new-identity limits
    // apply only if this enrollment would admit a new identity.
    const client = clientAddress(req);
    admitAttempt(client);
    const body = await readRegistrationBody(req);
    return Response.json(await issueRegistrationChallenge(body, new URL(req.url).origin, client));
  } catch (error) {
    return refusal(error);
  }
}
