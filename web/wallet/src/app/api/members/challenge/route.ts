import { admitClient, refusal } from "@/lib/admission-limits";
import { readRegistrationBody, issueRegistrationChallenge } from "@/lib/members";

export async function POST(req: Request) {
  try {
    admitClient(req);
    const body = await readRegistrationBody(req);
    return Response.json(await issueRegistrationChallenge(body, new URL(req.url).origin));
  } catch (error) {
    return refusal(error);
  }
}
