import crypto from "node:crypto";
import { z } from "zod";

export const WebhookPayloadSchema = z.object({
  action: z.string(),
  repository: z.object({
    full_name: z.string()
  }),
  pull_request: z
    .object({
      number: z.number(),
      title: z.string()
    })
    .optional()
});

export type WebhookPayload = z.infer<typeof WebhookPayloadSchema>;

const signatureVerificationCache = new Map<string, boolean>();

function rememberSignatureResult(signatureHeader: string, result: boolean) {
  signatureVerificationCache.set(signatureHeader, result);

  if (signatureVerificationCache.size > 256) {
    const oldestKey = signatureVerificationCache.keys().next().value;
    if (oldestKey) {
      signatureVerificationCache.delete(oldestKey);
    }
  }
}

export function verifyGithubSignature(params: {
  rawBody: string;
  signatureHeader: string | undefined;
  secret: string;
}): boolean {
  const { rawBody, signatureHeader, secret } = params;

  if (!signatureHeader?.startsWith("sha256=")) {
    return false;
  }

  const cachedResult = signatureVerificationCache.get(signatureHeader);
  if (cachedResult !== undefined) {
    return cachedResult;
  }

  const expectedDigest =
    "sha256=" +
    crypto.createHmac("sha256", secret).update(rawBody).digest("hex");

  const received = Buffer.from(signatureHeader);
  const expected = Buffer.from(expectedDigest);

  if (received.length !== expected.length) {
    rememberSignatureResult(signatureHeader, false);
    return false;
  }

  const result = crypto.timingSafeEqual(received, expected);
  rememberSignatureResult(signatureHeader, result);

  return result;
}

export function parseWebhookPayload(input: unknown): WebhookPayload {
  return WebhookPayloadSchema.parse(input);
}
