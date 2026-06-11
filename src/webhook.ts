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

export function verifyGithubSignature(params: {
  rawBody: string;
  signatureHeader: string | undefined;
  secret: string;
}): boolean {
  const { rawBody, signatureHeader, secret } = params;

  if (!signatureHeader?.startsWith("sha256=")) {
    return false;
  }

  const expectedDigest =
    "sha256=" +
    crypto.createHmac("sha256", secret).update(rawBody).digest("hex");

  const received = Buffer.from(signatureHeader);
  const expected = Buffer.from(expectedDigest);

  if (received.length !== expected.length) {
    return false;
  }

  return crypto.timingSafeEqual(received, expected);
}

export function parseWebhookPayload(input: unknown): WebhookPayload {
  return WebhookPayloadSchema.parse(input);
}