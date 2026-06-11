import express from "express";
import { parseWebhookPayload, verifyGithubSignature } from "./webhook.js";

export const app = express();

app.use(
  express.json({
    verify: (req, _res, buf) => {
      (req as express.Request & { rawBody?: string }).rawBody = buf.toString(
        "utf8"
      );
    }
  })
);

app.post("/webhook/github", (req, res) => {
  const rawBody = (req as express.Request & { rawBody?: string }).rawBody ?? "";
  const secret = process.env.GITHUB_WEBHOOK_SECRET ?? "dev-secret";

  const validSignature = verifyGithubSignature({
    rawBody,
    signatureHeader: req.header("x-hub-signature-256"),
    secret
  });

  if (!validSignature) {
    return res.status(401).json({ error: "invalid signature" });
  }

  const payload = parseWebhookPayload(req.body);

  return res.status(202).json({
    ok: true,
    action: payload.action,
    repo: payload.repository.full_name
  });
});

if (process.env.NODE_ENV !== "test") {
  app.listen(3000, () => {
    console.log("Smoke test app listening on http://localhost:3000");
  });
}