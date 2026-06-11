import crypto from "node:crypto";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { app } from "../src/app.js";

function signPayload(rawBody: string, secret = "dev-secret") {
  return (
    "sha256=" +
    crypto.createHmac("sha256", secret).update(rawBody).digest("hex")
  );
}

describe("GitHub webhook", () => {
  it("accepts a valid signature", async () => {
    const payload = {
      action: "opened",
      repository: {
        full_name: "demo/repocouncil-smoke-test"
      },
      pull_request: {
        number: 1,
        title: "Smoke test PR"
      }
    };

    const rawBody = JSON.stringify(payload);

    const res = await request(app)
      .post("/webhook/github")
      .set("content-type", "application/json")
      .set("x-hub-signature-256", signPayload(rawBody))
      .send(rawBody);

    expect(res.status).toBe(202);
    expect(res.body.ok).toBe(true);
  });

  it("rejects an invalid signature", async () => {
    const payload = {
      action: "opened",
      repository: {
        full_name: "demo/repocouncil-smoke-test"
      }
    };

    const res = await request(app)
      .post("/webhook/github")
      .set("content-type", "application/json")
      .set("x-hub-signature-256", "sha256=invalid")
      .send(payload);

    expect(res.status).toBe(401);
  });

  it("rejects invalid payload shape", async () => {
    const payload = {
      action: "opened",
      repository: {}
    };

    const rawBody = JSON.stringify(payload);

    const res = await request(app)
      .post("/webhook/github")
      .set("content-type", "application/json")
      .set("x-hub-signature-256", signPayload(rawBody))
      .send(rawBody);

    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});