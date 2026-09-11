import { describe, expect, test } from "bun:test";
import { docusign, docusignOAuth } from "../docusign/src/index";
import { dropboxSign, dropboxSignOAuth } from "../dropbox-sign/src/index";
import { createHmac } from "node:crypto";
import {
  validateRequest,
  documentDigest,
  reconcileSignatureRequest,
  type CreateSignatureRequest,
} from "@absolutejs/esign";
const input = (): CreateSignatureRequest => ({
  reference: "room-agreement-v1",
  title: "Pilot",
  documents: [
    {
      id: "contract",
      name: "pilot.pdf",
      bytes: new TextEncoder().encode("%PDF-1.4\nfixture"),
    },
  ],
  signers: [
    { id: "owner", name: "Owner", email: "owner@example.com" },
    { id: "partner", name: "Partner", email: "partner@example.com" },
  ],
  fields: [
    {
      documentId: "contract",
      signerId: "owner",
      page: 1,
      x: 40,
      y: 100,
      width: 140,
      height: 40,
    },
    {
      documentId: "contract",
      signerId: "partner",
      page: 1,
      x: 40,
      y: 180,
      width: 140,
      height: 40,
    },
  ],
  returnUrl: "http://localhost:3002/room/demo",
});
const envelope = {
  envelopeId: "env-1",
  status: "sent",
  customFields: {
    textCustomFields: [
      { name: "absolute_reference", value: "room-agreement-v1" },
    ],
  },
  recipients: {
    signers: [
      {
        recipientId: "1",
        clientUserId: "owner",
        name: "Owner",
        email: "owner@example.com",
        status: "sent",
      },
      {
        recipientId: "2",
        clientUserId: "partner",
        name: "Partner",
        email: "partner@example.com",
        status: "sent",
      },
    ],
  },
};
const signature = {
  signature_request_id: "req-1",
  is_complete: false,
  is_declined: false,
  has_error: false,
  metadata: { absolute_reference: "room-agreement-v1" },
  signatures: [
    {
      signature_id: "sig-1",
      signer_name: "Owner",
      signer_email_address: "owner@example.com",
      status_code: "awaiting_signature",
      signed_at: null,
    },
    {
      signature_id: "sig-2",
      signer_name: "Partner",
      signer_email_address: "partner@example.com",
      status_code: "awaiting_signature",
      signed_at: null,
    },
  ],
};
const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
const ds = (transport: typeof fetch) =>
  docusign({
    accountId: "account-1",
    accessToken: async () => "token",
    baseUri: "https://demo.docusign.net",
    hmacSecrets: ["secret"],
    fetch: transport,
  });
const db = (transport: typeof fetch) =>
  dropboxSign({
    accessToken: async () => "oauth-token",
    clientId: "client-1",
    webhookApiKey: "secret",
    testMode: true,
    fetch: transport,
  });
const transport = (
  handler: (url: string, init: RequestInit) => Promise<Response> | Response,
) =>
  ((url: unknown, init?: RequestInit) =>
    handler(String(url), init ?? {})) as typeof fetch;
describe("shared signature contract", () => {
  test("validates signer placement, duplicate recipients, PDF bytes, and return URLs", () => {
    expect(() => validateRequest(input())).not.toThrow();
    expect(() => validateRequest({ ...input(), fields: [] })).toThrow();
    expect(() =>
      validateRequest({
        ...input(),
        documents: [
          {
            id: "contract",
            name: "x.pdf",
            bytes: new TextEncoder().encode("<html>"),
          },
        ],
      }),
    ).toThrow();
    expect(() =>
      validateRequest({ ...input(), returnUrl: "javascript:alert(1)" }),
    ).toThrow();
  });
  test("document digest changes with bytes", () => {
    expect(documentDigest(new Uint8Array([1]))).not.toBe(
      documentDigest(new Uint8Array([2])),
    );
  });
  test("reconciliation verifies provider reference", async () => {
    await expect(
      reconcileSignatureRequest(
        ds(transport(() => json(envelope))),
        "env-1",
        "another-room",
      ),
    ).rejects.toThrow("does not match");
  });
});
describe("DocuSign", () => {
  test("maps PDFs, recipients and signature fields; creates once without retries", async () => {
    let calls = 0;
    const provider = ds(
      transport((_url, init) => {
        calls++;
        const body = JSON.parse(String(init.body));
        expect(body.status).toBe("sent");
        expect(body.recipients.signers[1].clientUserId).toBe("partner");
        expect(body.recipients.signers[1].tabs.signHereTabs[0].documentId).toBe(
          "1",
        );
        expect(body.documents[0].documentBase64).toBe(
          Buffer.from(input().documents[0].bytes).toString("base64"),
        );
        return json(envelope);
      }),
    );
    expect((await provider.createRequest(input())).id).toBe("env-1");
    expect(calls).toBe(1);
  });
  test("uses saved signer identity to open signing", async () => {
    const provider = ds(
      transport((url, init) => {
        if (url.endsWith("/views/recipient")) {
          const body = JSON.parse(String(init.body));
          expect(body.email).toBe("partner@example.com");
          expect(body.clientUserId).toBe("partner");
          return json({ url: "https://demo.docusign.net/sign" });
        }
        return json(envelope);
      }),
    );
    expect(
      (
        await provider.createSigningSession({
          requestId: "env-1",
          signerId: "2",
          returnUrl: input().returnUrl,
        })
      ).mode,
    ).toBe("redirect");
    await expect(
      provider.createSigningSession({
        requestId: "env-1",
        signerId: "wrong",
        returnUrl: input().returnUrl,
      }),
    ).rejects.toThrow();
  });
  test("verifies raw HMAC and account; rejects tampering", () => {
    const provider = ds(transport(() => json({})));
    const body = JSON.stringify({
      event: "envelope-completed",
      generatedDateTime: "2026-09-08T00:00:00Z",
      data: { envelopeId: "env-1", accountId: "account-1" },
    });
    const headers = new Headers({
      "X-DocuSign-Signature-1": createHmac("sha256", "secret")
        .update(body)
        .digest("base64"),
    });
    expect(provider.verifyWebhook(body, headers)?.requestId).toBe("env-1");
    expect(provider.verifyWebhook(body + " ", headers)).toBeNull();
    expect(provider.verifyWebhook(body, new Headers())).toBeNull();
  });
  test("does not download an unsigned document", async () => {
    await expect(
      ds(transport(() => json(envelope))).downloadCompleted("env-1"),
    ).rejects.toThrow("fully signed");
  });
  test("rejects arbitrary API origins before releasing credentials", () => {
    expect(() =>
      docusign({
        accountId: "a",
        accessToken: "private",
        baseUri: "https://evil.example",
        hmacSecrets: [],
      }),
    ).toThrow();
  });
  test("handles rate limits without replaying a create", async () => {
    let calls = 0;
    const provider = ds(
      transport(() => {
        calls++;
        return json({}, 429);
      }),
    );
    await expect(provider.createRequest(input())).rejects.toThrow("429");
    expect(calls).toBe(1);
  });
  test("OAuth includes state and supports refresh", async () => {
    const oauth = docusignOAuth({
      clientId: "client",
      clientSecret: "secret",
      environment: "sandbox",
      fetch: transport((_url, init) => {
        expect(String(init.body)).toContain("grant_type=refresh_token");
        return json({
          access_token: "next",
          refresh_token: "rotated",
          expires_in: 3600,
        });
      }),
    });
    expect(
      new URL(
        oauth.authorizationUrl({
          redirectUri: input().returnUrl,
          state: "csrf",
        }),
      ).searchParams.get("state"),
    ).toBe("csrf");
    expect((await oauth.refresh("old")).refreshToken).toBe("rotated");
  });
});
describe("Dropbox Sign", () => {
  test("maps zero-based signers and multipart PDF fields", async () => {
    const provider = db(
      transport((_url, init) => {
        const body = init.body as FormData;
        expect(body.get("test_mode")).toBe("1");
        expect(body.get("signers[1][email_address]")).toBe(
          "partner@example.com",
        );
        expect(
          JSON.parse(String(body.get("form_fields_per_document")))[0][1].signer,
        ).toBe(1);
        expect((init.headers as Record<string, string>).Authorization).toBe(
          "Bearer oauth-token",
        );
        return json({ signature_request: signature });
      }),
    );
    expect((await provider.createRequest(input())).signers[1].id).toBe("sig-2");
  });
  test("creates a short-lived embedded session for a saved signer", async () => {
    const provider = db(
      transport((url) =>
        url.includes("/embedded/")
          ? json({
              embedded: {
                sign_url: "https://app.hellosign.com/sign/123",
                expires_at: 2000000000,
              },
            })
          : json({ signature_request: signature }),
      ),
    );
    expect(
      (
        await provider.createSigningSession({
          requestId: "req-1",
          signerId: "sig-2",
          returnUrl: input().returnUrl,
        })
      ).clientId,
    ).toBe("client-1");
    await expect(
      provider.createSigningSession({
        requestId: "req-1",
        signerId: "foreign",
        returnUrl: input().returnUrl,
      }),
    ).rejects.toThrow();
  });
  test("completion needs is_complete; one signature is not enough", async () => {
    expect(
      (
        await db(
          transport(() =>
            json({
              signature_request: {
                ...signature,
                signatures: [
                  {
                    ...signature.signatures[0],
                    status_code: "signed",
                    signed_at: 1700000000,
                  },
                  signature.signatures[1],
                ],
              },
            }),
          ),
        ).getRequest("req-1")
      ).status,
    ).toBe("pending");
  });
  test("verifies event hash and returns exact provider acknowledgement", () => {
    const provider = db(transport(() => json({})));
    const event = {
      event_type: "signature_request_all_signed",
      event_time: "1700000000",
      event_hash: createHmac("sha256", "secret")
        .update("1700000000signature_request_all_signed")
        .digest("hex"),
    };
    expect(
      provider.verifyWebhook(
        JSON.stringify({ event, signature_request: signature }),
        new Headers(),
      )?.requestId,
    ).toBe("req-1");
    expect(
      provider.verifyWebhook(
        JSON.stringify({
          event: { ...event, event_hash: "bad" },
          signature_request: signature,
        }),
        new Headers(),
      ),
    ).toBeNull();
    expect(provider.webhookAcknowledgement).toBe("Hello API Event Received");
  });
  test("does not claim a separate audit endpoint", async () => {
    await expect(
      db(
        transport(() => json({ signature_request: signature })),
      ).downloadCompleted("req-1", "audit"),
    ).rejects.toThrow("includes its audit trail");
  });
  test("OAuth exchange sends state and app credentials", async () => {
    const oauth = dropboxSignOAuth({
      clientId: "client",
      clientSecret: "secret",
      fetch: transport((_url, init) => {
        const form = init.body as FormData;
        expect(form.get("state")).toBe("csrf");
        return json({ access_token: "token", expires_in: 3600 });
      }),
    });
    expect(
      (await oauth.exchangeCode({ code: "code", state: "csrf" })).accessToken,
    ).toBe("token");
  });
});
