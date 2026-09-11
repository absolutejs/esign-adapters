import {
  ESignError,
  hmacDigest,
  secureDigestMatch,
  webhookDigest,
  requestProvider,
  providerToken,
  validateRequest,
  validateReturnUrl,
  type AccessTokenSource,
  type ESignProvider,
  type ProviderHttpOptions,
  type SignatureRequest,
  type OAuthTokens,
} from "@absolutejs/esign";

type DocuSignOptions = ProviderHttpOptions & {
  accessToken: AccessTokenSource;
  accountId: string;
  /** Account-specific base_uri returned by OAuth /userinfo. */ baseUri: string;
  hmacSecrets: string[];
};
type Envelope = {
  envelopeId: string;
  status: string;
  completedDateTime?: string;
  customFields?: { textCustomFields?: { name: string; value: string }[] };
  recipients?: { signers?: Recipient[] };
};
type Recipient = {
  recipientId: string;
  clientUserId?: string;
  email: string;
  name: string;
  status: string;
  signedDateTime?: string;
};
const normalized = (data: Envelope): SignatureRequest => ({
  id: data.envelopeId,
  provider: "docusign",
  reference: data.customFields?.textCustomFields?.find(
    (field) => field.name === "absolute_reference",
  )?.value,
  status:
    data.status === "completed"
      ? "completed"
      : data.status === "declined"
        ? "declined"
        : data.status === "voided"
          ? "cancelled"
          : data.status === "created"
            ? "draft"
            : "pending",
  completedAt: data.completedDateTime,
  signers: (data.recipients?.signers ?? []).map((signer) => ({
    id: signer.recipientId,
    name: signer.name,
    email: signer.email,
    status:
      signer.status === "completed"
        ? "signed"
        : signer.status === "declined"
          ? "declined"
          : "pending",
    signedAt: signer.signedDateTime,
  })),
});
export const docusign = (options: DocuSignOptions): ESignProvider => {
  const origin = new URL(options.baseUri);
  if (
    origin.protocol !== "https:" ||
    !/(^|\.)docusign\.net$/.test(origin.hostname) ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/"
  )
    throw new ESignError(
      "docusign",
      "invalid_input",
      "Use the HTTPS account base_uri returned by DocuSign userinfo.",
    );
  if (!options.accountId.trim())
    throw new ESignError(
      "docusign",
      "invalid_input",
      "A DocuSign account ID is required.",
    );
  const base = `${origin.origin}/restapi/v2.1/accounts/${encodeURIComponent(options.accountId)}`;
  const call = async (path: string, init: RequestInit = {}) =>
    requestProvider(
      "docusign",
      `${base}${path}`,
      {
        ...init,
        headers: {
          Authorization: `Bearer ${await providerToken(options.accessToken)}`,
          "Content-Type": "application/json",
          ...init.headers,
        },
      },
      options,
    );
  const getEnvelope = async (id: string) =>
    (
      await call(
        `/envelopes/${encodeURIComponent(id)}?include=recipients,custom_fields`,
      )
    ).json() as Promise<Envelope>;
  return {
    id: "docusign",
    capabilities: {
      embeddedSigning: true,
      orderedSigning: true,
      cancellation: true,
      separateAuditDownload: true,
    },
    webhookAcknowledgement: "OK",
    async createRequest(input) {
      validateRequest(input);
      const response = await call("/envelopes", {
        method: "POST",
        body: JSON.stringify({
          emailSubject: input.title,
          status: "sent",
          customFields: {
            textCustomFields: [
              {
                name: "absolute_reference",
                value: input.reference,
                show: "false",
              },
            ],
          },
          documents: input.documents.map((doc, index) => ({
            documentId: String(index + 1),
            name: doc.name,
            fileExtension: "pdf",
            documentBase64: Buffer.from(doc.bytes).toString("base64"),
          })),
          recipients: {
            signers: input.signers.map((signer, index) => ({
              recipientId: String(index + 1),
              clientUserId: signer.id,
              name: signer.name,
              email: signer.email,
              routingOrder: String(signer.order ?? 1),
              tabs: {
                signHereTabs: input.fields
                  .filter((field) => field.signerId === signer.id)
                  .map((field) => ({
                    documentId: String(
                      input.documents.findIndex(
                        (doc) => doc.id === field.documentId,
                      ) + 1,
                    ),
                    pageNumber: String(field.page),
                    xPosition: String(field.x),
                    yPosition: String(field.y),
                    width: String(field.width),
                    height: String(field.height),
                  })),
              },
            })),
          },
          ...(input.webhookUrl
            ? {
                eventNotification: {
                  url: input.webhookUrl,
                  requireAcknowledgment: "true",
                  includeHMAC: "true",
                  envelopeEvents: [
                    "sent",
                    "delivered",
                    "completed",
                    "declined",
                    "voided",
                  ].map((status) => ({ envelopeEventStatusCode: status })),
                  eventData: {
                    version: "restv2.1",
                    format: "json",
                    includeData: ["recipients"],
                  },
                },
              }
            : {}),
        }),
      });
      const data = (await response.json()) as Envelope;
      if (!data.envelopeId)
        throw new ESignError(
          "docusign",
          "invalid_response",
          "DocuSign did not return an envelope ID.",
        );
      return {
        ...normalized(data),
        reference: input.reference,
        signers: input.signers.map((signer, index) => ({
          id: String(index + 1),
          name: signer.name,
          email: signer.email,
          status: "pending" as const,
        })),
      };
    },
    async getRequest(id) {
      return normalized(await getEnvelope(id));
    },
    async createSigningSession(input) {
      validateReturnUrl(input.returnUrl);
      const envelope = await getEnvelope(input.requestId);
      const signer = envelope.recipients?.signers?.find(
        (item) => item.recipientId === input.signerId,
      );
      if (!signer?.clientUserId)
        throw new ESignError(
          "docusign",
          "invalid_input",
          "This signer is not an embedded recipient of the saved request.",
        );
      const response = await call(
        `/envelopes/${encodeURIComponent(input.requestId)}/views/recipient`,
        {
          method: "POST",
          body: JSON.stringify({
            returnUrl: input.returnUrl,
            authenticationMethod: "none",
            recipientId: signer.recipientId,
            clientUserId: signer.clientUserId,
            userName: signer.name,
            email: signer.email,
          }),
        },
      );
      const data = (await response.json()) as { url: string };
      if (!data.url || new URL(data.url).protocol !== "https:")
        throw new ESignError(
          "docusign",
          "invalid_response",
          "DocuSign did not return a secure signing URL.",
        );
      return { url: data.url, mode: "redirect" };
    },
    async downloadCompleted(id, artifact = "document") {
      if ((await getEnvelope(id)).status !== "completed")
        throw new ESignError(
          "docusign",
          "not_completed",
          "The request is not fully signed.",
        );
      const response = await call(
        `/envelopes/${encodeURIComponent(id)}/documents/${artifact === "audit" ? "certificate" : "combined"}`,
      );
      return new Uint8Array(await response.arrayBuffer());
    },
    async cancelRequest(id, reason) {
      if (!reason.trim())
        throw new ESignError(
          "docusign",
          "invalid_input",
          "A cancellation reason is required.",
        );
      await call(`/envelopes/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: JSON.stringify({
          status: "voided",
          voidedReason: reason.slice(0, 1000),
        }),
      });
    },
    verifyWebhook(body, headers) {
      const signatures = [...headers.entries()]
        .filter(([key]) => /^x-docusign-signature-\d+$/i.test(key))
        .map(([, value]) => value);
      const valid = options.hmacSecrets
        .filter(Boolean)
        .some((secret) =>
          signatures.some((signature) =>
            secureDigestMatch(signature, hmacDigest(secret, body, "base64")),
          ),
        );
      if (!valid) return null;
      try {
        const data = JSON.parse(body) as {
          event: string;
          generatedDateTime: string;
          data: { envelopeId: string; accountId: string };
        };
        if (
          !data.data?.envelopeId ||
          data.data.accountId !== options.accountId ||
          !data.event ||
          !Number.isFinite(Date.parse(data.generatedDateTime))
        )
          return null;
        return {
          id: webhookDigest(body),
          requestId: data.data.envelopeId,
          type: data.event,
          occurredAt: data.generatedDateTime,
        };
      } catch {
        return null;
      }
    },
  };
};
export type DocuSignOAuthOptions = ProviderHttpOptions & {
  clientId: string;
  clientSecret: string;
  environment: "sandbox" | "production";
};
export const docusignOAuth = (options: DocuSignOAuthOptions) => {
  const base =
    options.environment === "sandbox"
      ? "https://account-d.docusign.com"
      : "https://account.docusign.com";
  const exchange = async (
    fields: Record<string, string>,
  ): Promise<OAuthTokens> => {
    const response = await requestProvider(
      "docusign",
      `${base}/oauth/token`,
      {
        method: "POST",
        headers: {
          Authorization: `Basic ${Buffer.from(`${options.clientId}:${options.clientSecret}`).toString("base64")}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams(fields),
      },
      options,
    );
    const data = (await response.json()) as {
      access_token: string;
      refresh_token?: string;
      expires_in: number;
    };
    if (!data.access_token || !Number.isFinite(data.expires_in))
      throw new ESignError(
        "docusign",
        "invalid_response",
        "Invalid OAuth token response.",
      );
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: new Date(Date.now() + data.expires_in * 1000).toISOString(),
    };
  };
  return {
    authorizationUrl(input: { redirectUri: string; state: string }) {
      validateReturnUrl(input.redirectUri);
      if (!input.state)
        throw new ESignError(
          "docusign",
          "invalid_input",
          "OAuth state is required.",
        );
      const url = new URL("/oauth/auth", base);
      url.search = new URLSearchParams({
        response_type: "code",
        scope: "signature",
        client_id: options.clientId,
        redirect_uri: input.redirectUri,
        state: input.state,
      }).toString();
      return url.toString();
    },
    exchangeCode(input: { code: string; redirectUri: string }) {
      return exchange({
        grant_type: "authorization_code",
        code: input.code,
        redirect_uri: input.redirectUri,
      });
    },
    refresh(refreshToken: string) {
      return exchange({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      });
    },
    async accounts(accessToken: string) {
      const response = await requestProvider(
        "docusign",
        `${base}/oauth/userinfo`,
        { headers: { Authorization: `Bearer ${accessToken}` } },
        options,
      );
      return response.json() as Promise<{
        sub: string;
        accounts: {
          account_id: string;
          account_name: string;
          is_default: boolean;
          base_uri: string;
        }[];
      }>;
    },
  };
};
