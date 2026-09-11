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

type DropboxSignOptions = ProviderHttpOptions & {
  accessToken?: AccessTokenSource;
  apiKey?: string;
  clientId: string;
  /** API key used by Dropbox Sign to sign callbacks, even for OAuth-backed requests. */ webhookApiKey: string;
  testMode: boolean;
};
type RequestData = {
  signature_request_id: string;
  metadata?: Record<string, string>;
  is_complete: boolean;
  is_declined: boolean;
  has_error: boolean;
  signatures: {
    signature_id: string;
    signer_name: string;
    signer_email_address: string;
    status_code: string;
    signed_at: number | null;
  }[];
};
const normalized = (data: RequestData): SignatureRequest => ({
  id: data.signature_request_id,
  provider: "dropbox-sign",
  reference: data.metadata?.absolute_reference,
  status: data.is_declined
    ? "declined"
    : data.is_complete
      ? "completed"
      : "pending",
  completedAt:
    data.is_complete && data.signatures.every((s) => s.signed_at)
      ? new Date(
          Math.max(...data.signatures.map((s) => s.signed_at ?? 0)) * 1000,
        ).toISOString()
      : undefined,
  signers: data.signatures.map((signer) => ({
    id: signer.signature_id,
    name: signer.signer_name,
    email: signer.signer_email_address,
    status:
      signer.status_code === "signed"
        ? "signed"
        : signer.status_code === "declined"
          ? "declined"
          : "pending",
    signedAt: signer.signed_at
      ? new Date(signer.signed_at * 1000).toISOString()
      : undefined,
  })),
});
export const dropboxSign = (options: DropboxSignOptions): ESignProvider => {
  if (!options.clientId || (!options.accessToken && !options.apiKey))
    throw new ESignError(
      "dropbox-sign",
      "invalid_input",
      "A client ID and OAuth token or API key are required.",
    );
  const call = async (path: string, init: RequestInit = {}) =>
    requestProvider(
      "dropbox-sign",
      `https://api.hellosign.com/v3${path}`,
      {
        ...init,
        headers: {
          Authorization: options.accessToken
            ? `Bearer ${await providerToken(options.accessToken)}`
            : `Basic ${Buffer.from(`${options.apiKey}:`).toString("base64")}`,
          ...init.headers,
        },
      },
      options,
    );
  const get = async (id: string) => {
    const data = (await (
      await call(`/signature_request/${encodeURIComponent(id)}`)
    ).json()) as { signature_request: RequestData };
    if (!data.signature_request?.signature_request_id)
      throw new ESignError(
        "dropbox-sign",
        "invalid_response",
        "Dropbox Sign did not return a signature request.",
      );
    return data.signature_request;
  };
  return {
    id: "dropbox-sign",
    capabilities: {
      embeddedSigning: true,
      orderedSigning: true,
      cancellation: true,
      separateAuditDownload: false,
    },
    webhookAcknowledgement: "Hello API Event Received",
    async createRequest(input) {
      validateRequest(input);
      const form = new FormData();
      form.set("client_id", options.clientId);
      form.set("test_mode", options.testMode ? "1" : "0");
      form.set("title", input.title);
      form.set("subject", input.title);
      form.set("metadata[absolute_reference]", input.reference);
      form.set("signing_redirect_url", input.returnUrl);
      input.documents.forEach((doc, index) =>
        form.set(
          `files[${index}]`,
          new Blob([new Uint8Array(doc.bytes)], { type: "application/pdf" }),
          doc.name,
        ),
      );
      input.signers.forEach((signer, index) => {
        form.set(`signers[${index}][name]`, signer.name);
        form.set(`signers[${index}][email_address]`, signer.email);
        if (signer.order !== undefined)
          form.set(`signers[${index}][order]`, String(signer.order - 1));
      });
      form.set(
        "form_fields_per_document",
        JSON.stringify(
          input.documents.map((doc) =>
            input.fields
              .filter((field) => field.documentId === doc.id)
              .map((field, index) => ({
                api_id: `signature_${doc.id}_${index}`,
                type: "signature",
                required: true,
                signer: input.signers.findIndex(
                  (signer) => signer.id === field.signerId,
                ),
                page: field.page,
                x: field.x,
                y: field.y,
                width: field.width,
                height: field.height,
              })),
          ),
        ),
      );
      // Dropbox Sign configures callbacks on the API app, not each request.
      const data = (await (
        await call("/signature_request/create_embedded", {
          method: "POST",
          body: form,
        })
      ).json()) as { signature_request: RequestData };
      if (!data.signature_request?.signature_request_id)
        throw new ESignError(
          "dropbox-sign",
          "invalid_response",
          "Dropbox Sign did not return a signature request ID.",
        );
      return normalized(data.signature_request);
    },
    async getRequest(id) {
      return normalized(await get(id));
    },
    async createSigningSession(input) {
      validateReturnUrl(input.returnUrl);
      const request = await get(input.requestId);
      if (
        !request.signatures.some(
          (signer) => signer.signature_id === input.signerId,
        )
      )
        throw new ESignError(
          "dropbox-sign",
          "invalid_input",
          "This signer does not belong to the saved signature request.",
        );
      const data = (await (
        await call(`/embedded/sign_url/${encodeURIComponent(input.signerId)}`)
      ).json()) as { embedded: { sign_url: string; expires_at: number } };
      if (
        !data.embedded?.sign_url ||
        new URL(data.embedded.sign_url).protocol !== "https:"
      )
        throw new ESignError(
          "dropbox-sign",
          "invalid_response",
          "Dropbox Sign did not return a secure signing URL.",
        );
      return {
        url: data.embedded.sign_url,
        expiresAt: new Date(data.embedded.expires_at * 1000).toISOString(),
        mode: "embedded",
        clientId: options.clientId,
      };
    },
    async downloadCompleted(id, artifact = "document") {
      if (artifact === "audit")
        throw new ESignError(
          "dropbox-sign",
          "unsupported",
          "Dropbox Sign includes its audit trail in the completed document.",
        );
      if (!(await get(id)).is_complete)
        throw new ESignError(
          "dropbox-sign",
          "not_completed",
          "The request is not fully signed.",
        );
      const response = await call(
        `/signature_request/files/${encodeURIComponent(id)}?file_type=pdf`,
      );
      return new Uint8Array(await response.arrayBuffer());
    },
    async cancelRequest(id, _reason) {
      await call(`/signature_request/cancel/${encodeURIComponent(id)}`, {
        method: "POST",
      });
    },
    verifyWebhook(body, _headers) {
      if (!options.webhookApiKey) return null;
      try {
        // The HTTP integration passes the multipart/form-data `json` field verbatim.
        const data = JSON.parse(body) as {
          event: {
            event_type: string;
            event_time: string;
            event_hash: string;
            event_metadata?: { reported_for_app_id?: string };
          };
          signature_request?: RequestData;
        };
        const event = data.event;
        if (
          !event?.event_type ||
          !event.event_time ||
          !event.event_hash ||
          !data.signature_request?.signature_request_id
        )
          return null;
        if (
          event.event_metadata?.reported_for_app_id &&
          event.event_metadata.reported_for_app_id !== options.clientId
        )
          return null;
        if (
          !secureDigestMatch(
            event.event_hash,
            hmacDigest(
              options.webhookApiKey,
              event.event_time + event.event_type,
              "hex",
            ),
          )
        )
          return null;
        const occurredAt = new Date(Number(event.event_time) * 1000);
        if (!Number.isFinite(occurredAt.getTime())) return null;
        return {
          id: webhookDigest(body),
          requestId: data.signature_request.signature_request_id,
          type: event.event_type,
          occurredAt: occurredAt.toISOString(),
        };
      } catch {
        return null;
      }
    },
  };
};
export type DropboxSignOAuthOptions = ProviderHttpOptions & {
  clientId: string;
  clientSecret: string;
};
export const dropboxSignOAuth = (options: DropboxSignOAuthOptions) => {
  const exchange = async (
    fields: Record<string, string>,
  ): Promise<OAuthTokens> => {
    const form = new FormData();
    Object.entries({
      client_id: options.clientId,
      client_secret: options.clientSecret,
      ...fields,
    }).forEach(([key, value]) => form.set(key, value));
    const data = (await (
      await requestProvider(
        "dropbox-sign",
        "https://app.hellosign.com/oauth/token",
        { method: "POST", body: form },
        options,
      )
    ).json()) as {
      access_token: string;
      refresh_token?: string;
      expires_in: number;
    };
    if (!data.access_token || !Number.isFinite(data.expires_in))
      throw new ESignError(
        "dropbox-sign",
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
          "dropbox-sign",
          "invalid_input",
          "OAuth state is required.",
        );
      const url = new URL("https://app.hellosign.com/oauth/authorize");
      url.search = new URLSearchParams({
        response_type: "code",
        client_id: options.clientId,
        redirect_uri: input.redirectUri,
        state: input.state,
      }).toString();
      return url.toString();
    },
    exchangeCode(input: { code: string; state: string }) {
      return exchange({
        grant_type: "authorization_code",
        code: input.code,
        state: input.state,
      });
    },
    refresh(refreshToken: string) {
      return exchange({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      });
    },
    async account(accessToken: string) {
      const data = (await (
        await requestProvider(
          "dropbox-sign",
          "https://api.hellosign.com/v3/account",
          { headers: { Authorization: `Bearer ${accessToken}` } },
          options,
        )
      ).json()) as { account: { account_id: string; email_address: string } };
      return data.account;
    },
  };
};
