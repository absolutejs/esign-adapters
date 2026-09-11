# @absolutejs/esign-docusign

```ts
import { docusign } from '@absolutejs/esign-docusign';
const provider = docusign({
  accountId: connectedAccount.accountId,
  baseUri: connectedAccount.baseUri,
  accessToken: () => tokenResolver.getFreshToken(),
  hmacSecrets: [process.env.DOCUSIGN_CONNECT_HMAC_SECRET!],
});
```

The base URI must be the HTTPS `base_uri` for the selected account returned by OAuth `/userinfo`, not a user-entered API URL. Sandbox uses `https://account-d.docusign.com`; production OAuth uses `https://account.docusign.com`. `docusignOAuth` provides authorization URL construction, code exchange, refresh, and account discovery. The application must validate OAuth state and authorize the selected account.

Use a DocuSign integration key with an approved redirect URI and configure Connect HMAC secrets. Pass the exact raw JSON callback body and headers to `verifyWebhook`; key rotation is supported by passing multiple secrets. Reconcile the saved envelope afterward. `authenticationMethod: none` records that the application provides recipient authorization; it does not add provider identity verification.

Signature requests use embedded recipients. Open `createSigningSession().url` as a top-level navigation, then reconcile after returning. Both combined PDF and completion certificate downloads require a completed envelope.

References: [Create envelope](https://developers.docusign.com/docs/esign-rest-api/reference/envelopes/envelopes/create/), [recipient view](https://www.docusign.com/blog/developers/deep-dive-the-embedded-signing-recipient-view), [Connect HMAC](https://www.docusign.com/blog/developers/manually-authenticating-hmac-signatures-docusign-connect-webhook-configurations).
