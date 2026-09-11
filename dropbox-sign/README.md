# @absolutejs/esign-dropbox-sign

```ts
import { dropboxSign } from '@absolutejs/esign-dropbox-sign';
const provider = dropboxSign({
  clientId: process.env.DROPBOX_SIGN_CLIENT_ID!,
  accessToken: () => tokenResolver.getFreshToken(),
  webhookApiKey: process.env.DROPBOX_SIGN_WEBHOOK_API_KEY!,
  testMode: true,
});
```

Supports OAuth bearer tokens or an explicitly configured API key. OAuth tokens are distinct from the API key used to verify callback event hashes. `dropboxSignOAuth` provides authorization URLs, code exchange, refresh, and account discovery. The host must validate OAuth state and persist grants securely.

Configure the API app's callback URL and allowed embedded domain. App approval is required for production embedded/OAuth use. Keep `testMode: true` until the app is approved and live verification is complete. Test-mode requests are not production signatures.

Use the official `hellosign-embedded` browser client to open the returned signing URL with `clientId`; honor its documented domain checks and configured return flow. Do not treat a browser `sign` or `close` event as completion. Reconcile the saved request with the backend.

Dropbox sends callbacks as multipart form data. Pass the exact `json` field to `verifyWebhook`. Return `Hello API Event Received` after processing. The HMAC covers event time/type only; **always fetch the saved request again before updating agreement state**. Completed-document downloads contain the audit trail; a separate audit endpoint is not offered by this adapter.

References: [Embedded signing](https://developers.hellosign.com/docs/embedded-signing/walkthrough), [callback verification](https://developers.hellosign.com/docs/guides/events-and-callbacks/walkthrough), [OAuth](https://developers.hellosign.com/docs/guides/o-auth/walkthrough), [field placement](https://developers.hellosign.com/api/manual-reference-pages/constants).
