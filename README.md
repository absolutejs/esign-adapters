# AbsoluteJS e-sign adapters

Independent packages implementing `@absolutejs/esign`. Mirrors the `voice` / `voice-adapters` arrangement.

| Package | Signing session | Separate audit file | Callback configuration |
| --- | --- | --- | --- |
| `@absolutejs/esign-docusign` | Redirect to embedded recipient view | Yes | Connect HMAC, JSON events; per-envelope URL supported |
| `@absolutejs/esign-dropbox-sign` | Embedded session via the provider client | Audit included in completed PDF | API app callback URL |

Run `bun install` to install the published `@absolutejs/esign` core, then run `bun run build`. Run `bun test test` for mocked provider-contract tests. The implementation is tested without credentials; no live signing requests have been sent.

Provider account connection and request creation are separate: users connect their own accounts through OAuth, then the application authorizes which party can send or sign each agreement. Signers do not need an onSpark account merely to participate.
