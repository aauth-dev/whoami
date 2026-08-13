# whoami.aauth.dev — Claude project notes

## Deployment

**Do not run `wrangler deploy` manually.** Cloudflare Workers Builds is
connected to this repo and auto-deploys on every push to `main`. The
build runs `npm install`, then `npx wrangler deploy`.

To ship a change:

1. Commit locally.
2. `git push origin main`.
3. Verify (usually live within a minute):
   ```bash
   curl -s https://whoami.aauth.dev/.well-known/aauth-resource.json | jq .
   ```

Check deployment history in the Cloudflare dashboard (Workers & Pages →
whoami-aauth-dev → Deployments).

## Local development

- `npm run dev` — runs `wrangler dev` for local testing.
- `npx tsc --noEmit` — type check.

## Architecture quick ref

- Cloudflare Worker (`src/index.ts`, Hono) with a single `GET /` endpoint
  plus `.well-known` routes.
- No KV or other storage — stateless resource server.
- Signing key is an Ed25519 JWK stored as the `SIGNING_KEY` Worker
  secret (generated via `npm run generate-key`).

## Endpoint behaviour

| Request | Response |
|---------|----------|
| No HTTP signature | 401 + `Accept-Signature` header |
| Signature failed | 401 + `Signature-Error` header |
| `aa-agent+jwt`, no `?scope=` | 200 + agent identity `{ iss, sub, ps? }` |
| `aa-agent+jwt` with `?scope=` | 401 + `AAuth-Requirement: requirement=person-token` |
| `aa-person+jwt`, no `?scope=` | 200 + person identity `{ iss, sub }` |
| `aa-person+jwt` with `?scope=` | 401 + `AAuth-Requirement: requirement=auth-token` with resource token |
| `aa-auth+jwt` in Signature-Key | 200 + identity claims JSON |

`?scope=` changes the question from "who is this agent" to "who is the
person this agent acts for", and is what escalates the access mode. The
`whoami` scope is always included on the resource token.

## AAuth -11 invariants worth not breaking

- whoami deliberately demonstrates **two** access modes at one endpoint:
  agent identity access (agent token, no scope) and person identity
  access (person token). Do not collapse them.
- A resource MUST have verified a person token before it issues a
  resource token. When `?scope=` is set and only an agent token was
  presented, the challenge is returned without reading or fetching
  anything from the agent token — nothing in it would change the answer,
  and following its `iss` would let an attacker drive outbound requests.
- A person's identity is the pair `(iss, sub)`. `sub` is opaque and
  unique only within its issuer. `identityRecordKey` in `src/aauth.ts`
  is the only way a record key is produced, and it cannot be given a
  `sub` without an `iss`. An **agent** identifier is different: global,
  self-qualifying (`aauth:local@domain`), and still never parsed.
- Of the tokens a resource reads, only the agent token carries an agent
  identifier. -11 removed `agent` from person, resource and auth tokens
  — do not log or record one on those paths.
- Signing algorithms are fully specified (RFC 9864): emit **and accept**
  `Ed25519` only; the polymorphic `EdDSA` is rejected in
  `JWT_ALG_PARAMS`. This is a flag day with the issuers — Wallet's
  `svr/issuer/sign.js` must ship `Ed25519` for AAuth token types in the
  same window. Separately, `alg` is **stripped** before
  `crypto.subtle.importKey` in `src/crypto.ts` (both in `verifyJWT` and
  `importSigningKey`) — workerd rejects an OKP JWK whose `alg` is
  `Ed25519`, and `generate-key.mjs` stamps exactly that on the
  `SIGNING_KEY` secret. Both strips are load-bearing and Node-based
  tests will not catch their removal.
- R3 annotations are sparse. whoami's one AAuth operation requires
  exactly the resource-wide `access_mode`, so it publishes no
  `x-aauth-access-mode`.

## Testing

- `npm test` — vitest unit tests in `test/` (signed requests, token
  verification, resource token shape, directed identifiers).
- `bash scripts/test.sh` — curl-based smoke tests against the deployed URL.
- `bash scripts/test.sh http://localhost:8787` — test against local dev.
