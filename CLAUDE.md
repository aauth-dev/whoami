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
| `aa-agent+jwt` in Signature-Key | 401 + `AAuth-Requirement` with resource token |
| `aa-auth+jwt` in Signature-Key | 200 + identity claims JSON |

The `?scope=` query parameter adds identity scopes to the resource
token. The `whoami` scope is always included.

## Testing

- `bash scripts/test.sh` — curl-based smoke tests against the deployed URL.
- `bash scripts/test.sh http://localhost:8787` — test against local dev.
