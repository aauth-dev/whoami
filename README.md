# whoami — AAuth Identity Resource

Part of [AAuth](https://aauth.dev). Live at [whoami.aauth.dev](https://whoami.aauth.dev).

A reference resource server demonstrating [AAuth](https://github.com/dickhardt/AAuth) identity claim release. Agents present an `agent_token`, receive a `resource_token` pointing at their Person Server, and come back with an `auth_token` that unlocks the caller's identity claims.

## Try it

Drive the full flow in the [AAuth Playground](https://playground.aauth.dev) — it handles agent signing, the PS interaction, and consent. Pick the whoami tab after bootstrapping an agent.

## Live endpoints

| URL | Description |
|-----|-------------|
| [/](https://whoami.aauth.dev/) | Identity claims endpoint (signed requests only) |
| [/.well-known/aauth-resource.json](https://whoami.aauth.dev/.well-known/aauth-resource.json) | Resource metadata with `scope_descriptions` |
| [/.well-known/jwks.json](https://whoami.aauth.dev/.well-known/jwks.json) | Public signing key (Ed25519) |

## How it works

Every request to `GET /` must carry an RFC 9421 HTTP Message Signature whose `Signature-Key` is a JWT. What happens next depends on the JWT `typ`:

### 1. No signature

The resource returns `401` with an `Accept-Signature` header telling the agent which components to sign and that it expects a JWT-keyed signature.

### 2. `aa-agent+jwt` — agent introducing itself

The resource verifies the agent token against the agent server's JWKS, reads the `ps` claim, fetches the PS metadata for its issuer, and mints a short-lived `resource_token` (`aa-resource+jwt`) audienced to that PS. The token carries the requested scopes and the agent's JWK thumbprint.

The response is `401` with an `AAuth-Requirement` header containing the resource token. The agent takes it to its PS and exchanges it for an `auth_token`.

### 3. `aa-auth+jwt` — agent returning with claims

The resource verifies the auth token against the issuer's JWKS, checks `aud`, `exp`, and that `whoami` is in `scope`, then returns a JSON body containing the identity claims (everything except JWT infrastructure claims like `iss`, `aud`, `exp`, `cnf`, etc.).

## Scopes

The `whoami` scope is always included on the resource token. Additional identity scopes can be requested via the `?scope=` query parameter and are passed through on `resource_token.scope`. The supported set combines standard OIDC scopes with Hellō identity attributes:

```
openid profile name nickname given_name family_name preferred_username
picture email phone ethereum discord twitter github gitlab bio banner
recovery mastodon instagram verified_name existing_name existing_username
tenant_sub org groups roles
```

Example: `GET /?scope=email%20picture`

## Tech stack

- [Cloudflare Workers](https://workers.cloudflare.com/) with [Hono](https://hono.dev/)
- Stateless — no KV or other storage
- [@hellocoop/httpsig](https://www.npmjs.com/package/@hellocoop/httpsig) for RFC 9421 HTTP Message Signatures
- Ed25519 signing keys

## Development

```bash
npm install
npm run dev                                  # local dev server
npx tsc --noEmit                             # type check
bash scripts/test.sh                         # smoke tests against production
bash scripts/test.sh http://localhost:8787   # smoke tests against local dev
```

## Deployment

Cloudflare Workers Builds auto-deploys on push to `main`. To set up from scratch:

```bash
npm run generate-key
# copy the output, then:
npx wrangler secret put SIGNING_KEY
npx wrangler deploy
```

## Contributing

Please read [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) before participating.

## License

[MIT](./LICENSE)
