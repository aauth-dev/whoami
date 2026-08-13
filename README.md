# whoami — AAuth Identity Resource

Part of [AAuth](https://aauth.dev). Live at [whoami.aauth.dev](https://whoami.aauth.dev/.well-known/aauth-resource.json).

A reference resource server demonstrating [AAuth](https://github.com/dickhardt/AAuth) identity. It answers two questions at one endpoint, and so shows two of AAuth's five access modes.

Present an `agent_token` and it tells you who the *agent* is — agent identity access, the replacement for an API key, with no Person Server involved. Present a `person_token` and it tells you who the *person* is. Ask for identity claims with `?scope=` and it returns a `resource_token` pointing back at that Person Server; come back with the `auth_token` and it releases the claims.

## Try it

Drive the full flow in the [AAuth Playground](https://playground.aauth.dev) — it handles agent signing, the PS interaction, and consent. Pick the whoami tab after bootstrapping an agent.

## Live endpoints

| URL | Description |
|-----|-------------|
| [/](https://whoami.aauth.dev/) | Identity claims endpoint (signed requests only) |
| [/.well-known/aauth-resource.json](https://whoami.aauth.dev/.well-known/aauth-resource.json) | Resource metadata with `access_mode` and `scope_descriptions` |
| [/.well-known/jwks.json](https://whoami.aauth.dev/.well-known/jwks.json) | Public signing key (Ed25519) |
| [/openapi.json](https://whoami.aauth.dev/openapi.json) | R3 vocabulary describing the endpoint |

## How it works

Every request to `GET /` must carry an RFC 9421 HTTP Message Signature whose `Signature-Key` is a JWT. What happens next depends on the JWT `typ`:

### 1. No signature

The resource returns `401` with an `Accept-Signature` header telling the agent which components to sign and that it expects a JWT-keyed signature.

### 2. `aa-agent+jwt` — agent asking who it is

With no `?scope=`, this is **agent identity access**. The resource verifies the agent token — `dwk: aauth-agent.json`, the agent provider's JWKS discovered at `{iss}/.well-known/aauth-agent.json`, `exp`/`iat`, `iss` as a conforming server identifier, `sub` as a valid agent identifier, and `cnf.jwk` equal to the key that signed the request — and returns the agent's `iss` and `sub`, plus `ps` and `parent_agent` when the token carries them. No Person Server, no authorization flow.

With `?scope=`, the caller is asking about a *person* instead, and an agent token cannot produce one: a resource must have verified a person token before it issues a resource token. The response is `401` with `AAuth-Requirement: requirement=person-token`, a header that carries no parameters. Nothing in the agent token is read on that path — it would not change the answer, and following its `iss` would let anyone drive outbound requests from this Worker for free. The agent obtains a person token for `https://whoami.aauth.dev` from its PS's `person_token_endpoint` and retries.

### 3. `aa-person+jwt` — agent naming the person it acts for

The resource verifies the person token: `typ`, `dwk: aauth-person.json`, the PS's JWKS discovered at `{iss}/.well-known/aauth-person.json`, `exp`/`iat`, `iss` as a conforming server identifier, `aud` equal to this resource, and `cnf.jwk` equal to the key that signed the HTTP request. A person token carrying `scope` or `account` is rejected.

With no `?scope=`, the verified token is the answer: the resource returns the person's directed identity, `iss` and `sub`.

With `?scope=`, it mints a short-lived `resource_token` (`aa-resource+jwt`) audienced to the PS that issued the person token. The token copies `ps`, `sub` and `person_token_jti` from that person token, carries `agent_jkt` and `mission_s256` when the person token had one, and expires within five minutes and never after the person token does. The response is `401` with `AAuth-Requirement: requirement=auth-token; resource-token="..."`. The agent takes it to its PS and exchanges it for an `auth_token`.

### 4. `aa-auth+jwt` — agent returning with claims

The resource verifies the auth token against the issuer's JWKS — `aauth-person.json` from a PS, `aauth-access.json` from an AS — checks `aud`, `exp`, `cnf.jwk` against the request-signing key, that `sub` is present, and that `whoami` is in `scope`. It then returns a JSON body with `iss` and `sub` followed by the identity claims, dropping JWT infrastructure claims (`aud`, `exp`, `iat`, `jti`, `cnf`, `dwk`, `scope`, `ps`, `mission_s256`).

## Identity

The two identities this resource returns are not the same shape.

**A person is the pair (`iss`, `sub`).** `sub` is a directed identifier: unique within the issuer that minted it, not globally, and opaque. This resource treats it accordingly — it never parses or normalizes a `sub`, it always releases `iss` alongside it, and it never matches a `sub` received from one issuer against a record established under another, however the values compare. Two person tokens carrying the same `sub` string from different Person Servers are two different people here.

**An agent is named by `sub` alone**, an agent identifier of the form `aauth:local@domain`. It is global and self-qualifying, and just as opaque: compare it exactly and case-sensitively, and never parse the local part. The `+` in `aauth:planner.7f3c+search1@vendor.example` is for readability in logs; `parent_agent` is the authoritative sub-agent marker.

The agent token is the only token this resource reads that carries an agent identifier. AAuth -11 removed `agent` from person, resource and auth tokens, so on the person path none is recorded — what binds a request to an agent there is `agent_jkt`, the thumbprint of its signing key.

## Missions

A mission reaches a resource only inside a PS-issued token, as the `mission_s256` claim; the `AAuth-Mission` header was removed in -11. When a person token carries one, the resource token copies it unchanged — omitting it is what mission stripping would look like, and the PS detects it by resolving `person_token_jti` against the token it actually issued.

## Scopes

The `whoami` scope is always included on the resource token. Additional identity scopes can be requested via the `?scope=` query parameter and are passed through on `resource_token.scope`. Setting `?scope=` is what changes the question from "who is this agent" to "who is the person this agent acts for", and so escalates the call from `agent-token` to `person-token` and then `auth-token`. The supported set combines standard OIDC scopes with Hellō identity attributes:

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
npm test                                     # unit tests (vitest)
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
