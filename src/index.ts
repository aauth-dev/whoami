import { Hono } from 'hono'
import { cors } from 'hono/cors'
import {
  verify as httpSigVerify,
  generateSignatureErrorHeader,
  generateAcceptSignatureHeader,
} from '@hellocoop/httpsig'
import {
  importSigningKey,
  getPublicJWK,
  signJWT,
  generateJTI,
  computeJwkThumbprint,
  verifyJWT,
} from './crypto'
import type { Env } from './types'

type HonoEnv = { Bindings: Env }

const app = new Hono<HonoEnv>()

// AAuth-specific response headers must be explicitly exposed so
// cross-origin JS clients (playground.aauth.dev and other demo agents
// running in a browser) can read them. Without this, fetch() drops
// AAuth-Requirement from the 401 response and the agent never sees
// the resource_token it needs to exchange at the PS.
app.use('*', cors({
  exposeHeaders: ['AAuth-Requirement', 'Accept-Signature', 'Signature-Error'],
}))

// Identity scopes the PS can release — passed through on resource_token.scope.
const PS_IDENTITY_SCOPES: Set<string> = new Set([
  'openid', 'profile', 'name', 'nickname', 'given_name', 'family_name',
  'preferred_username', 'picture', 'email', 'phone', 'ethereum', 'discord',
  'twitter', 'github', 'gitlab', 'bio', 'banner', 'recovery', 'mastodon',
  'instagram', 'verified_name', 'existing_name', 'existing_username',
  'tenant_sub', 'org', 'groups', 'roles',
])

// ── Well-known endpoints ──

app.get('/.well-known/aauth-resource.json', (c) => {
  const origin = c.env.ORIGIN
  return c.json({
    issuer: origin,
    jwks_uri: `${origin}/.well-known/jwks.json`,
    client_name: 'AAuth Who Am I',
    scope_descriptions: {
      whoami: 'Access your identity claims',
    },
  })
})

app.get('/.well-known/jwks.json', async (c) => {
  const publicJwk = await getPublicJWK(c.env.SIGNING_KEY)
  return c.json({ keys: [publicJwk] })
})

// ── Main endpoint ──
//
// Three outcomes based on what the caller presents:
//
// 1. No HTTP signature → 401 + Accept-Signature header
//    (tells the agent what signature scheme we expect)
//
// 2. agent_token in Signature-Key → 401 + AAuth-Requirement header
//    (resource token the agent takes to its PS for an auth_token)
//
// 3. auth_token in Signature-Key → 200 + identity claims as JSON

app.get('/', async (c) => {
  const url = new URL(c.req.url)

  const sigResult = await httpSigVerify({
    method: c.req.method,
    authority: url.host,
    path: url.pathname,
    query: url.search.replace(/^\?/, ''),
    headers: c.req.raw.headers,
  })

  // ── No valid signature ──
  if (!sigResult.verified) {
    // Distinguish "no signature at all" from "bad signature"
    const noSig = !c.req.header('signature') && !c.req.header('signature-input')

    if (noSig) {
      // Tell the agent what we expect
      const acceptSig = generateAcceptSignatureHeader({
        label: 'sig',
        components: ['@method', '@authority', '@path', 'signature-key'],
        sigkey: 'jkt',
      })
      return c.json(
        { error: 'signature_required' },
        { status: 401, headers: { 'Accept-Signature': acceptSig } },
      )
    }

    // Signature was attempted but failed
    const headers: Record<string, string> = {}
    if (sigResult.signatureError) {
      headers['Signature-Error'] = generateSignatureErrorHeader(sigResult.signatureError)
    }
    return c.json(
      { error: 'signature_verification_failed', detail: sigResult.error },
      { status: 401, headers },
    )
  }

  // Must be JWT key type
  if (sigResult.keyType !== 'jwt' || !sigResult.jwt) {
    return c.json({ error: 'Signature-Key must use sig=jwt scheme' }, 401)
  }

  const jwtHeader = sigResult.jwt.header as Record<string, unknown>
  const jwtPayload = sigResult.jwt.payload as Record<string, unknown>
  const jwtRaw = sigResult.jwt.raw

  // ── auth_token → verify and return identity claims ──
  if (jwtHeader.typ === 'aa-auth+jwt') {
    return handleAuthToken(c, jwtRaw, jwtPayload)
  }

  // ── agent_token → mint resource token, return 401 ──
  if (jwtHeader.typ === 'aa-agent+jwt') {
    return handleAgentToken(c, jwtRaw, jwtPayload)
  }

  return c.json({ error: `unsupported JWT type: ${jwtHeader.typ}` }, 400)
})

// ── Auth token handler ──

async function handleAuthToken(
  c: { env: Env; json: Function; req: { url: string } },
  jwtRaw: string,
  payload: Record<string, unknown>,
) {
  // Verify JWT against issuer's JWKS (the Person Server)
  const iss = payload.iss as string | undefined
  const dwk = (payload.dwk as string) || 'aauth-person.json'
  if (!iss) return c.json({ error: 'auth_token missing iss' }, 401)

  let jwks: { keys: JsonWebKey[] }
  try {
    const metaRes = await fetch(`${iss}/.well-known/${dwk}`)
    if (!metaRes.ok) return c.json({ error: `Failed to fetch issuer metadata: ${metaRes.status}` }, 502)
    const meta = (await metaRes.json()) as Record<string, unknown>
    const jwksUri = meta.jwks_uri as string
    if (!jwksUri) return c.json({ error: 'Issuer metadata missing jwks_uri' }, 502)
    const jwksRes = await fetch(jwksUri)
    if (!jwksRes.ok) return c.json({ error: `Failed to fetch issuer JWKS: ${jwksRes.status}` }, 502)
    jwks = (await jwksRes.json()) as { keys: JsonWebKey[] }
  } catch (err) {
    return c.json({ error: `Cannot reach issuer: ${(err as Error).message}` }, 502)
  }

  try {
    await verifyJWT(jwtRaw, jwks)
  } catch (err) {
    return c.json({ error: `auth_token verification failed: ${(err as Error).message}` }, 401)
  }

  const origin = c.env.ORIGIN
  if (payload.aud !== origin) {
    return c.json({ error: 'auth_token aud mismatch' }, 401)
  }

  const now = Math.floor(Date.now() / 1000)
  if (!payload.exp || (payload.exp as number) < now) {
    return c.json({ error: 'auth_token expired' }, 401)
  }

  const scopeStr = typeof payload.scope === 'string' ? payload.scope : ''
  const scopes = scopeStr.split(/\s+/).filter(Boolean)
  if (!scopes.includes('whoami')) {
    return c.json({ error: 'insufficient_scope', required: 'whoami', granted: scopes }, 403)
  }

  // Return identity claims — strip JWT infrastructure claims
  const INFRA_CLAIMS = new Set(['iss', 'aud', 'exp', 'iat', 'jti', 'cnf', 'dwk', 'act', 'scope'])
  const claims: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(payload)) {
    if (!INFRA_CLAIMS.has(key)) {
      claims[key] = value
    }
  }

  return c.json(claims)
}

// ── Agent token handler ──

async function handleAgentToken(
  c: { env: Env; json: Function; req: { url: string; query: (k: string) => string | undefined } },
  jwtRaw: string,
  payload: Record<string, unknown>,
) {
  // Verify agent_token against its issuer's JWKS (the agent server)
  const agentIss = payload.iss as string | undefined
  const agentDwk = (payload.dwk as string) || 'aauth-agent.json'
  if (!agentIss) return c.json({ error: 'agent_token missing iss' }, 401)

  let jwks: { keys: JsonWebKey[] }
  try {
    const metaRes = await fetch(`${agentIss}/.well-known/${agentDwk}`)
    if (!metaRes.ok) return c.json({ error: `Failed to fetch agent server metadata: ${metaRes.status}` }, 502)
    const meta = (await metaRes.json()) as Record<string, unknown>
    const jwksUri = meta.jwks_uri as string
    if (!jwksUri) return c.json({ error: 'Agent server metadata missing jwks_uri' }, 502)
    const jwksRes = await fetch(jwksUri)
    if (!jwksRes.ok) return c.json({ error: `Failed to fetch agent server JWKS: ${jwksRes.status}` }, 502)
    jwks = (await jwksRes.json()) as { keys: JsonWebKey[] }
  } catch (err) {
    return c.json({ error: `Cannot reach agent server: ${(err as Error).message}` }, 502)
  }

  try {
    await verifyJWT(jwtRaw, jwks)
  } catch (err) {
    return c.json({ error: `agent_token verification failed: ${(err as Error).message}` }, 401)
  }

  const now = Math.floor(Date.now() / 1000)
  if (!payload.exp || (payload.exp as number) < now) {
    return c.json({ error: 'agent_token expired' }, 401)
  }

  // If no scope requested, return the agent's own identity directly
  const scopeParam = c.req.query('scope') || ''
  const requestedScopes = scopeParam.trim().split(/\s+/).filter(Boolean)

  if (requestedScopes.length === 0) {
    const identity: Record<string, unknown> = { sub: payload.sub }
    if (payload.ps) identity.ps = payload.ps
    return c.json(identity)
  }

  // PS URL from agent_token's ps claim
  const psUrl = payload.ps as string | undefined
  if (!psUrl) return c.json({ error: 'agent_token missing ps claim' }, 400)

  // Fetch PS metadata for resource_token aud
  let psIssuer: string
  try {
    const psRes = await fetch(`${psUrl}/.well-known/aauth-person.json`)
    if (!psRes.ok) return c.json({ error: `Failed to fetch PS metadata: ${psRes.status}` }, 502)
    const psMeta = (await psRes.json()) as Record<string, unknown>
    if (!psMeta.issuer) return c.json({ error: 'PS metadata missing issuer' }, 502)
    psIssuer = psMeta.issuer as string
  } catch (err) {
    return c.json({ error: `Cannot reach PS: ${(err as Error).message}` }, 502)
  }

  // Build scope: always "whoami" + requested identity scopes from ?scope=
  const unknown = requestedScopes.filter((s) => !PS_IDENTITY_SCOPES.has(s))
  if (unknown.length > 0) {
    return c.json({ error: 'invalid_scope', unknown }, 400)
  }
  const scopeString = ['whoami', ...requestedScopes].join(' ')

  // Mint resource token
  const origin = c.env.ORIGIN
  const privateKey = await importSigningKey(c.env.SIGNING_KEY)
  const publicJwk = await getPublicJWK(c.env.SIGNING_KEY)
  const cnf = payload.cnf as { jwk: JsonWebKey } | undefined
  if (!cnf?.jwk) return c.json({ error: 'agent_token missing cnf.jwk' }, 400)
  const agentJkt = await computeJwkThumbprint(cnf.jwk)

  const rtHeader = { alg: 'EdDSA', typ: 'aa-resource+jwt', kid: publicJwk.kid }
  const rtPayload = {
    iss: origin,
    dwk: 'aauth-resource.json',
    aud: psIssuer,
    jti: generateJTI(),
    agent: payload.sub as string,
    agent_jkt: agentJkt,
    scope: scopeString,
    iat: now,
    exp: now + 300,
  }

  const resourceToken = await signJWT(rtHeader, rtPayload, privateKey)

  return c.json(
    { error: 'auth_token_required' },
    {
      status: 401,
      headers: {
        'AAuth-Requirement': `requirement=auth-token; resource-token="${resourceToken}"`,
      },
    },
  )
}

export default app
