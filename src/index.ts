import { Hono } from 'hono'
import { cors } from 'hono/cors'
import {
  verify as httpSigVerify,
  generateSignatureErrorHeader,
  generateAcceptSignatureHeader,
  generateAcceptSignatureSchemeHeader,
  generateAcceptSignatureAlgHeader,
} from '@hellocoop/httpsig'
import {
  importSigningKey,
  getPublicJWK,
  signJWT,
  generateJTI,
  verifyJWT,
} from './crypto'
import {
  TOKEN_TYP,
  DWK,
  SIGNING_ALG,
  fetchIssuerJwks,
  identityRecordKey,
  isServerIdentifier,
  verifyAgentToken,
  verifyConfirmationKey,
  verifyPersonToken,
  type PersonIdentity,
} from './aauth'
import { emit, emitVerifyFailed } from './events'
import type { Env } from './types'

type HonoEnv = { Bindings: Env }

const app = new Hono<HonoEnv>()

// Catch every unhandled exception, emit a structured error event with
// a stack trace, and return a clean 500. Without this, unprotected
// crypto and KV calls bubble to Hono's default 500 with no context.
app.onError((err, c) => {
  const error = err instanceof Error ? err : new Error(String(err))
  emit(c, {
    event: 'aauth.unhandled_error',
    level: 50,
    msg: error.message,
    route: new URL(c.req.url).pathname,
    method: c.req.method,
    error_name: error.name,
    error_message: error.message,
    error_stack: error.stack,
  })
  return c.json({ error: 'internal error' }, 500)
})

// AAuth-specific response headers must be explicitly exposed so
// cross-origin JS clients (playground.aauth.dev and other demo agents
// running in a browser) can read them. Without this, fetch() drops
// AAuth-Requirement from the 401 response and the agent never sees
// the resource_token it needs to exchange at the PS.
app.use('*', cors({
  // '*' is the value hono has always defaulted to here; recent @types make
  // `origin` required, so it is now stated rather than implied.
  origin: '*',
  exposeHeaders: [
    'AAuth-Requirement',
    'Accept-Signature',
    'Accept-Signature-Scheme',
    'Accept-Signature-Alg',
    'Signature-Error',
  ],
}))

// Identity scopes the PS can release — passed through on resource_token.scope.
const PS_IDENTITY_SCOPES: Set<string> = new Set([
  'openid', 'profile', 'name', 'nickname', 'given_name', 'family_name',
  'preferred_username', 'picture', 'email', 'phone', 'ethereum', 'discord',
  'twitter', 'github', 'gitlab', 'bio', 'banner', 'recovery', 'mastodon',
  'instagram', 'verified_name', 'existing_name', 'existing_username',
  'tenant_sub', 'org', 'groups', 'roles',
])

// Resource tokens SHOULD NOT have a lifetime exceeding 5 minutes.
const RESOURCE_TOKEN_LIFETIME = 300

// ── Well-known endpoints ──

app.get('/.well-known/aauth-resource.json', (c) => {
  const origin = c.env.ORIGIN
  return c.json({
    issuer: origin,
    jwks_uri: `${origin}/.well-known/jwks.json`,
    name: 'AAuth Who Am I',
    description:
      'Echoes back the identity claims a resource sees from your AAuth credentials — a minimal resource for testing identity-based access.',
    logo_uri: `${origin}/logo.png`,
    // The lowest bar that gets a useful answer: an agent token alone returns
    // the agent's own identity. A person token returns the person's. Asking
    // for identity scopes with ?scope= escalates to auth-token. Declaring the
    // minimum means no agent skips this resource for a setup it does have;
    // the runtime AAuth-Requirement is authoritative in every case.
    access_mode: 'agent-token',
    scope_descriptions: {
      whoami: 'Echo your provided identity claims',
    },
    r3_vocabularies: {
      'urn:aauth:vocabulary:openapi': `${origin}/openapi.json`,
    },
  })
})

app.get('/.well-known/jwks.json', async (c) => {
  const publicJwk = await getPublicJWK(c.env.SIGNING_KEY)
  return c.json({ keys: [publicJwk] })
})

// ── Main endpoint ──
//
// Four outcomes based on what the caller presents:
//
// 1. No HTTP signature → 401 + Accept-Signature header
//    (tells the agent what signature scheme we expect)
//
// 2. agent_token in Signature-Key → 200 + the agent's own identity (agent
//    identity access), or, when ?scope= asks about a person, 401 +
//    AAuth-Requirement: requirement=person-token — a resource MUST have
//    verified a person token before it issues a resource token
//
// 3. person_token in Signature-Key → 200 + the person's identity (iss, sub),
//    or, when ?scope= asks for identity claims, 401 + AAuth-Requirement
//    carrying a resource token the agent takes to its PS for an auth_token
//
// 4. auth_token in Signature-Key → 200 + identity claims as JSON

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
      // Tell the agent what we expect. The sigkey parameter was removed in
      // -08; the accepted Signature-Key schemes travel in the separate
      // Accept-Signature-Scheme header.
      const acceptSig = generateAcceptSignatureHeader({
        label: 'sig',
        components: ['@method', '@authority', '@path', 'signature-key'],
      })
      emitVerifyFailed(c, 'no_signature')
      return c.json(
        { error: 'signature_required' },
        {
          status: 401,
          headers: {
            'Accept-Signature': acceptSig,
            'Accept-Signature-Scheme': generateAcceptSignatureSchemeHeader(['jwt']),
          },
        },
      )
    }

    // Signature was attempted but failed
    const headers: Record<string, string> = {}
    if (sigResult.signatureError) {
      headers['Signature-Error'] = generateSignatureErrorHeader(sigResult.signatureError)
    }
    // On unsupported_algorithm the accepted set comes back on the result;
    // advertise it so the client can re-sign with an acceptable algorithm.
    if (sigResult.acceptSignatureAlg) {
      headers['Accept-Signature-Alg'] = generateAcceptSignatureAlgHeader(
        sigResult.acceptSignatureAlg,
      )
    }
    emitVerifyFailed(c, 'signature_invalid', {
      detail: sigResult.error,
      signature_error_code: sigResult.signatureError?.error,
    })
    return c.json(
      { error: 'signature_verification_failed', detail: sigResult.error },
      { status: 401, headers },
    )
  }

  // Must be JWT key type
  if (sigResult.keyType !== 'jwt' || !sigResult.jwt) {
    emitVerifyFailed(c, 'wrong_key_scheme', { actual_key_type: sigResult.keyType })
    return c.json({ error: 'Signature-Key must use sig=jwt scheme' }, 401)
  }

  const jwtHeader = sigResult.jwt.header as Record<string, unknown>
  const jwtPayload = sigResult.jwt.payload as Record<string, unknown>
  const jwtRaw = sigResult.jwt.raw

  // ── auth_token → verify and return identity claims ──
  //
  // Only `typ` distinguishes an auth token from a person token, so the branch
  // is exact-match: an aa-person+jwt never reaches the auth-token path.
  if (jwtHeader.typ === TOKEN_TYP.auth) {
    return handleAuthToken(c, jwtRaw, jwtPayload, sigResult.thumbprint)
  }

  // ── person_token → identity, or mint a resource token ──
  if (jwtHeader.typ === TOKEN_TYP.person) {
    return handlePersonToken(c, jwtRaw, jwtPayload, sigResult.thumbprint)
  }

  // ── agent_token → agent identity, or 401 requirement=person-token ──
  if (jwtHeader.typ === TOKEN_TYP.agent) {
    return handleAgentToken(c, jwtRaw, jwtPayload, sigResult.thumbprint)
  }

  emitVerifyFailed(c, 'unsupported_jwt_type', { jwt_typ: jwtHeader.typ })
  return c.json({ error: `unsupported JWT type: ${jwtHeader.typ}` }, 400)
})

// ── Auth token handler ──

async function handleAuthToken(
  c: import('hono').Context<HonoEnv>,
  jwtRaw: string,
  payload: Record<string, unknown>,
  callerJkt: string,
) {
  // dwk names the metadata document the issuer's keys are discovered through:
  // aauth-person.json from a PS asserting identity, aauth-access.json from an
  // AS. Anything else is not an auth token issuer.
  const iss = payload.iss as string | undefined
  const dwk = payload.dwk
  if (!iss) return c.json({ error: 'auth_token missing iss' }, 401)
  if (dwk !== DWK.person && dwk !== DWK.access) {
    emitVerifyFailed(c, 'auth_token_bad_dwk', { iss, dwk })
    return c.json({ error: `auth_token dwk must be ${DWK.person} or ${DWK.access}` }, 401)
  }
  if (!isServerIdentifier(iss)) {
    emitVerifyFailed(c, 'auth_token_bad_iss', { iss })
    return c.json({ error: 'auth_token iss is not a valid server identifier' }, 401)
  }

  const lookup = await fetchIssuerJwks(iss, dwk)
  if (!lookup.ok) {
    emitVerifyFailed(c, 'auth_token_key_discovery_failed', { iss, detail: lookup.error })
    return c.json({ error: lookup.error }, lookup.status)
  }

  try {
    await verifyJWT(jwtRaw, lookup.jwks)
  } catch (err) {
    emitVerifyFailed(c, 'auth_token_jwt_verify_failed', {
      iss,
      detail: (err as Error).message,
    })
    return c.json({ error: `auth_token verification failed: ${(err as Error).message}` }, 401)
  }

  const origin = c.env.ORIGIN
  if (payload.aud !== origin) {
    emitVerifyFailed(c, 'auth_token_aud_mismatch', {
      iss,
      aud_actual: payload.aud,
      aud_expected: origin,
    })
    return c.json({ error: 'auth_token aud mismatch' }, 401)
  }

  const now = Math.floor(Date.now() / 1000)
  if (!payload.exp || (payload.exp as number) < now) {
    emitVerifyFailed(c, 'auth_token_expired', { iss, exp: payload.exp })
    return c.json({ error: 'auth_token expired' }, 401)
  }

  // cnf.jwk is REQUIRED and must be the key that signed this request.
  const cnfResult = await verifyConfirmationKey(payload.cnf, callerJkt)
  if (!cnfResult.ok) {
    emitVerifyFailed(c, 'auth_token_cnf_mismatch', { iss, detail: cnfResult.error })
    return c.json({ error: `auth_token ${cnfResult.error}` }, 401)
  }

  // Verification step 7: `sub` is present, and (iss, sub) matches or
  // establishes this resource's record for the person. The value is opaque —
  // whoami never parses it, and never compares it to a sub from another iss.
  const sub = payload.sub
  if (typeof sub !== 'string' || sub === '') {
    emitVerifyFailed(c, 'auth_token_missing_sub', { iss })
    return c.json({ error: 'auth_token missing sub' }, 401)
  }
  const identity: PersonIdentity = { iss, sub }

  const scopeStr = typeof payload.scope === 'string' ? payload.scope : ''
  const scopes = scopeStr.split(/\s+/).filter(Boolean)
  if (!scopes.includes('whoami')) {
    emitVerifyFailed(c, 'insufficient_scope', {
      iss,
      required: 'whoami',
      granted: scopes,
    })
    return c.json({ error: 'insufficient_scope', required: 'whoami', granted: scopes }, 403)
  }

  // Return identity claims. `iss` and `sub` are released together and first:
  // a directed sub on its own names nobody, so whoami never hands one out
  // without the issuer whose namespace it belongs to.
  const INFRA_CLAIMS = new Set([
    'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'cnf', 'dwk', 'act', 'scope',
    'ps', 'mission_s256',
  ])
  const claims: Record<string, unknown> = { iss: identity.iss, sub: identity.sub }
  for (const [key, value] of Object.entries(payload)) {
    if (!INFRA_CLAIMS.has(key)) {
      claims[key] = value
    }
  }

  emit(c, {
    event: 'aauth.whoami.auth_verified',
    msg: 'auth_token verified',
    person_iss: identity.iss,
    person_sub: identity.sub,
    identity_key: identityRecordKey(identity),
    ps: payload.ps,
    mission_s256: payload.mission_s256,
    scope: scopeStr,
    jkt: callerJkt,
  })

  return c.json(claims)
}

// ── Agent token handler ──
//
// Two outcomes, and which one applies is decided by what the caller asked
// for, not by what it presented.
//
// With no scopes requested, this is agent identity access
// (#overview-identity-access): the resource verifies the agent token and
// answers with the agent's own identity. No PS, no authorization flow — the
// API-key replacement. The agent token is the one token a resource reads that
// still carries an agent identifier; -11 removed `agent` from person,
// resource and auth tokens, not from here.
//
// With scopes requested, the caller is asking about a *person*, and an agent
// token cannot produce one: a resource MUST have verified a person token
// before it issues a resource token. So the response is the
// requirement=person-token challenge, which carries no parameters — and the
// agent token is neither fetched nor verified on that path, because nothing
// in it would change the answer and following its `iss` would let an attacker
// drive outbound requests from this Worker for free.

async function handleAgentToken(
  c: import('hono').Context<HonoEnv>,
  jwtRaw: string,
  payload: Record<string, unknown>,
  callerJkt: string,
) {
  const scopeParam = c.req.query('scope') || ''
  const requestedScopes = scopeParam.trim().split(/\s+/).filter(Boolean)

  if (requestedScopes.length > 0) {
    emit(c, {
      event: 'aauth.whoami.person_token_required',
      msg: 'agent_token presented with a scope request; challenging for a person token',
      requested_scope: requestedScopes.join(' '),
    })
    return c.json(
      { error: 'person_token_required' },
      {
        status: 401,
        headers: {
          'AAuth-Requirement': 'requirement=person-token',
        },
      },
    )
  }

  const now = Math.floor(Date.now() / 1000)
  const result = await verifyAgentToken(jwtRaw, payload, { signingJkt: callerJkt, now })
  if (!result.ok) {
    emitVerifyFailed(c, result.reason, { iss: payload.iss, detail: result.error })
    return c.json({ error: result.error }, result.status)
  }
  const { identity } = result.token

  // An agent identifier is global and self-qualifying (`aauth:local@domain`),
  // unlike a person's directed `sub` — but it is just as opaque. `iss` is
  // released alongside it because it names the provider that vouched for it.
  const body: Record<string, unknown> = { iss: identity.iss, sub: identity.sub }
  if (identity.ps) body.ps = identity.ps
  if (identity.parent_agent) body.parent_agent = identity.parent_agent

  emit(c, {
    event: 'aauth.whoami.agent_identity_returned',
    msg: 'agent_token verified; returning agent identity',
    agent_iss: identity.iss,
    agent_sub: identity.sub,
    agent_jkt: result.token.jkt,
    ps: identity.ps,
  })

  return c.json(body)
}

// ── Person token handler ──
//
// The person token is what makes the identity this resource records
// PS-asserted rather than agent-asserted. With no scopes requested it is
// enough on its own — whoami serves the identity it just verified. With
// scopes requested it becomes the basis of a resource token.

async function handlePersonToken(
  c: import('hono').Context<HonoEnv>,
  jwtRaw: string,
  payload: Record<string, unknown>,
  callerJkt: string,
) {
  const origin = c.env.ORIGIN
  const now = Math.floor(Date.now() / 1000)

  const result = await verifyPersonToken(jwtRaw, payload, {
    resource: origin,
    signingJkt: callerJkt,
    now,
  })
  if (!result.ok) {
    emitVerifyFailed(c, result.reason, { iss: payload.iss, detail: result.error })
    return c.json({ error: result.error }, result.status)
  }
  const person = result.token
  const { identity } = person

  const scopeParam = c.req.query('scope') || ''
  const requestedScopes = scopeParam.trim().split(/\s+/).filter(Boolean)

  // No scopes requested — identity access. The person token already carries
  // the person's identity at this resource, so no resource token is needed.
  if (requestedScopes.length === 0) {
    const body: Record<string, unknown> = { iss: identity.iss, sub: identity.sub }
    // tenant is organizational context, not part of the identifier.
    if (person.tenant) body.tenant = person.tenant
    emit(c, {
      event: 'aauth.whoami.person_identity_returned',
      msg: 'person_token verified; no scopes requested, returning identity',
      person_iss: identity.iss,
      person_sub: identity.sub,
      identity_key: identityRecordKey(identity),
      person_token_jti: person.jti,
      mission_s256: person.mission_s256,
      agent_jkt: person.jkt,
    })
    return c.json(body)
  }

  // Build scope: always "whoami" + requested identity scopes from ?scope=
  const unknown = requestedScopes.filter((s) => !PS_IDENTITY_SCOPES.has(s))
  if (unknown.length > 0) {
    return c.json({ error: 'invalid_scope', unknown }, 400)
  }
  const scopeString = ['whoami', ...requestedScopes].join(' ')

  // Mint resource token. `aud` is the PS that issued the person token — the
  // same issuer whose namespace `sub` belongs to.
  const privateKey = await importSigningKey(c.env.SIGNING_KEY)
  const publicJwk = await getPublicJWK(c.env.SIGNING_KEY)

  // A resource token derived from a person token must not outlive it.
  //
  // This is the most a resource can do about mission expiry, and it is not
  // the mission clamp. -11 says a token carrying `mission_s256` MUST NOT
  // expire after the mission's `expires_at` — but a resource only ever sees
  // `mission_s256`, a hash, and has no endpoint that turns it back into an
  // expiry. The real clamp lives at the PS, which holds the approved mission
  // and re-checks it when it resolves `person_token_jti`. Do not "fix" this
  // by trying to read an expiry the resource cannot have.
  const exp = Math.min(now + RESOURCE_TOKEN_LIFETIME, person.exp)

  const rtHeader = { alg: SIGNING_ALG, typ: TOKEN_TYP.resource, kid: publicJwk.kid }
  const rtPayload: Record<string, unknown> = {
    iss: origin,
    dwk: DWK.resource,
    aud: identity.iss,
    jti: generateJTI(),
    // ps, sub and person_token_jti are copied from the person token this
    // resource verified. There is no agent claim in -11 — agent_jkt binds the
    // token to the agent's key, and the PS learns the agent's identity from
    // the agent token that signs the token request.
    ps: identity.iss,
    sub: identity.sub,
    person_token_jti: person.jti,
    agent_jkt: person.jkt,
    scope: scopeString,
    iat: now,
    exp,
  }
  // REQUIRED when the person token carried one — a resource MUST NOT omit it.
  if (person.mission_s256) rtPayload.mission_s256 = person.mission_s256
  if (person.tenant) rtPayload.tenant = person.tenant

  const resourceToken = await signJWT(rtHeader, rtPayload, privateKey)

  emit(c, {
    event: 'aauth.whoami.resource_token_minted',
    msg: 'resource_token minted from verified person_token',
    person_iss: identity.iss,
    person_sub: identity.sub,
    identity_key: identityRecordKey(identity),
    person_token_jti: person.jti,
    mission_s256: person.mission_s256,
    agent_jkt: person.jkt,
    caller_jkt: callerJkt,
    granted_scope: scopeString,
    requested_scope: requestedScopes.join(' '),
    ps_issuer: identity.iss,
  })

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
