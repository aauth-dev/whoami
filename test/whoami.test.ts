import { beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import {
  AGENT_PROVIDER,
  AGENT_SUB,
  AS,
  OTHER_PS,
  PS,
  RESOURCE,
  agentToken,
  authToken,
  callWhoami,
  decodeJwt,
  makeEnv,
  makeKeyPair,
  now,
  personToken,
  type KeyPair,
} from './helpers'
import type { Env } from '../src/types'

// A mission the agent is operating under. The hash is all a resource ever
// sees — the AAuth-Mission header was removed in -11.
const MISSION_S256 = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

let resourceKey: KeyPair
let psKey: KeyPair
let otherPsKey: KeyPair
let asKey: KeyPair
let agentServerKey: KeyPair
let agent: KeyPair
let env: Env
let sent: unknown[]
let outbound: string[]

function jwksResponse(key: KeyPair) {
  return new Response(JSON.stringify({ keys: [key.publicJwk] }), {
    headers: { 'content-type': 'application/json' },
  })
}

function metadataResponse(issuer: string) {
  return new Response(
    JSON.stringify({ issuer, jwks_uri: `${issuer}/.well-known/jwks.json` }),
    { headers: { 'content-type': 'application/json' } },
  )
}

beforeAll(async () => {
  ;[resourceKey, psKey, otherPsKey, asKey, agentServerKey, agent] = await Promise.all([
    makeKeyPair(),
    makeKeyPair(),
    makeKeyPair(),
    makeKeyPair(),
    makeKeyPair(),
    makeKeyPair(),
  ])
})

beforeEach(() => {
  const made = makeEnv(JSON.stringify(resourceKey.privateJwk))
  env = made.env
  sent = made.sent
  outbound = []

  vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
    const url = String(input)
    outbound.push(url)
    if (url === `${PS}/.well-known/aauth-person.json`) return metadataResponse(PS)
    if (url === `${PS}/.well-known/jwks.json`) return jwksResponse(psKey)
    if (url === `${OTHER_PS}/.well-known/aauth-person.json`) return metadataResponse(OTHER_PS)
    if (url === `${OTHER_PS}/.well-known/jwks.json`) return jwksResponse(otherPsKey)
    if (url === `${AS}/.well-known/aauth-access.json`) return metadataResponse(AS)
    if (url === `${AS}/.well-known/jwks.json`) return jwksResponse(asKey)
    if (url === `${AGENT_PROVIDER}/.well-known/aauth-agent.json`) {
      return metadataResponse(AGENT_PROVIDER)
    }
    if (url === `${AGENT_PROVIDER}/.well-known/jwks.json`) return jwksResponse(agentServerKey)
    return new Response('not found', { status: 404 })
  })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('metadata', () => {
  it('declares the lowest access mode that gets an answer', async () => {
    const res = await callWhoami('/.well-known/aauth-resource.json', env)
    const body = (await res.json()) as Record<string, unknown>
    expect(res.status).toBe(200)
    expect(body.issuer).toBe(RESOURCE)
    expect(body.access_mode).toBe('agent-token')
  })

  it('publishes a public key with a fully-specified alg', async () => {
    const res = await callWhoami('/.well-known/jwks.json', env)
    const body = (await res.json()) as { keys: Record<string, unknown>[] }
    expect(body.keys[0].alg).toBe('Ed25519')
    expect(body.keys[0].d).toBeUndefined()
    expect(body.keys[0].kid).toBeTruthy()
  })
})

describe('no signature', () => {
  it('challenges with Accept-Signature', async () => {
    const res = await callWhoami('/', env)
    expect(res.status).toBe(401)
    expect(res.headers.get('accept-signature')).toBeTruthy()
    expect(res.headers.get('accept-signature-scheme')).toContain('jwt')
  })
})

describe('agent token — agent identity access', () => {
  it('returns the agent identity with no PS involved', async () => {
    const jwt = await agentToken(agentServerKey, agent)
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      iss: AGENT_PROVIDER,
      sub: AGENT_SUB,
      ps: PS,
    })
    expect(outbound).not.toContain(`${PS}/.well-known/aauth-person.json`)
  })

  it('omits ps when the agent token names none', async () => {
    const jwt = await agentToken(agentServerKey, agent, { drop: ['ps'] })
    const res = await callWhoami('/', env, agent, jwt)
    expect(await res.json()).toEqual({ iss: AGENT_PROVIDER, sub: AGENT_SUB })
  })

  it('surfaces parent_agent on a sub-agent token', async () => {
    const jwt = await agentToken(agentServerKey, agent, {
      payload: {
        sub: 'aauth:planner.7f3c+search1@agent.example',
        parent_agent: 'aauth:planner.7f3c@agent.example',
      },
    })
    const body = (await (await callWhoami('/', env, agent, jwt)).json()) as Record<string, unknown>
    expect(body.sub).toBe('aauth:planner.7f3c+search1@agent.example')
    expect(body.parent_agent).toBe('aauth:planner.7f3c@agent.example')
  })

  it('rejects a sub that is not an agent identifier', async () => {
    const jwt = await agentToken(agentServerKey, agent, {
      payload: { sub: 'https://agent.example/agents/1' },
    })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
    expect(outbound).toEqual([])
  })

  it('rejects a wrong dwk', async () => {
    const jwt = await agentToken(agentServerKey, agent, { payload: { dwk: 'aauth-person.json' } })
    expect((await callWhoami('/', env, agent, jwt)).status).toBe(401)
  })

  it('rejects a signature from a key the agent provider does not publish', async () => {
    const jwt = await agentToken(psKey, agent, { header: { kid: agentServerKey.publicJwk.kid } })
    expect((await callWhoami('/', env, agent, jwt)).status).toBe(401)
  })

  it('rejects an expired token', async () => {
    const t = now()
    const jwt = await agentToken(agentServerKey, agent, { payload: { iat: t - 7200, exp: t - 60 } })
    expect((await callWhoami('/', env, agent, jwt)).status).toBe(401)
  })
})

describe('agent token — asking about a person', () => {
  it('is challenged with requirement=person-token', async () => {
    const jwt = await agentToken(agentServerKey, agent)
    const res = await callWhoami('/?scope=email', env, agent, jwt)
    expect(res.status).toBe(401)
    expect(res.headers.get('aauth-requirement')).toBe('requirement=person-token')
    expect(await res.json()).toEqual({ error: 'person_token_required' })
  })

  it('gets no resource token', async () => {
    const jwt = await agentToken(agentServerKey, agent)
    const res = await callWhoami('/?scope=email', env, agent, jwt)
    expect(res.headers.get('aauth-requirement')).not.toContain('resource-token')
  })

  it('makes no outbound request — nothing in the agent token changes the answer', async () => {
    const jwt = await agentToken(agentServerKey, agent, {
      payload: { iss: 'https://attacker.example' },
    })
    await callWhoami('/?scope=email', env, agent, jwt)
    expect(outbound).toEqual([])
  })
})

describe('person token — identity access', () => {
  it('returns the directed identity as (iss, sub)', async () => {
    const jwt = await personToken(psKey, agent)
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      iss: PS,
      sub: 'directed-sub-for-whoami',
    })
  })

  it('releases tenant alongside, but not as part of, the identifier', async () => {
    const jwt = await personToken(psKey, agent, { payload: { tenant: 'acme' } })
    const res = await callWhoami('/', env, agent, jwt)
    const body = (await res.json()) as Record<string, unknown>
    expect(body).toEqual({ iss: PS, sub: 'directed-sub-for-whoami', tenant: 'acme' })
    const event = sent.find(
      (e) => (e as { event: string }).event === 'aauth.whoami.person_identity_returned',
    ) as Record<string, unknown>
    expect(event.identity_key).not.toContain('acme')
  })

  it('keys the identity record on the issuer as well as the sub', async () => {
    const same = 'directed-sub-for-whoami'
    await callWhoami('/', env, agent, await personToken(psKey, agent))
    const first = sent.find(
      (e) => (e as { event: string }).event === 'aauth.whoami.person_identity_returned',
    ) as Record<string, unknown>

    const made = makeEnv(JSON.stringify(resourceKey.privateJwk))
    const other = await personToken(otherPsKey, agent, {
      header: { kid: otherPsKey.publicJwk.kid },
      payload: { iss: OTHER_PS, sub: same },
    })
    await callWhoami('/', made.env, agent, other)
    const second = made.sent.find(
      (e) => (e as { event: string }).event === 'aauth.whoami.person_identity_returned',
    ) as Record<string, unknown>

    // Identical `sub` strings, different issuers: two records, never one.
    expect(first.person_sub).toBe(second.person_sub)
    expect(first.identity_key).not.toBe(second.identity_key)
  })

  it('rejects a token audienced at another resource', async () => {
    const jwt = await personToken(psKey, agent, {
      payload: { aud: 'https://elsewhere.example' },
    })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
    expect((await res.json()) as Record<string, unknown>).toMatchObject({
      error: 'person_token aud mismatch',
    })
  })

  it('rejects a wrong dwk', async () => {
    const jwt = await personToken(psKey, agent, { payload: { dwk: 'aauth-access.json' } })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
  })

  it('rejects an iss that is not a server identifier', async () => {
    const jwt = await personToken(psKey, agent, {
      payload: { iss: 'https://ps.example/tenant/1' },
    })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
    expect(outbound).toEqual([])
  })

  it('rejects a token carrying scope', async () => {
    const jwt = await personToken(psKey, agent, { payload: { scope: 'whoami email' } })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
    expect((await res.json()) as Record<string, unknown>).toMatchObject({
      error: 'person_token MUST NOT carry scope or account',
    })
  })

  it('rejects an expired token', async () => {
    const t = now()
    const jwt = await personToken(psKey, agent, {
      payload: { iat: t - 7200, exp: t - 60 },
    })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
  })

  it('rejects a signature from a key the PS does not publish', async () => {
    const jwt = await personToken(otherPsKey, agent, {
      header: { kid: psKey.publicJwk.kid },
    })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
  })

  it('rejects a polymorphic EdDSA header alg', async () => {
    const jwt = await personToken(psKey, agent, { header: { alg: 'EdDSA' } })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
  })
})

describe('person token — resource token', () => {
  async function mintResourceToken(overrides = {}) {
    const jwt = await personToken(psKey, agent, overrides)
    const res = await callWhoami('/?scope=email%20picture', env, agent, jwt)
    expect(res.status).toBe(401)
    const requirement = res.headers.get('aauth-requirement') as string
    expect(requirement).toContain('requirement=auth-token')
    const rt = /resource-token="([^"]+)"/.exec(requirement)?.[1] as string
    return decodeJwt(rt)
  }

  it('signs with the fully-specified Ed25519 identifier', async () => {
    const { header } = await mintResourceToken()
    expect(header.alg).toBe('Ed25519')
    expect(header.typ).toBe('aa-resource+jwt')
    expect(header.kid).toBeTruthy()
  })

  it('copies ps, sub and person_token_jti from the person token', async () => {
    const { payload } = await mintResourceToken()
    expect(payload.ps).toBe(PS)
    expect(payload.sub).toBe('directed-sub-for-whoami')
    expect(payload.person_token_jti).toBe('pt-1')
    expect(payload.aud).toBe(PS)
    expect(payload.iss).toBe(RESOURCE)
    expect(payload.dwk).toBe('aauth-resource.json')
    expect(payload.scope).toBe('whoami email picture')
  })

  it('carries no agent claim', async () => {
    const { payload } = await mintResourceToken()
    expect(payload.agent).toBeUndefined()
    expect(payload.approver).toBeUndefined()
    expect(payload.mission).toBeUndefined()
    expect(payload.agent_jkt).toBeTruthy()
  })

  it('binds agent_jkt to the request-signing key', async () => {
    const { payload } = await mintResourceToken()
    const { calculateThumbprint } = await import('@hellocoop/httpsig')
    expect(payload.agent_jkt).toBe(await calculateThumbprint(agent.publicJwk))
  })

  it('copies mission_s256 when the person token carried one', async () => {
    const { payload } = await mintResourceToken({
      payload: { mission_s256: MISSION_S256 },
    })
    expect(payload.mission_s256).toBe(MISSION_S256)
  })

  it('omits mission_s256 when the person token had none', async () => {
    const { payload } = await mintResourceToken()
    expect(payload.mission_s256).toBeUndefined()
  })

  it('copies tenant when the person token carried one', async () => {
    const { payload } = await mintResourceToken({ payload: { tenant: 'acme' } })
    expect(payload.tenant).toBe('acme')
  })

  it('does not outlive the person token it came from', async () => {
    const t = now()
    const { payload } = await mintResourceToken({ payload: { iat: t, exp: t + 30 } })
    expect(payload.exp).toBeLessThanOrEqual(t + 30)
  })

  it('lives no longer than 5 minutes', async () => {
    const { payload } = await mintResourceToken()
    expect((payload.exp as number) - (payload.iat as number)).toBeLessThanOrEqual(300)
  })

  it('rejects an unknown scope before minting', async () => {
    const jwt = await personToken(psKey, agent)
    const res = await callWhoami('/?scope=nonsense', env, agent, jwt)
    expect(res.status).toBe(400)
    expect((await res.json()) as Record<string, unknown>).toMatchObject({
      error: 'invalid_scope',
    })
  })
})

describe('auth token', () => {
  it('releases iss and sub together with the claims', async () => {
    const jwt = await authToken(psKey, agent)
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      iss: PS,
      sub: 'directed-sub-for-whoami',
      email: 'alice@example.com',
      name: 'Alice Example',
    })
  })

  it('strips ps and mission_s256 from the released claims', async () => {
    const jwt = await authToken(psKey, agent, {
      payload: { mission_s256: MISSION_S256 },
    })
    const res = await callWhoami('/', env, agent, jwt)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.ps).toBeUndefined()
    expect(body.mission_s256).toBeUndefined()
    expect(body.cnf).toBeUndefined()
  })

  it('accepts an AS-issued token discovered through aauth-access.json', async () => {
    const jwt = await authToken(asKey, agent, {
      header: { kid: asKey.publicJwk.kid },
      payload: { iss: AS, dwk: 'aauth-access.json', ps: PS },
    })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(200)
    expect(((await res.json()) as Record<string, unknown>).iss).toBe(AS)
  })

  it('rejects a dwk that names no AAuth issuer document', async () => {
    const jwt = await authToken(psKey, agent, { payload: { dwk: 'aauth-agent.json' } })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
    expect(outbound).toEqual([])
  })

  it('rejects a polymorphic EdDSA header alg', async () => {
    const jwt = await authToken(psKey, agent, { header: { alg: 'EdDSA' } })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
  })

  it('rejects an aud for another resource', async () => {
    const jwt = await authToken(psKey, agent, { payload: { aud: AS } })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
  })

  it('rejects a token with no sub', async () => {
    const jwt = await authToken(psKey, agent, { drop: ['sub'] })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
  })

  it('refuses without the whoami scope', async () => {
    const jwt = await authToken(psKey, agent, { payload: { scope: 'email' } })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(403)
  })

  it('rejects a person token presented where an auth token is required', async () => {
    // Only typ distinguishes the two: an aa-person+jwt with auth-token claims
    // must never take the auth-token path.
    const jwt = await personToken(psKey, agent, {
      payload: { scope: 'whoami', email: 'alice@example.com' },
    })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(401)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.email).toBeUndefined()
  })
})

describe('unknown token type', () => {
  it('is rejected', async () => {
    const jwt = await personToken(psKey, agent, { header: { typ: 'aa-resource+jwt' } })
    const res = await callWhoami('/', env, agent, jwt)
    expect(res.status).toBe(400)
  })
})
