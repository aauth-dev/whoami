import { describe, expect, it } from 'vitest'
import {
  DWK,
  SIGNING_ALG,
  TOKEN_TYP,
  checkConfirmationJwk,
  identityRecordKey,
  isAgentIdentifier,
  isForbiddenAlg,
  isServerIdentifier,
  sameIdentity,
} from '../src/aauth'

describe('constants', () => {
  it('names the -11 token types and metadata documents', () => {
    expect(TOKEN_TYP).toEqual({
      agent: 'aa-agent+jwt',
      person: 'aa-person+jwt',
      resource: 'aa-resource+jwt',
      auth: 'aa-auth+jwt',
    })
    expect(DWK.person).toBe('aauth-person.json')
    expect(DWK.resource).toBe('aauth-resource.json')
    expect(DWK.access).toBe('aauth-access.json')
    expect(SIGNING_ALG).toBe('Ed25519')
  })

  it('forbids polymorphic, symmetric and unsigned algorithms', () => {
    expect(isForbiddenAlg('EdDSA')).toBe(true)
    expect(isForbiddenAlg('none')).toBe(true)
    expect(isForbiddenAlg('HS256')).toBe(true)
    expect(isForbiddenAlg('Ed25519')).toBe(false)
  })
})

describe('isServerIdentifier', () => {
  it.each([
    'https://agent.example',
    'https://xn--nxasmq6b.example',
    'https://a.b.c.example',
  ])('accepts %s', (v) => {
    expect(isServerIdentifier(v)).toBe(true)
  })

  it.each([
    ['http://agent.example', 'not https'],
    ['https://Agent.Example', 'not lowercase'],
    ['https://agent.example:8443', 'has a port'],
    ['https://agent.example/v1', 'has a path'],
    ['https://agent.example/', 'trailing slash'],
    ['https://agent.example?a=b', 'has a query'],
    ['https://agent.example#f', 'has a fragment'],
    ['https://user@agent.example', 'has userinfo'],
    ['agent.example', 'not a URL'],
    ['', 'empty'],
  ])('rejects %s (%s)', (v) => {
    expect(isServerIdentifier(v)).toBe(false)
  })
})

describe('isAgentIdentifier', () => {
  it.each([
    'aauth:assistant-v2@agent.example',
    'aauth:planner.7f3c@vendor.example',
    'aauth:planner.7f3c+search1@vendor.example',
    'aauth:a_b+c.d-e@xn--nxasmq6b.example',
  ])('accepts %s', (v) => {
    expect(isAgentIdentifier(v)).toBe(true)
  })

  it.each([
    ['My Agent@agent.example', 'no scheme, uppercase and space'],
    ['aauth:My.Agent@agent.example', 'uppercase in local part'],
    ['aauth:@agent.example', 'empty local part'],
    ['aauth:agent@http://agent.example', 'domain includes scheme'],
    ['aauth:agent@agent.example:8443', 'domain has a port'],
    ['aauth:agent@', 'empty domain'],
    ['https://agent.example/agents/1', 'a URL, not an agent identifier'],
  ])('rejects %s (%s)', (v) => {
    expect(isAgentIdentifier(v)).toBe(false)
  })

  it('rejects a local part over 255 characters', () => {
    expect(isAgentIdentifier(`aauth:${'a'.repeat(256)}@agent.example`)).toBe(false)
    expect(isAgentIdentifier(`aauth:${'a'.repeat(255)}@agent.example`)).toBe(true)
  })
})

describe('directed identifiers', () => {
  const sub = '8f14e45fceea167a5a36dedd4bea2543'

  it('keys a person on (iss, sub)', () => {
    expect(sameIdentity({ iss: 'https://ps.example', sub }, { iss: 'https://ps.example', sub })).toBe(
      true,
    )
  })

  it('never matches the same sub under a different issuer', () => {
    const a = { iss: 'https://ps.example', sub }
    const b = { iss: 'https://other.example', sub }
    expect(sameIdentity(a, b)).toBe(false)
    expect(identityRecordKey(a)).not.toBe(identityRecordKey(b))
  })

  it('cannot be made to collide by moving the iss/sub boundary', () => {
    // Without the length prefix, ("https://a.example", "x|y") and
    // ("https://a.example|x", "y") would produce the same key.
    const a = identityRecordKey({ iss: 'https://a.example', sub: 'x|y' })
    const b = identityRecordKey({ iss: 'https://a.example|x', sub: 'y' })
    expect(a).not.toBe(b)
  })

  it('treats the sub as opaque', () => {
    // Values that differ only by case, whitespace or encoding are different
    // identifiers — nothing normalizes them.
    const base = { iss: 'https://ps.example', sub: 'Alice' }
    expect(identityRecordKey(base)).not.toBe(
      identityRecordKey({ iss: 'https://ps.example', sub: 'alice' }),
    )
    expect(identityRecordKey(base)).not.toBe(
      identityRecordKey({ iss: 'https://ps.example', sub: 'Alice ' }),
    )
  })
})

describe('checkConfirmationJwk', () => {
  const okp = { kty: 'OKP', crv: 'Ed25519', x: 'abc', alg: 'Ed25519' }

  it('accepts a fully-specified OKP key', () => {
    expect(checkConfirmationJwk(okp).ok).toBe(true)
  })

  it('rejects a missing alg', () => {
    const { alg: _alg, ...noAlg } = okp
    expect(checkConfirmationJwk(noAlg).ok).toBe(false)
  })

  it('rejects a polymorphic alg', () => {
    expect(checkConfirmationJwk({ ...okp, alg: 'EdDSA' }).ok).toBe(false)
  })

  it('rejects a symmetric key', () => {
    expect(checkConfirmationJwk({ kty: 'oct', k: 'secret', alg: 'HS256' }).ok).toBe(false)
  })

  it('rejects a structurally incomplete key before decoding it', () => {
    expect(checkConfirmationJwk({ kty: 'OKP', alg: 'Ed25519' }).ok).toBe(false)
    expect(checkConfirmationJwk({ kty: 'EC', crv: 'P-256', x: 'a', alg: 'ES256' }).ok).toBe(false)
    expect(checkConfirmationJwk({ kty: 'RSA', n: 'a', alg: 'RS256' }).ok).toBe(false)
  })

  it('rejects a key carrying private material', () => {
    expect(checkConfirmationJwk({ ...okp, d: 'secret' }).ok).toBe(false)
  })
})
