// AAuth -11 protocol constants and shared verification helpers.
//
// These mirror the surface `@aauth/protocol` 1.0.0 exports (TOKEN_TYP, DWK,
// SIGNING_ALG). They are declared locally because this Worker has no @aauth/*
// dependency yet; when `@aauth/resource` 2.0.0 lands, TOKEN_TYP/DWK/SIGNING_ALG
// and the verification helpers below are what it should replace.

import { computeJwkThumbprint, verifyJWT } from './crypto'

export const TOKEN_TYP = {
  agent: 'aa-agent+jwt',
  person: 'aa-person+jwt',
  resource: 'aa-resource+jwt',
  auth: 'aa-auth+jwt',
} as const

export const DWK = {
  agent: 'aauth-agent.json',
  person: 'aauth-person.json',
  resource: 'aauth-resource.json',
  access: 'aauth-access.json',
} as const

// RFC 9864 fully-specified identifier. Emitted and accepted; the polymorphic
// `EdDSA` is neither.
export const SIGNING_ALG = 'Ed25519' as const

// Algorithms this resource refuses to see anywhere a signature is verified or
// a confirmation key is read. `EdDSA` names a family rather than an
// operation; `none` is unsigned; HS* are symmetric, and a shared secret
// cannot prove possession to a verifier that holds it.
const FORBIDDEN_ALGS = new Set([
  'none',
  'EdDSA',
  'HS256',
  'HS384',
  'HS512',
])

export function isForbiddenAlg(alg: unknown): boolean {
  return typeof alg === 'string' && FORBIDDEN_ALGS.has(alg)
}

// ── Server identifiers (protocol §Server Identifiers) ──
//
// https scheme, host only, no port/path/query/fragment, no trailing slash,
// lowercase. Compared with exact string comparison — never normalized, because
// normalizing is how two different identifiers become one.

export function isServerIdentifier(value: unknown): value is string {
  if (typeof value !== 'string' || value === '') return false
  if (value !== value.toLowerCase()) return false
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return false
  }
  if (url.protocol !== 'https:') return false
  if (url.port !== '') return false
  if (url.pathname !== '/' || value.endsWith('/')) return false
  if (url.search !== '' || url.hash !== '') return false
  if (url.username !== '' || url.password !== '') return false
  return value === `https://${url.hostname}`
}

// ── Agent identifiers (protocol §Agent Identifiers) ──
//
// `aauth:local@domain`. The local part is lowercase ASCII letters, digits,
// hyphen, underscore, plus and period, non-empty and at most 255 characters;
// `+` is the sub-agent delimiter. The domain conforms to the server
// identifier requirements without the scheme. Compared with exact,
// case-sensitive string comparison — an agent identifier is global, unlike a
// directed `sub`, but it is no less opaque: the local part MUST NOT be parsed
// for protocol decisions.

const AGENT_LOCAL = /^[a-z0-9\-_+.]{1,255}$/

export function isAgentIdentifier(value: unknown): value is string {
  if (typeof value !== 'string' || !value.startsWith('aauth:')) return false
  const rest = value.slice('aauth:'.length)
  const at = rest.lastIndexOf('@')
  if (at <= 0 || at === rest.length - 1) return false
  const local = rest.slice(0, at)
  const domain = rest.slice(at + 1)
  if (!AGENT_LOCAL.test(local)) return false
  return isServerIdentifier(`https://${domain}`)
}

// ── Directed identifiers (protocol §Directed Identifiers) ──
//
// `sub` is unique within its issuer, not globally. A resource MUST treat
// (iss, sub) as the identifier, MUST treat the value as opaque, and MUST NOT
// match a `sub` received from one issuer against a record established under
// another, however the values compare.

export interface PersonIdentity {
  /** Issuer whose namespace `sub` belongs to. Never dropped. */
  iss: string
  /** Directed subject identifier. Opaque — never parsed, never normalized. */
  sub: string
}

/**
 * The key a resource records a person under. The issuer is length-prefixed so
 * that no two distinct (iss, sub) pairs can produce the same key by moving the
 * boundary between them, and the issuer can never be dropped from the key by
 * accident: there is no code path that produces a key from `sub` alone.
 */
export function identityRecordKey(identity: PersonIdentity): string {
  return `${identity.iss.length}:${identity.iss}|${identity.sub}`
}

export function sameIdentity(a: PersonIdentity, b: PersonIdentity): boolean {
  return a.iss === b.iss && a.sub === b.sub
}

// ── Confirmation keys ──

export interface JwkCheckResult {
  ok: boolean
  error?: string
}

/**
 * Structural checks on a `cnf.jwk`, per auth token verification step 6: reject
 * a JWK missing `kty` or the members required for its key type before any
 * attempt to decode it. `alg` is REQUIRED and must be fully specified —
 * `EdDSA` names a family, not an operation, and a confirmation key that can be
 * read two ways is rejected rather than resolved in favour of either reading.
 */
export function checkConfirmationJwk(jwk: unknown): JwkCheckResult {
  if (!jwk || typeof jwk !== 'object') return { ok: false, error: 'cnf.jwk is not an object' }
  const k = jwk as Record<string, unknown>
  if (typeof k.kty !== 'string') return { ok: false, error: 'cnf.jwk missing kty' }
  if (typeof k.alg !== 'string' || k.alg === '') {
    return { ok: false, error: 'cnf.jwk missing a fully-specified alg' }
  }
  if (isForbiddenAlg(k.alg)) return { ok: false, error: `cnf.jwk alg not allowed: ${k.alg}` }

  const required: Record<string, string[]> = {
    OKP: ['crv', 'x'],
    EC: ['crv', 'x', 'y'],
    RSA: ['n', 'e'],
  }
  const members = required[k.kty]
  if (!members) return { ok: false, error: `cnf.jwk unsupported kty: ${k.kty}` }
  for (const m of members) {
    if (typeof k[m] !== 'string' || k[m] === '') {
      return { ok: false, error: `cnf.jwk missing ${m}` }
    }
  }
  if (k.d !== undefined) return { ok: false, error: 'cnf.jwk carries private key material' }
  return { ok: true }
}

/**
 * Verify that a token's `cnf.jwk` is the key that signed the HTTP request.
 * `signingJkt` is the thumbprint of the key HTTP Message Signature
 * verification actually used.
 */
export async function verifyConfirmationKey(
  cnf: unknown,
  signingJkt: string,
): Promise<{ ok: true; jkt: string } | { ok: false; error: string }> {
  const jwk = (cnf as { jwk?: unknown } | undefined)?.jwk
  if (jwk === undefined) return { ok: false, error: 'cnf.jwk is required' }
  const structural = checkConfirmationJwk(jwk)
  if (!structural.ok) return { ok: false, error: structural.error as string }

  let jkt: string
  try {
    jkt = await computeJwkThumbprint(jwk as JsonWebKey)
  } catch (err) {
    return { ok: false, error: `cnf.jwk is not usable key material: ${(err as Error).message}` }
  }
  if (jkt !== signingJkt) {
    return { ok: false, error: 'cnf.jwk does not match the key that signed the request' }
  }
  return { ok: true, jkt }
}

// ── Issuer key discovery ──

export type JwksLookup =
  | { ok: true; jwks: { keys: JsonWebKey[] }; metadata: Record<string, unknown> }
  | { ok: false; status: 401 | 502; error: string }

/**
 * Discover an issuer's JWKS via `{iss}/.well-known/{dwk}` per
 * I-D.hardt-httpbis-signature-key, and confirm the metadata's `issuer` matches
 * the `iss` that named it.
 */
export async function fetchIssuerJwks(iss: string, dwk: string): Promise<JwksLookup> {
  if (!isServerIdentifier(iss)) {
    return { ok: false, status: 401, error: `iss is not a valid server identifier: ${iss}` }
  }
  try {
    const metaRes = await fetch(`${iss}/.well-known/${dwk}`)
    if (!metaRes.ok) {
      return { ok: false, status: 502, error: `Failed to fetch issuer metadata: ${metaRes.status}` }
    }
    const metadata = (await metaRes.json()) as Record<string, unknown>
    if (typeof metadata.issuer === 'string' && metadata.issuer !== iss) {
      return { ok: false, status: 401, error: 'issuer metadata does not match iss' }
    }
    const jwksUri = metadata.jwks_uri
    if (typeof jwksUri !== 'string' || jwksUri === '') {
      return { ok: false, status: 502, error: 'Issuer metadata missing jwks_uri' }
    }
    const jwksRes = await fetch(jwksUri)
    if (!jwksRes.ok) {
      return { ok: false, status: 502, error: `Failed to fetch issuer JWKS: ${jwksRes.status}` }
    }
    const jwks = (await jwksRes.json()) as { keys: JsonWebKey[] }
    return { ok: true, jwks, metadata }
  } catch (err) {
    return { ok: false, status: 502, error: `Cannot reach issuer: ${(err as Error).message}` }
  }
}

// ── Agent token verification (protocol §Agent Token Verification) ──

export interface AgentIdentity {
  /** Agent provider that issued the token. */
  iss: string
  /** Agent identifier, `aauth:local@domain`. Stable across key rotations. */
  sub: string
  /** The agent's person server, when the token names one. */
  ps?: string
  /** Parent agent identifier — present only on a sub-agent's token. */
  parent_agent?: string
}

export interface VerifiedAgentToken {
  identity: AgentIdentity
  jkt: string
  exp: number
}

export type AgentTokenResult =
  | { ok: true; token: VerifiedAgentToken }
  | { ok: false; status: 401 | 502; reason: string; error: string }

/**
 * Verify an agent token for agent identity access — the mode where the
 * resource decides on who the agent is, with no PS involved.
 *
 * The agent token is the one token a resource reads that still carries an
 * agent identifier. -11 removed `agent` from person, resource and auth
 * tokens; `sub` here is unaffected.
 */
export async function verifyAgentToken(
  jwtRaw: string,
  payload: Record<string, unknown>,
  opts: { signingJkt: string; now: number },
): Promise<AgentTokenResult> {
  const { signingJkt, now } = opts

  // 2. dwk MUST be aauth-agent.json.
  if (payload.dwk !== DWK.agent) {
    return {
      ok: false,
      status: 401,
      reason: 'agent_token_bad_dwk',
      error: `agent_token dwk must be ${DWK.agent}`,
    }
  }

  // 4. iss is the agent provider URL and must be a server identifier.
  const iss = payload.iss
  if (!isServerIdentifier(iss)) {
    return {
      ok: false,
      status: 401,
      reason: 'agent_token_bad_iss',
      error: 'agent_token iss is not a valid server identifier',
    }
  }

  const sub = payload.sub
  if (!isAgentIdentifier(sub)) {
    return {
      ok: false,
      status: 401,
      reason: 'agent_token_bad_sub',
      error: 'agent_token sub is not a valid agent identifier',
    }
  }

  // 3. exp in the future, iat not in the future.
  const exp = payload.exp
  if (typeof exp !== 'number' || exp < now) {
    return { ok: false, status: 401, reason: 'agent_token_expired', error: 'agent_token expired' }
  }
  if (typeof payload.iat === 'number' && payload.iat > now + 60) {
    return {
      ok: false,
      status: 401,
      reason: 'agent_token_iat_future',
      error: 'agent_token iat is in the future',
    }
  }

  // 5. cnf.jwk must be the key that signed the request.
  const cnfResult = await verifyConfirmationKey(payload.cnf, signingJkt)
  if (!cnfResult.ok) {
    return { ok: false, status: 401, reason: 'agent_token_cnf_mismatch', error: cnfResult.error }
  }

  // 6. ps, when present, is a server identifier.
  const ps = payload.ps
  if (ps !== undefined && !isServerIdentifier(ps)) {
    return {
      ok: false,
      status: 401,
      reason: 'agent_token_bad_ps',
      error: 'agent_token ps is not a valid server identifier',
    }
  }

  // 7. parent_agent, when present, is an agent identifier. Its presence marks
  //    a sub-agent; the single-level rule is the PS's to enforce.
  const parentAgent = payload.parent_agent
  if (parentAgent !== undefined && !isAgentIdentifier(parentAgent)) {
    return {
      ok: false,
      status: 401,
      reason: 'agent_token_bad_parent_agent',
      error: 'agent_token parent_agent is not a valid agent identifier',
    }
  }

  // 2. Discover the agent provider's JWKS and verify the JWT signature.
  const lookup = await fetchIssuerJwks(iss, DWK.agent)
  if (!lookup.ok) {
    return {
      ok: false,
      status: lookup.status,
      reason: 'agent_token_key_discovery_failed',
      error: lookup.error,
    }
  }
  try {
    await verifyJWT(jwtRaw, lookup.jwks)
  } catch (err) {
    return {
      ok: false,
      status: 401,
      reason: 'agent_token_jwt_verify_failed',
      error: `agent_token verification failed: ${(err as Error).message}`,
    }
  }

  const identity: AgentIdentity = { iss, sub }
  if (typeof ps === 'string') identity.ps = ps
  if (typeof parentAgent === 'string') identity.parent_agent = parentAgent
  return { ok: true, token: { identity, jkt: cnfResult.jkt, exp } }
}

// ── Person token verification (protocol §Person Token Verification) ──

export interface VerifiedPersonToken {
  /** (iss, sub) — the identity. Never split. */
  identity: PersonIdentity
  jti: string
  jkt: string
  exp: number
  mission_s256?: string
  tenant?: string
}

export type PersonTokenResult =
  | { ok: true; token: VerifiedPersonToken }
  | { ok: false; status: 401 | 502; reason: string; error: string }

/**
 * Verify a person token. Steps follow §Person Token Verification:
 * typ (checked by the caller when routing), dwk + JWKS signature, exp/iat,
 * iss, aud, cnf.jwk against the request-signing key.
 */
export async function verifyPersonToken(
  jwtRaw: string,
  payload: Record<string, unknown>,
  opts: { resource: string; signingJkt: string; now: number },
): Promise<PersonTokenResult> {
  const { resource, signingJkt, now } = opts

  // 2. dwk MUST be aauth-person.json — a person token is only ever a PS token.
  if (payload.dwk !== DWK.person) {
    return {
      ok: false,
      status: 401,
      reason: 'person_token_bad_dwk',
      error: `person_token dwk must be ${DWK.person}`,
    }
  }

  // 4. iss must be a valid server identifier (checked inside fetchIssuerJwks
  //    before any request is made, so a malformed iss is never fetched).
  const iss = payload.iss
  if (typeof iss !== 'string') {
    return { ok: false, status: 401, reason: 'person_token_missing_iss', error: 'person_token missing iss' }
  }

  // 5. aud must be this resource's own identifier, by exact comparison.
  if (payload.aud !== resource) {
    return {
      ok: false,
      status: 401,
      reason: 'person_token_aud_mismatch',
      error: 'person_token aud mismatch',
    }
  }

  const sub = payload.sub
  if (typeof sub !== 'string' || sub === '') {
    return { ok: false, status: 401, reason: 'person_token_missing_sub', error: 'person_token missing sub' }
  }

  const jti = payload.jti
  if (typeof jti !== 'string' || jti === '') {
    return { ok: false, status: 401, reason: 'person_token_missing_jti', error: 'person_token missing jti' }
  }

  // 3. exp in the future, iat not in the future.
  const exp = payload.exp
  if (typeof exp !== 'number' || exp < now) {
    return { ok: false, status: 401, reason: 'person_token_expired', error: 'person_token expired' }
  }
  if (typeof payload.iat === 'number' && payload.iat > now + 60) {
    return { ok: false, status: 401, reason: 'person_token_iat_future', error: 'person_token iat is in the future' }
  }

  // 6. cnf.jwk is REQUIRED and must be the key that signed the request.
  const cnfResult = await verifyConfirmationKey(payload.cnf, signingJkt)
  if (!cnfResult.ok) {
    return { ok: false, status: 401, reason: 'person_token_cnf_mismatch', error: cnfResult.error }
  }

  // A person token MUST NOT carry scope or account.
  if (payload.scope !== undefined || payload.account !== undefined) {
    return {
      ok: false,
      status: 401,
      reason: 'person_token_carries_authorization',
      error: 'person_token MUST NOT carry scope or account',
    }
  }

  // 2. Discover the PS's JWKS and verify the JWT signature.
  const lookup = await fetchIssuerJwks(iss, DWK.person)
  if (!lookup.ok) {
    return { ok: false, status: lookup.status, reason: 'person_token_key_discovery_failed', error: lookup.error }
  }
  try {
    await verifyJWT(jwtRaw, lookup.jwks)
  } catch (err) {
    return {
      ok: false,
      status: 401,
      reason: 'person_token_jwt_verify_failed',
      error: `person_token verification failed: ${(err as Error).message}`,
    }
  }

  const token: VerifiedPersonToken = {
    identity: { iss, sub },
    jti,
    jkt: cnfResult.jkt,
    exp,
  }
  if (typeof payload.mission_s256 === 'string') token.mission_s256 = payload.mission_s256
  if (typeof payload.tenant === 'string') token.tenant = payload.tenant
  return { ok: true, token }
}
