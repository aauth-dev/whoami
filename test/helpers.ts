// Test fixtures: Ed25519 keys, AAuth token minting, and signed requests.

import { fetch as httpSigFetch, calculateThumbprint } from '@hellocoop/httpsig'
import app from '../src/index'
import type { Env } from '../src/types'

export const RESOURCE = 'https://whoami.aauth.dev'
export const PS = 'https://ps.example'
export const OTHER_PS = 'https://other-ps.example'
export const AS = 'https://as.example'
export const AGENT_PROVIDER = 'https://agent.example'
export const AGENT_SUB = 'aauth:assistant-v2@agent.example'

export interface KeyPair {
  privateJwk: JsonWebKey & { alg: string }
  publicJwk: JsonWebKey & { alg: string; kid: string }
  privateKey: CryptoKey
}

export async function makeKeyPair(): Promise<KeyPair> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  const rawPrivate = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey
  const rawPublic = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey
  // RFC 9864 fully-specified identifier — never the polymorphic "EdDSA".
  const privateJwk = { ...rawPrivate, alg: 'Ed25519' }
  const { d: _d, key_ops: _ops, ext: _ext, ...pub } = rawPublic as unknown as Record<string, unknown>
  const publicBase = { ...pub, alg: 'Ed25519' } as JsonWebKey & { alg: string }
  const kid = await calculateThumbprint(publicBase)
  return {
    privateJwk: privateJwk as JsonWebKey & { alg: string },
    publicJwk: { ...publicBase, kid },
    privateKey: pair.privateKey,
  }
}

const enc = new TextEncoder()

function b64url(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function mintJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  key: CryptoKey,
): Promise<string> {
  const h = b64url(enc.encode(JSON.stringify(header)))
  const p = b64url(enc.encode(JSON.stringify(payload)))
  const sig = await crypto.subtle.sign('Ed25519', key, enc.encode(`${h}.${p}`))
  return `${h}.${p}.${b64url(new Uint8Array(sig))}`
}

export function decodeJwt(jwt: string): {
  header: Record<string, unknown>
  payload: Record<string, unknown>
} {
  const parts = jwt.split('.')
  const dec = (s: string) => {
    const padded = s + '='.repeat((4 - (s.length % 4)) % 4)
    const bin = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    return JSON.parse(new TextDecoder().decode(bytes))
  }
  return { header: dec(parts[0]), payload: dec(parts[1]) }
}

export const now = () => Math.floor(Date.now() / 1000)

// ── Token builders ──

export interface TokenOverrides {
  header?: Record<string, unknown>
  payload?: Record<string, unknown>
  drop?: string[]
}

function applyOverrides(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  o: TokenOverrides = {},
) {
  const h = { ...header, ...(o.header ?? {}) }
  const p = { ...payload, ...(o.payload ?? {}) }
  for (const k of o.drop ?? []) delete p[k]
  return { h, p }
}

export async function personToken(
  psKey: KeyPair,
  agent: KeyPair,
  o: TokenOverrides = {},
): Promise<string> {
  const t = now()
  const { h, p } = applyOverrides(
    { alg: 'Ed25519', typ: 'aa-person+jwt', kid: psKey.publicJwk.kid },
    {
      iss: PS,
      dwk: 'aauth-person.json',
      aud: RESOURCE,
      sub: 'directed-sub-for-whoami',
      cnf: { jwk: agent.publicJwk },
      jti: 'pt-1',
      iat: t,
      exp: t + 3600,
    },
    o,
  )
  return mintJwt(h, p, psKey.privateKey)
}

export async function agentToken(
  agentServerKey: KeyPair,
  agent: KeyPair,
  o: TokenOverrides = {},
): Promise<string> {
  const t = now()
  const { h, p } = applyOverrides(
    { alg: 'Ed25519', typ: 'aa-agent+jwt', kid: agentServerKey.publicJwk.kid },
    {
      iss: AGENT_PROVIDER,
      dwk: 'aauth-agent.json',
      sub: 'aauth:assistant-v2@agent.example',
      ps: PS,
      cnf: { jwk: agent.publicJwk },
      jti: 'at-1',
      iat: t,
      exp: t + 3600,
    },
    o,
  )
  return mintJwt(h, p, agentServerKey.privateKey)
}

export async function authToken(
  psKey: KeyPair,
  agent: KeyPair,
  o: TokenOverrides = {},
): Promise<string> {
  const t = now()
  const { h, p } = applyOverrides(
    { alg: 'Ed25519', typ: 'aa-auth+jwt', kid: psKey.publicJwk.kid },
    {
      iss: PS,
      dwk: 'aauth-person.json',
      aud: RESOURCE,
      jti: 'auth-1',
      ps: PS,
      sub: 'directed-sub-for-whoami',
      cnf: { jwk: agent.publicJwk },
      scope: 'whoami email',
      email: 'alice@example.com',
      name: 'Alice Example',
      iat: t,
      exp: t + 3600,
    },
    o,
  )
  return mintJwt(h, p, psKey.privateKey)
}

// ── Worker invocation ──

export function makeEnv(signingKey: string): { env: Env; sent: unknown[] } {
  const sent: unknown[] = []
  const env = {
    ORIGIN: RESOURCE,
    SIGNING_KEY: signingKey,
    EVENTS_QUEUE: {
      send: async (msg: unknown) => {
        sent.push(msg)
      },
    },
  } as unknown as Env
  return { env, sent }
}

const waited: Promise<unknown>[] = []
export const execCtx = {
  waitUntil: (p: Promise<unknown>) => {
    waited.push(p)
  },
  passThroughOnException: () => {},
} as unknown as ExecutionContext

/** Build the RFC 9421 signature headers for a GET, without sending anything. */
export async function signHeaders(
  url: string,
  agent: KeyPair,
  jwt: string,
): Promise<Headers> {
  const { headers } = await httpSigFetch(url, {
    signingKey: agent.privateJwk,
    signatureKey: { type: 'jwt', jwt },
    dryRun: true,
  })
  return headers
}

export async function callWhoami(
  path: string,
  env: Env,
  agent?: KeyPair,
  jwt?: string,
): Promise<Response> {
  const url = `${RESOURCE}${path}`
  const headers = agent && jwt ? await signHeaders(url, agent, jwt) : new Headers()
  return app.request(url, { method: 'GET', headers }, env, execCtx)
}
