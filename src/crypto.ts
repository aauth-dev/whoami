// Ed25519 JWT signing & verification — shared with other AAuth servers

const textEncoder = new TextEncoder()

function base64urlEncode(data: Uint8Array): string {
  let binary = ''
  for (const byte of data) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4)
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

export async function importSigningKey(jwkJson: string): Promise<CryptoKey> {
  const jwk = JSON.parse(jwkJson)
  return crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign'])
}

export async function getPublicJWK(jwkJson: string): Promise<JsonWebKey & { kid: string }> {
  const jwk = JSON.parse(jwkJson)
  const { d: _d, key_ops: _ops, ext: _ext, ...rest } = jwk
  const publicJwk = { ...rest, key_ops: ['verify'] }
  const kid = await computeJwkThumbprint(publicJwk)
  return { ...publicJwk, kid }
}

export { calculateThumbprint as computeJwkThumbprint } from '@hellocoop/httpsig'

export async function signJWT(
  header: Record<string, string>,
  payload: Record<string, unknown>,
  privateKey: CryptoKey
): Promise<string> {
  const headerB64 = base64urlEncode(textEncoder.encode(JSON.stringify(header)))
  const payloadB64 = base64urlEncode(textEncoder.encode(JSON.stringify(payload)))
  const signingInput = `${headerB64}.${payloadB64}`
  const signature = await crypto.subtle.sign('Ed25519', privateKey, textEncoder.encode(signingInput))
  return `${signingInput}.${base64urlEncode(new Uint8Array(signature))}`
}

export function generateJTI(): string {
  return base64urlEncode(crypto.getRandomValues(new Uint8Array(16)))
}

export function decodeJWTPayload(jwt: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64urlDecode(jwt.split('.')[1])))
}

// JWT alg → WebCrypto parameters
const JWT_ALG_PARAMS: Record<string, { importAlgo: any; verifyAlgo: any }> = {
  EdDSA: { importAlgo: { name: 'Ed25519' }, verifyAlgo: 'Ed25519' },
  RS256: {
    importAlgo: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    verifyAlgo: 'RSASSA-PKCS1-v1_5',
  },
  ES256: {
    importAlgo: { name: 'ECDSA', namedCurve: 'P-256' },
    verifyAlgo: { name: 'ECDSA', hash: 'SHA-256' },
  },
}

export async function verifyJWT(
  jwt: string,
  jwks: { keys: JsonWebKey[] }
): Promise<{ header: Record<string, unknown>; payload: Record<string, unknown> }> {
  const parts = jwt.split('.')
  if (parts.length !== 3) throw new Error('invalid JWT format')
  const [headerB64, payloadB64, signatureB64] = parts

  const header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerB64)))
  const algParams = JWT_ALG_PARAMS[header.alg]
  if (!algParams) throw new Error(`unsupported alg: ${header.alg}`)

  const candidates = jwks.keys.filter((k) =>
    header.kid ? (k as { kid?: string }).kid === header.kid : true
  )
  if (candidates.length === 0) throw new Error('no matching key in JWKS')

  const signingInput = textEncoder.encode(`${headerB64}.${payloadB64}`)
  const signature = base64urlDecode(signatureB64)

  for (const jwk of candidates) {
    try {
      const key = await crypto.subtle.importKey(
        'jwk',
        { ...jwk, key_ops: ['verify'] },
        algParams.importAlgo,
        false,
        ['verify']
      )
      const ok = await crypto.subtle.verify(
        algParams.verifyAlgo,
        key,
        signature as unknown as ArrayBuffer,
        signingInput as unknown as ArrayBuffer
      )
      if (ok) {
        const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadB64)))
        return { header, payload }
      }
    } catch {
      // try next key
    }
  }
  throw new Error('signature verification failed')
}

export { base64urlEncode, base64urlDecode }
