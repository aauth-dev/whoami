#!/usr/bin/env node

// Generate an Ed25519 key pair for resource token signing.
// Run: node scripts/generate-key.mjs
// Then set as a Cloudflare secret: wrangler secret put SIGNING_KEY

import { webcrypto } from 'node:crypto'

const keyPair = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])
const privateJwk = await webcrypto.subtle.exportKey('jwk', keyPair.privateKey)

// WebCrypto exportKey does not set alg; signature-key -08 (RFC 9864) requires
// every JWK to carry a fully-specified alg. EdDSA is rejected — use Ed25519.
privateJwk.alg = 'Ed25519'

console.log('Private JWK (set as SIGNING_KEY secret):')
console.log(JSON.stringify(privateJwk))
