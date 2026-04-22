export interface Env {
  ORIGIN: string
  SIGNING_KEY: string // Ed25519 private key (JWK JSON), set as a secret
}
