export interface Env {
  ORIGIN: string
  SIGNING_KEY: string // Ed25519 private key (JWK JSON), set as a secret
  EVENTS_QUEUE: Queue // bound to aauth-events queue; consumed by aauth-shipper
}
