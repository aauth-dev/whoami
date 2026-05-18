import type { Context } from 'hono'
import type { Env } from './types'

type HonoEnv = { Bindings: Env }

const SERVICE = 'whoami' as const

export type EmitInput = {
  event: string
  level?: number
  msg?: string
  [k: string]: unknown
}

// Enqueue a structured event to the aauth-events queue without
// blocking the response. Errors are logged and swallowed — event
// emission must never break the request path.
export function emit(c: Context<HonoEnv>, input: EmitInput): void {
  const full = {
    service: SERVICE,
    timestamp: new Date().toISOString(),
    event_id: crypto.randomUUID(),
    level: 30,
    ...input,
  }
  c.executionCtx.waitUntil(
    c.env.EVENTS_QUEUE.send(full).catch((err: unknown) =>
      console.error('event_emit_failed', {
        error: String(err),
        event: input.event,
      })
    )
  )
}

// Convenience wrapper for the verify_failed event, which is emitted
// from multiple sites.
export function emitVerifyFailed(
  c: Context<HonoEnv>,
  reason: string,
  extra: Record<string, unknown> = {},
): void {
  emit(c, {
    event: 'aauth.whoami.verify_failed',
    level: 40,
    msg: `verify failed: ${reason}`,
    route: new URL(c.req.url).pathname,
    failure_reason: reason,
    ...extra,
  })
}
