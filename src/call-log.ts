// The AAuth call log (@aauth/call-log): one `aauth.call` record per call this
// resource answers. Its agents are browsers, which do not log, so the record
// written here is the only one of each call; it makes no calls to other AAuth
// roles itself (issuer key discovery is not one). Records go where every
// event goes, by the queue to Freezer, and the monitor shows them.
import type { Context } from 'hono'
import { callLogMiddleware, tokenize, type CallLogHost, type ContextLike } from '@aauth/call-log'
import { emit } from './events'
import type { Env } from './types'

type HonoEnv = { Bindings: Env }

const executionCtx = (c: Context<HonoEnv>): { waitUntil(p: Promise<unknown>): void } | undefined => {
  try {
    return c.executionCtx
  } catch {
    return undefined
  }
}

/** The host for a call this resource answers: records carry the request context. */
export const calleeHost = (c: Context<HonoEnv>): CallLogHost => {
  const ctx = executionCtx(c)
  return {
    origin: c.env.ORIGIN,
    role: 'resource',
    // tokenize once more over the whole record: a resource token inside a parsed
    // AAuth-Requirement (the auth-token challenge) is a string 0.1.0 leaves as is.
    log: (record) => emit(c, { ...(tokenize(record) as Record<string, unknown>), event: record.event }),
    defer: ctx ? (p) => ctx.waitUntil(p) : undefined,
  }
}

// Not calls between AAuth roles: the package skips metadata, JWKS, health and
// OpenAPI by itself. `/` is the resource here, so it is not skipped.
export const callLog = async (c: Context<HonoEnv>, next: () => Promise<void>) => {
  // A view of the context: Hono's `executionCtx` getter throws where there is
  // none, and the package reads it as a plain property.
  const view: ContextLike = {
    req: c.req,
    get res() {
      return c.res
    },
    executionCtx: executionCtx(c),
  }
  return callLogMiddleware(calleeHost(c))(view, next)
}
