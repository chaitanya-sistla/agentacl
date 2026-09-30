import * as React from 'react'
import { get, post, type Session } from '@/lib/api'
import { useToast } from '@/components/ui/toast'
import { Badge } from '@/components/ui/badge'

// ---- restart tracking: the console asks the server how a restart went ----

export type RestartState = { state: 'restarting' | 'restarted' | 'refused' | 'exited' | 'slow'; session?: string; detail?: string }

const tracked = new Map<string, RestartState>()
const listeners = new Set<() => void>()
const emit = () => listeners.forEach((f) => f())
const subscribe = (f: () => void) => {
  listeners.add(f)
  return () => listeners.delete(f)
}

/** Polls /api/sessions/restart-status until the restart settles. */
function track(session: string, since: string, onSettled?: () => void) {
  tracked.set(session, { state: 'restarting' })
  emit()
  const started = Date.now()
  const tick = async () => {
    let r: RestartState = { state: 'restarting' }
    try {
      r = await get<RestartState>('/api/sessions/restart-status', { session, since })
    } catch {
      // keep polling: the console may be busy
    }
    const waited = Date.now() - started
    if (r.state === 'restarting' && waited > 30_000) r = { state: 'slow' }
    tracked.set(session, r)
    emit()
    if (r.state === 'restarting' || (r.state === 'slow' && waited < 180_000)) setTimeout(tick, 1000)
    else onSettled?.()
  }
  setTimeout(tick, 800)
}

export function useRestartState(session: string | undefined): RestartState | undefined {
  return React.useSyncExternalStore(subscribe, () => (session ? tracked.get(session) : undefined))
}

/** The outcome of a restart, for a session row. Nothing if it wasn't restarted here. */
export function RestartBadge({ session }: { session: string }) {
  const r = useRestartState(session)
  if (!r) return null
  switch (r.state) {
    case 'restarting':
      return <Badge variant="secondary">Restarting…</Badge>
    case 'restarted':
      return <Badge variant="success">Restarted</Badge>
    case 'refused':
      return (
        <Badge variant="danger" title={r.detail}>
          Restart refused: rules invalid
        </Badge>
      )
    case 'exited':
      return <Badge variant="secondary">The agent exited</Badge>
    case 'slow':
      return (
        <Badge variant="warning" title="The agent hasn't come back yet. Activity shows what happened.">
          Taking longer than expected
        </Badge>
      )
  }
}

/** Restart / stop a supervised session with toasts. */
export function useSessionActions(onDone?: () => void) {
  const toast = useToast()
  const [busy, setBusy] = React.useState<string | null>(null)
  const restart = async (s: Pick<Session, 'session' | 'agent_name' | 'agent' | 'restartable'>) => {
    if (!s.restartable) {
      toast({ kind: 'error', title: 'This agent can’t be restarted from here', body: 'It was started by an older AgentACL. Quit it and run it again with agentacl run.' })
      return false
    }
    setBusy(s.session)
    try {
      const r = await post<{ requested_at: string }>('/api/sessions/restart', { session: s.session })
      toast({ kind: 'success', title: `Restarting ${s.agent_name ?? s.agent}`, body: 'It relaunches under the current rules and resumes the last conversation. If the rules are invalid it keeps running and says why.' })
      track(s.session, r.requested_at, () => onDone?.())
      return true
    } catch (e: any) {
      toast({ kind: 'error', title: 'Restart failed', body: e.message })
      return false
    } finally {
      setBusy(null)
    }
  }
  const stop = async (s: Pick<Session, 'session' | 'agent_name' | 'agent'>) => {
    setBusy(s.session)
    try {
      await post('/api/sessions/stop', { session: s.session })
      toast({ kind: 'success', title: `Stopping ${s.agent_name ?? s.agent}` })
      setTimeout(() => onDone?.(), 1500)
    } catch (e: any) {
      toast({ kind: 'error', title: 'Stop failed', body: e.message })
    } finally {
      setBusy(null)
    }
  }
  return { restart, stop, busy }
}
