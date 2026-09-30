import * as React from 'react'
import { post, type Session } from '@/lib/api'
import { useToast } from '@/components/ui/toast'

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
      await post('/api/sessions/restart', { session: s.session })
      toast({ kind: 'success', title: `Restarting ${s.agent_name ?? s.agent}`, body: 'It relaunches under the current rules and resumes the last conversation. If the rules are invalid it keeps running and Activity shows why.' })
      setTimeout(() => onDone?.(), 2500)
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
