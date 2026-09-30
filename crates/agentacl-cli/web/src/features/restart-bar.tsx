import * as React from 'react'
import { RotateCw } from 'lucide-react'
import { get, type Session } from '@/lib/api'
import { useData, useInterval } from '@/lib/hooks'
import { baseName } from '@/lib/format'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { RestartBadge, useSessionActions } from '@/features/session-actions'

/**
 * Running agents whose rules changed since they started (for example after
 * allowing a request): restart them to apply, and see how each restart went.
 * `refresh` changes whenever the caller saved something.
 */
export function RestartBar({ refresh }: { refresh: number }) {
  const d = useData(() => get<{ sessions: Session[] }>('/api/sessions'), [refresh])
  useInterval(d.reload, 5000)
  const actions = useSessionActions(d.reload)
  // Keep a row visible while its restart is tracked, even once it's up to date.
  const [mine, setMine] = React.useState<Session[]>([])
  const stale = (d.data?.sessions ?? []).filter((s) => s.stale === true)
  const rows = [...stale, ...mine.filter((m) => !stale.some((s) => s.session === m.session))]
  if (rows.length === 0) return null
  const restart = async (s: Session) => {
    if (await actions.restart(s)) setMine((x) => [...x.filter((y) => y.session !== s.session), s])
  }
  return (
    <Card className="mb-4 border-amber-500/30 bg-amber-500/[0.04] p-4">
      <div className="mb-2 text-sm">
        <span className="font-medium">
          {stale.length > 0 ? `${stale.length} running agent${stale.length > 1 ? 's use' : ' uses'} older rules` : 'Restarts'}
        </span>
        <span className="text-muted-foreground"> · macOS fixes an agent’s sandbox when it starts. A restart applies your changes, and the conversation resumes.</span>
      </div>
      <ul className="flex flex-col divide-y rounded-md border bg-background">
        {rows.map((s) => (
          <li key={s.session} className="flex items-center gap-3 px-3 py-2 text-sm">
            <div className="min-w-0 flex-1">
              <span className="font-medium">{s.agent_name ?? s.agent}</span>
              <span className="text-muted-foreground"> in {baseName(s.project)} · pid {s.pid}</span>
            </div>
            <RestartBadge session={s.session} />
            {stale.some((x) => x.session === s.session) &&
              (s.restartable ? (
                <Button size="sm" variant="outline" disabled={actions.busy === s.session} onClick={() => restart(s)}>
                  <RotateCw /> Restart now
                </Button>
              ) : (
                <span className="text-xs text-muted-foreground">Quit and run it again</span>
              ))}
          </li>
        ))}
      </ul>
    </Card>
  )
}
