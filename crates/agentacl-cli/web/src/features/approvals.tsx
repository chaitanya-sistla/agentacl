import * as React from 'react'
import { Globe, Plus, ShieldQuestion } from 'lucide-react'
import { post, type AnswerKind, type Approval } from '@/lib/api'
import { useApp } from '@/lib/app-context'
import { baseName } from '@/lib/format'
import { Button } from '@/components/ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/misc'
import { useToast } from '@/components/ui/toast'
import { CategoryBadge } from '@/components/app/charts'
import { cn } from '@/lib/utils'

/** Time left to answer, as a bar and seconds. */
function Countdown({ created, expires }: { created: string; expires: string }) {
  const [now, setNow] = React.useState(Date.now())
  React.useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 250)
    return () => clearInterval(t)
  }, [])
  const total = Math.max(1, Date.parse(expires) - Date.parse(created))
  const left = Math.max(0, Date.parse(expires) - now)
  const pct = Math.min(100, (left / total) * 100)
  const secs = Math.ceil(left / 1000)
  return (
    <div className="flex items-center gap-2">
      <div className="h-1 flex-1 overflow-hidden rounded-full bg-muted">
        <div className={cn('h-full rounded-full transition-[width] duration-200 ease-linear', secs <= 10 ? 'bg-amber-500' : 'bg-brand')} style={{ width: `${pct}%` }} />
      </div>
      <span className="w-12 text-right text-xs tabular-nums text-muted-foreground">{secs >= 60 ? `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}` : `${secs}s`}</span>
    </div>
  )
}

/** Answers and extensions, with toasts. */
function useApprovalActions() {
  const { refreshInbox } = useApp()
  const toast = useToast()
  const [busy, setBusy] = React.useState<string | null>(null)
  const answer = async (a: Approval, ans: AnswerKind, agentOnly = false) => {
    setBusy(a.id)
    try {
      const r = await post<{ note?: string }>('/api/approvals/answer', { id: a.id, answer: ans, agent_only: agentOnly })
      const blocked = ans === 'block' || ans === 'block-always'
      const how = {
        once: 'this once',
        session: 'for this session',
        always: agentOnly ? `always, for ${a.agent_name} only` : 'always (saved to your rules)',
        block: 'this time',
        'block-always': 'always (saved to your rules)',
      }[ans]
      toast({
        kind: blocked ? 'info' : 'success',
        title: `${blocked ? 'Blocked' : 'Allowed'} ${a.host} ${how}`,
        // The name was never looked up before you answered; private and local
        // addresses are still refused after it resolves.
        body: r.note ?? (blocked ? undefined : 'Private and local network addresses stay blocked.'),
      })
    } catch (e: any) {
      toast({ kind: 'error', title: 'Could not answer', body: e.message })
    } finally {
      setBusy(null)
      refreshInbox()
    }
  }
  const extend = async (a: Approval) => {
    setBusy(a.id)
    try {
      await post('/api/approvals/extend', { id: a.id })
    } catch (e: any) {
      toast({ kind: 'error', title: 'Could not add time', body: e.message })
    } finally {
      setBusy(null)
      refreshInbox()
    }
  }
  return { answer, extend, busy }
}

function ApprovalCard({ a, actions, floating }: { a: Approval; actions: ReturnType<typeof useApprovalActions>; floating?: boolean }) {
  const { answer, extend, busy } = actions
  return (
    <div
      role="alertdialog"
      aria-label={`${a.agent_name} wants to reach ${a.host}`}
      className={cn('overflow-hidden rounded-xl border border-brand/40 bg-popover', floating ? 'shadow-2xl ring-1 ring-brand/20' : 'shadow-sm')}
    >
      <div className="flex gap-3 p-4">
        <div className="grid size-9 shrink-0 place-items-center rounded-lg bg-brand/10 text-brand">
          <ShieldQuestion className="size-4.5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-sm">
            <b>{a.agent_name}</b> is waiting to reach
          </div>
          <div className="mt-0.5 flex items-center gap-2">
            <Globe className="size-3.5 shrink-0 text-muted-foreground" />
            <span className="truncate font-mono text-[13px] font-medium">{a.display}</span>
            <span className="text-xs text-muted-foreground">:{a.port}</span>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <CategoryBadge id={a.category.id} label={a.category.label} />
            <span className="truncate">in {baseName(a.project)}</span>
          </div>
          <p className="mt-1.5 text-xs text-muted-foreground">{a.category.advice}</p>
        </div>
      </div>
      <div className="flex items-center gap-2 px-4">
        <div className="flex-1">
          <Countdown created={a.created} expires={a.expires} />
        </div>
        <Button size="sm" variant="ghost" className="h-7 px-2 text-xs" disabled={busy === a.id} onClick={() => extend(a)} title="Wait one more minute (some tools give up sooner on their own)">
          <Plus /> 1 min
        </Button>
      </div>
      <div className="flex items-center gap-2 p-3">
        <Button size="sm" variant="brand" disabled={busy === a.id} onClick={() => answer(a, 'session')}>
          Allow for session
        </Button>
        <Button size="sm" variant="outline" disabled={busy === a.id} onClick={() => answer(a, 'block')}>
          Block
        </Button>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button size="sm" variant="ghost" disabled={busy === a.id} className="ml-auto">
              More
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="z-[100]">
            <DropdownMenuItem onSelect={() => answer(a, 'once')}>Allow the connection waiting now</DropdownMenuItem>
            <DropdownMenuItem onSelect={() => answer(a, 'always', true)}>Always allow, for {a.agent_name} only</DropdownMenuItem>
            <DropdownMenuItem onSelect={() => answer(a, 'always')}>Always allow, for every agent (save to rules)</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem destructive onSelect={() => answer(a, 'block-always')}>
              Always block this site (save to rules)
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  )
}

/** Every waiting request, inline (the Requests page). */
export function WaitingList() {
  const { inbox } = useApp()
  const actions = useApprovalActions()
  const list = inbox?.approvals ?? []
  if (list.length === 0) return null
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {list.map((a) => (
        <ApprovalCard key={a.id} a={a} actions={actions} />
      ))}
    </div>
  )
}

/**
 * Live network approvals: an agent is waiting on a connection to a site no
 * rule names (Network → "Ask me"). Floating on every page except Requests,
 * which lists them inline.
 */
export function ApprovalsDock({ hidden }: { hidden?: boolean }) {
  const { inbox } = useApp()
  const actions = useApprovalActions()
  const list = inbox?.approvals ?? []
  if (hidden || list.length === 0) return null
  return (
    <div className="fixed right-4 bottom-4 z-[95] flex w-[380px] max-w-[calc(100vw-2rem)] flex-col gap-2">
      {list.slice(-3).map((a) => (
        <ApprovalCard key={a.id} a={a} actions={actions} floating />
      ))}
      {list.length > 3 && <div className="rounded-lg bg-popover px-3 py-2 text-center text-xs text-muted-foreground shadow">{list.length - 3} more waiting</div>}
    </div>
  )
}
