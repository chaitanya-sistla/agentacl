import * as React from 'react'
import { Globe, ShieldQuestion } from 'lucide-react'
import { post, type AnswerKind, type Approval } from '@/lib/api'
import { useApp } from '@/lib/app-context'
import { baseName } from '@/lib/format'
import { Button } from '@/components/ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/misc'
import { useToast } from '@/components/ui/toast'
import { CategoryBadge } from '@/components/app/charts'

function Countdown({ expires }: { expires: string }) {
  const [now, setNow] = React.useState(Date.now())
  React.useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 250)
    return () => clearInterval(t)
  }, [])
  const left = Math.max(0, Date.parse(expires) - now)
  const pct = Math.min(100, (left / 25000) * 100)
  return (
    <div className="h-1 w-full overflow-hidden rounded-full bg-muted">
      <div className="h-full rounded-full bg-brand transition-[width] duration-200 ease-linear" style={{ width: `${pct}%` }} />
    </div>
  )
}

/**
 * Live network approvals: an agent is waiting on a connection to a site no
 * rule names (Network → "Ask me"). Shown on every page, newest last.
 */
export function ApprovalsDock() {
  const { inbox, refreshInbox } = useApp()
  const toast = useToast()
  const [busy, setBusy] = React.useState<string | null>(null)
  const list = inbox?.approvals ?? []
  if (list.length === 0) return null

  const answer = async (a: Approval, ans: AnswerKind) => {
    setBusy(a.id)
    try {
      const r = await post<{ note?: string }>('/api/approvals/answer', { id: a.id, answer: ans })
      const blocked = ans === 'block' || ans === 'block-always'
      const how = { once: 'this once', session: 'for this session', always: 'always (saved to your rules)', block: 'this time', 'block-always': 'always (saved to your rules)' }[ans]
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

  return (
    <div className="fixed right-4 bottom-4 z-[95] flex w-[380px] max-w-[calc(100vw-2rem)] flex-col gap-2">
      {list.slice(-3).map((a) => (
        <div key={a.id} role="alertdialog" aria-label={`${a.agent_name} wants to reach ${a.host}`} className="overflow-hidden rounded-xl border border-brand/40 bg-popover shadow-2xl ring-1 ring-brand/20">
          <div className="flex gap-3 p-4">
            <div className="grid size-9 shrink-0 place-items-center rounded-lg bg-brand/10 text-brand">
              <ShieldQuestion className="size-4.5" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-sm">
                <b>{a.agent_name}</b> wants to reach
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
          <div className="px-4">
            <Countdown expires={a.expires} />
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
                <DropdownMenuItem onSelect={() => answer(a, 'always')}>Always allow this site, any port (save to rules)</DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem destructive onSelect={() => answer(a, 'block-always')}>
                  Always block this site (save to rules)
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      ))}
      {list.length > 3 && <div className="rounded-lg bg-popover px-3 py-2 text-center text-xs text-muted-foreground shadow">{list.length - 3} more waiting</div>}
    </div>
  )
}
