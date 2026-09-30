import { Bell, BellOff, Timer } from 'lucide-react'
import { get, post, type NotifySettings } from '@/lib/api'
import { useData } from '@/lib/hooks'
import { Button } from '@/components/ui/button'
import { NativeSelect } from '@/components/ui/input'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/misc'
import { useToast } from '@/components/ui/toast'

const waitLabel = (s: number) => (s < 60 ? `${s} seconds` : s === 60 ? '1 minute' : `${s / 60} minutes`)

/** How long agents wait for an answer, and quiet mode for notifications. */
export function NotifyControls() {
  const toast = useToast()
  const d = useData(() => get<NotifySettings>('/api/notify'), [])
  const n = d.data
  if (!n) return null
  const quietUntil = n.quiet_until ? new Date(n.quiet_until) : null
  const quiet = n.quiet || !!quietUntil
  const setQuiet = async (body: { quiet: boolean; minutes?: number }) => {
    try {
      d.setData(await post<NotifySettings>('/api/notify', body))
    } catch (e: any) {
      toast({ kind: 'error', title: 'Could not change notifications', body: e.message })
    }
  }
  const setWait = async (secs: number) => {
    try {
      await post('/api/network/wait', { secs })
      d.setData({ ...n, wait_secs: secs })
      toast({ kind: 'success', title: `Agents now wait up to ${waitLabel(secs)} for your answer`, body: 'Some tools give up sooner on their own; the request then shows as refused.' })
    } catch (e: any) {
      toast({ kind: 'error', title: 'Could not change the wait', body: e.message })
    }
  }
  return (
    <div className="flex flex-wrap items-center gap-2">
      <label className="flex items-center gap-2 text-sm text-muted-foreground" title="How long an agent waits on a new site while you decide (Network → Ask me)">
        <Timer className="size-4" /> Wait
        <NativeSelect value={n.wait_secs} onChange={(e) => setWait(Number(e.target.value))}>
          {n.wait_choices.map((s) => (
            <option key={s} value={s}>
              {waitLabel(s)}
            </option>
          ))}
        </NativeSelect>
      </label>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm">
            {quiet ? <BellOff /> : <Bell />}
            {n.quiet ? 'Quiet' : quietUntil ? `Quiet until ${quietUntil.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'Notifications on'}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <div className="max-w-64 px-2 py-1.5 text-xs text-muted-foreground">At most one notification a minute. Requests always appear here.</div>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setQuiet({ quiet: true, minutes: 60 })}>Quiet for 1 hour</DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setQuiet({ quiet: true })}>Quiet until I turn them back on</DropdownMenuItem>
          {quiet && <DropdownMenuItem onSelect={() => setQuiet({ quiet: false })}>Turn notifications back on</DropdownMenuItem>}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}
