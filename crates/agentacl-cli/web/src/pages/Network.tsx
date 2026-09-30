import * as React from 'react'
import { Ban, Check, Globe, MoreHorizontal, Search, ShieldQuestion, ShieldX, Trash2, Waypoints } from 'lucide-react'
import { get, post, type NetMode, type NetworkResp, type Site } from '@/lib/api'
import { useData, useInterval } from '@/lib/hooks'
import { useApp } from '@/lib/app-context'
import { baseName, timeAgo } from '@/lib/format'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input, NativeSelect } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger, Tooltip } from '@/components/ui/misc'
import { useToast } from '@/components/ui/toast'
import { Empty, ErrorText, Loading, Mono, PageHeader, Pagination, Stat } from '@/components/app/common'
import { CategoryBadge } from '@/components/app/charts'
import { SiteRuleDialog, type SiteRuleIntent } from '@/features/site-rule'
import { cn } from '@/lib/utils'

type Filter = 'all' | 'blocked' | 'allowed' | 'ruled'

/** The site's current status, from its effective decision (not its history). */
function status(s: Site, mode: NetMode): { label: string; variant: 'success' | 'danger' | 'warning' | 'outline' | 'info'; why: string } {
  const e = s.effective
  if (e.effect === 'allow') {
    if (e.by === 'you') return { label: 'Allowed by you', variant: 'success', why: 'Your rules allow this site.' }
    if (e.by === 'agent') return { label: 'Needed by the agent', variant: 'success', why: 'The agent needs this site to run.' }
    return { label: 'Allowed', variant: 'success', why: e.reason }
  }
  if (e.by === 'you') return { label: 'Blocked by you', variant: 'danger', why: 'You blocked this site.' }
  if (e.by === 'console') return { label: 'Allowed by you', variant: 'success', why: 'Allowed in the console.' }
  if (e.by === 'default') return mode === 'ask' ? { label: 'Asks you', variant: 'info', why: 'No rule names it; agents wait for your answer.' } : { label: 'Not allowed', variant: 'warning', why: 'No rule allows it.' }
  return { label: e.by === 'builtin' ? 'Blocked (built-in)' : 'Blocked by a rule', variant: 'danger', why: e.reason }
}

export default function NetworkPage() {
  const toast = useToast()
  const { refreshInbox } = useApp()
  const [days, setDays] = React.useState(7)
  const d = useData(() => get<NetworkResp>('/api/network', { days }), [days])
  useInterval(() => d.reload(), 10000)
  const [q, setQ] = React.useState('')
  const [filter, setFilter] = React.useState<Filter>('all')
  const [cat, setCat] = React.useState('')
  const [page, setPage] = React.useState(1)
  const [size, setSize] = React.useState(25)
  const [intent, setIntent] = React.useState<SiteRuleIntent | null>(null)
  const [savingMode, setSavingMode] = React.useState(false)

  const sites = d.data?.sites ?? []
  const filtered = sites
    .filter((s) => !q || s.host.includes(q.toLowerCase()))
    .filter((s) => !cat || s.category.id === cat)
    .filter((s) => (filter === 'blocked' ? s.blocked > 0 : filter === 'allowed' ? s.allowed > 0 : filter === 'ruled' ? !!(s.policy_rule || s.console_rule) : true))
    .sort((a, b) => b.blocked + b.allowed - (a.blocked + a.allowed) || (b.last_seen ?? '').localeCompare(a.last_seen ?? ''))
  const pages = Math.max(1, Math.ceil(filtered.length / size))
  const rows = filtered.slice((page - 1) * size, page * size)
  const totals = sites.reduce((t, s) => ({ allowed: t.allowed + s.allowed, blocked: t.blocked + s.blocked, blockedSites: t.blockedSites + (s.blocked > 0 ? 1 : 0) }), { allowed: 0, blocked: 0, blockedSites: 0 })
  const cats = Array.from(new Map(sites.map((s) => [s.category.id, s.category.label])).entries())

  const setMode = async (mode: NetMode) => {
    setSavingMode(true)
    try {
      await post('/api/network/mode', { mode })
      toast({ kind: 'success', title: mode === 'ask' ? 'Agents will ask before reaching new sites' : 'New sites are blocked', body: 'Applies right away to every running agent.' })
      d.reload()
      refreshInbox()
    } catch (e: any) {
      toast({ kind: 'error', title: 'Could not change the setting', body: e.message })
    } finally {
      setSavingMode(false)
    }
  }
  const mode = d.data?.mode ?? 'block'

  return (
    <>
      <PageHeader
        title="Network"
        description="Every site your agents reached or tried to reach. All agent traffic goes through AgentACL, so a block here takes effect immediately, even for agents already running."
        actions={
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            Activity from the last
            <NativeSelect value={days} onChange={(e) => { setDays(Number(e.target.value)); setPage(1) }}>
              <option value={1}>24 hours</option>
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
            </NativeSelect>
          </label>
        }
      />

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>When an agent reaches a site no rule names</CardTitle>
          <CardDescription>Applies immediately to all running agents. Sites you allowed or blocked, and what each agent needs to run, are not affected.</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {(
            [
              ['block', ShieldX, 'Block it', 'The connection is refused and shows up in Requests, where you can allow it later.'],
              ['ask', ShieldQuestion, 'Ask me', 'The agent waits up to 25 seconds while you allow or block it here, with a desktop notification. No answer means blocked.'],
            ] as const
          ).map(([m, Icon, label, help]) => (
            <button
              key={m}
              disabled={savingMode}
              onClick={() => m !== mode && setMode(m)}
              className={cn('flex gap-3 rounded-xl border p-4 text-left transition-colors', mode === m ? 'border-brand bg-brand/[0.06] ring-1 ring-brand' : 'hover:bg-accent/40')}
            >
              <Icon className={cn('mt-0.5 size-5 shrink-0', mode === m ? 'text-brand' : 'text-muted-foreground')} />
              <div>
                <div className="flex items-center gap-2 font-medium">
                  {label} {mode === m && <Badge variant="info">Current</Badge>}
                </div>
                <div className="mt-0.5 text-sm text-muted-foreground">{help}</div>
              </div>
            </button>
          ))}
        </CardContent>
      </Card>

      <div className="mb-6 grid grid-cols-2 gap-4 xl:grid-cols-4">
        <Stat label="Sites seen" value={sites.filter((s) => s.last_seen).length} hint={`last ${days === 1 ? '24 hours' : `${days} days`}`} icon={Globe} tone="brand" />
        <Stat label="Connections allowed" value={totals.allowed.toLocaleString()} icon={Check} tone="success" />
        <Stat label="Connections blocked" value={totals.blocked.toLocaleString()} icon={Ban} tone="danger" onClick={() => setFilter('blocked')} />
        <Stat label="Sites blocked" value={totals.blockedSites} hint="at least one connection refused" icon={ShieldX} tone="warning" onClick={() => setFilter('blocked')} />
      </div>

      <Card>
        <div className="flex flex-wrap items-center gap-3 border-b p-3">
          <div className="relative min-w-56 flex-1">
            <Search className="absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
            <Input className="pl-8" placeholder="Filter sites…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1) }} />
          </div>
          <NativeSelect value={filter} onChange={(e) => { setFilter(e.target.value as Filter); setPage(1) }} aria-label="Show">
            <option value="all">All sites</option>
            <option value="blocked">Blocked at least once</option>
            <option value="allowed">Allowed at least once</option>
            <option value="ruled">Has a rule you set</option>
          </NativeSelect>
          <NativeSelect value={cat} onChange={(e) => { setCat(e.target.value); setPage(1) }} aria-label="Category">
            <option value="">All kinds</option>
            {cats.map(([id, label]) => (
              <option key={id} value={id}>
                {label}
              </option>
            ))}
          </NativeSelect>
        </div>
        <ErrorText error={d.error} />
        {d.loading && !d.data ? (
          <Loading />
        ) : filtered.length === 0 ? (
          <div className="p-6">
            <Empty icon={Globe} title="No sites here">
              Sites appear as soon as an agent started with <code className="font-mono">agentacl run</code> connects anywhere.
            </Empty>
          </div>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Site</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-56">Connections</TableHead>
                  <TableHead>Used by</TableHead>
                  <TableHead>Last seen</TableHead>
                  <TableHead className="w-12" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((s) => {
                  const st = status(s, mode)
                  const total = Math.max(1, s.allowed + s.blocked)
                  const ruled = s.policy_rule || s.console_rule
                  return (
                    <TableRow key={s.host}>
                      <TableCell className="max-w-80">
                        <Mono className="block truncate font-medium">{s.display}</Mono>
                        <div className="mt-1 flex items-center gap-1.5">
                          <CategoryBadge id={s.category.id} label={s.category.label} />
                          {s.ports.filter((p) => p && p !== '443').length > 0 && <span className="text-[11px] text-muted-foreground">ports {s.ports.join(', ')}</span>}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Tooltip content={st.why}>
                          <span>
                            <Badge variant={st.variant}>{st.label}</Badge>
                          </span>
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted">
                          <div className="bg-emerald-500" style={{ width: `${(s.allowed / total) * 100}%` }} />
                          <div className="bg-red-500" style={{ width: `${(s.blocked / total) * 100}%` }} />
                        </div>
                        <div className="mt-1 flex justify-between text-[11px] text-muted-foreground tabular-nums">
                          <span className="text-emerald-600 dark:text-emerald-400">{s.allowed.toLocaleString()} allowed</span>
                          <span className="text-red-600 dark:text-red-400">{s.blocked.toLocaleString()} blocked</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-sm">
                        <div>{s.agents.join(', ') || '—'}</div>
                        {s.projects.length > 0 && <div className="truncate text-xs text-muted-foreground">{s.projects.map(baseName).join(', ')}</div>}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">{s.last_seen ? timeAgo(s.last_seen) : '—'}</TableCell>
                      <TableCell>
                        {s.manageable && (
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" className="size-8">
                                <MoreHorizontal />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent>
                              <DropdownMenuItem onSelect={() => setIntent({ host: s.host, effect: 'allow', category: s.category, wasBlockedByYou: s.effective.by === 'you' && s.effective.effect !== 'allow' })} disabled={s.policy_rule === 'allow' || !s.effective.allowable}>
                                <Check /> {s.effective.allowable ? 'Allow site' : 'Can’t allow: ' + (s.effective.by === 'builtin' ? 'built-in block' : 'a rule blocks it')}
                              </DropdownMenuItem>
                              <DropdownMenuItem onSelect={() => setIntent({ host: s.host, effect: 'block', category: s.category })} disabled={s.policy_rule === 'block'}>
                                <Ban /> Block site
                              </DropdownMenuItem>
                              {ruled && (
                                <>
                                  <DropdownMenuSeparator />
                                  <DropdownMenuItem onSelect={() => setIntent({ host: s.host, effect: 'none', category: s.category })}>
                                    <Trash2 /> Remove my rule
                                  </DropdownMenuItem>
                                </>
                              )}
                            </DropdownMenuContent>
                          </DropdownMenu>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
            <Pagination page={page} pages={pages} total={filtered.length} size={size} onPage={setPage} onSize={(n) => { setSize(n); setPage(1) }} />
          </>
        )}
      </Card>

      {(d.data?.patterns.length ?? 0) > 0 && (
        <Card className="mt-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-[15px]">
              <Waypoints className="size-4" /> Pattern rules
            </CardTitle>
            <CardDescription>Wildcard rules from your policy file. Edit them in Policies → Rules.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {d.data!.patterns.map((p) => (
              <Badge key={p.pattern + p.effect} variant={p.effect === 'allow' ? 'success' : 'danger'}>
                {p.effect === 'allow' ? 'Allow' : 'Block'} <span className="font-mono">{p.pattern}</span>
              </Badge>
            ))}
          </CardContent>
        </Card>
      )}

      <SiteRuleDialog intent={intent} onClose={() => setIntent(null)} onDone={() => d.reload()} />
    </>
  )
}
