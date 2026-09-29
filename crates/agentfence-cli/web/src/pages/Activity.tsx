import * as React from 'react'
import * as D from '@radix-ui/react-dialog'
import { Download, RefreshCw, Search, ScrollText } from 'lucide-react'
import { get, type AuditEvent, type EventsResp, type Project } from '@/lib/api'
import { useData, useInterval } from '@/lib/hooks'
import { useApp } from '@/lib/app-context'
import { actionLabel, explainRule, fmtTime, policyLabel, timeAgo, tildify } from '@/lib/format'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input, NativeSelect } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { SheetContent } from '@/components/ui/dialog'
import { EffectBadge, Empty, ErrorText, Loading, Mono, PageHeader, Pagination } from '@/components/app/common'

const SINCE: Record<string, number | null> = { '1h': 3600, '24h': 86400, '7d': 7 * 86400, '30d': 30 * 86400, all: null }

function sinceIso(k: string): string | undefined {
  const s = SINCE[k]
  return s ? new Date(Date.now() - s * 1000).toISOString().replace(/\.\d+Z$/, '.000Z') : undefined
}

function why(e: AuditEvent): string {
  return explainRule(e.policy, e.rule_id, e.decision, e.reason_display)
}

export function EventsTable({ fixed, initial }: { fixed?: { project?: string }; initial?: { kind?: string; since?: string; q?: string; policy?: string } }) {
  const { home, agents } = useApp()
  const [kind, setKind] = React.useState(initial?.kind ?? 'all')
  const [since, setSince] = React.useState(initial?.since ?? '7d')
  const [agent, setAgent] = React.useState('')
  const [project, setProject] = React.useState(fixed?.project ?? '')
  const [q, setQ] = React.useState(initial?.q ?? '')
  const [qLive, setQLive] = React.useState(initial?.q ?? '')
  const [policy, setPolicy] = React.useState(initial?.policy ?? '')
  const [page, setPage] = React.useState(1)
  const [size, setSize] = React.useState(25)
  const [sel, setSel] = React.useState<AuditEvent | null>(null)
  const projects = useData(() => (fixed?.project ? Promise.resolve({ projects: [] as Project[] }) : get<{ projects: Project[] }>('/api/projects')))

  React.useEffect(() => {
    const t = setTimeout(() => {
      setQ(qLive)
      setPage(1)
    }, 300)
    return () => clearTimeout(t)
  }, [qLive])

  const params = { kind, since: sinceIso(since), agent, project, policy, q, page, size }
  const d = useData(() => get<EventsResp>('/api/events', params), [kind, since, agent, project, policy, q, page, size])
  useInterval(() => page === 1 && d.reload(), 10000)
  const reset = <T,>(f: (v: T) => void) => (v: T) => {
    f(v)
    setPage(1)
  }

  const [exportNote, setExportNote] = React.useState<string | null>(null)
  const exportCsv = async () => {
    const rows: AuditEvent[] = []
    let total = 0
    for (let pg = 1; pg <= 10; pg++) {
      const r = await get<EventsResp>('/api/events', { ...params, page: pg, size: 200 })
      rows.push(...r.events)
      total = r.total
      if (pg >= r.pages) break
    }
    setExportNote(rows.length < total ? `Exported the newest ${rows.length.toLocaleString()} of ${total.toLocaleString()} events. Narrow the filters or use \`agentfence events --json\` for everything.` : null)
    const cols = ['timestamp', 'agent', 'session', 'action', 'resource', 'decision', 'enforcement', 'policy', 'rule_id', 'reason', 'count', 'human', 'machine'] as const
    // Agents influence paths and hosts: neutralise spreadsheet formulas.
    const esc = (v: unknown) => {
      let s = String(v ?? '')
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s
      return `"${s.replace(/"/g, '""')}"`
    }
    const csv = [cols.join(','), ...rows.map((e) => cols.map((c) => esc(c === 'resource' ? e.resource_display : c === 'reason' ? e.reason_display : (e as any)[c])).join(','))].join('\n')
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
    a.download = `agentfence-activity-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
  }

  const c = d.data?.counts_24h
  return (
    <>
      <Card>
        <div className="flex flex-wrap items-end gap-3 border-b p-3">
          <div className="relative min-w-56 flex-1">
            <Search className="absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
            <Input className="pl-8" placeholder="Search paths, hosts, commands, rules…" value={qLive} onChange={(e) => setQLive(e.target.value)} />
          </div>
          <NativeSelect value={kind} onChange={(e) => reset(setKind)(e.target.value)} aria-label="Result">
            <option value="all">All results</option>
            <option value="blocked">Blocked{c ? ` (${c.blocked} in 24 h)` : ''}</option>
            <option value="observed">Would block (not enforced)</option>
            <option value="allowed">Allowed</option>
            <option value="system">Agent start/stop & changes</option>
          </NativeSelect>
          <NativeSelect value={agent} onChange={(e) => reset(setAgent)(e.target.value)} aria-label="Agent">
            <option value="">All agents</option>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
            <option value="agentfence-ui">Console (you)</option>
          </NativeSelect>
          {!fixed?.project && (
            <NativeSelect value={project} onChange={(e) => reset(setProject)(e.target.value)} aria-label="Project" className="max-w-56">
              <option value="">All projects</option>
              {(projects.data?.projects ?? []).map((p) => (
                <option key={p.path} value={p.path}>
                  {p.name}
                </option>
              ))}
            </NativeSelect>
          )}
          <NativeSelect value={since} onChange={(e) => reset(setSince)(e.target.value)} aria-label="Time">
            <option value="1h">Last hour</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="all">All time</option>
          </NativeSelect>
          {policy && (
            <Button variant="secondary" onClick={() => reset(setPolicy)('')} title="Clear this filter">
              {policyLabel[policy] ?? policy} ✕
            </Button>
          )}
          <Button variant="outline" size="icon" onClick={d.reload} title="Refresh">
            <RefreshCw className={d.loading ? 'animate-spin' : ''} />
          </Button>
          <Button variant="outline" onClick={exportCsv}>
            <Download /> Export CSV
          </Button>
        </div>
        <ErrorText error={d.error} />
        {exportNote && <div className="border-b bg-muted/40 px-3 py-2 text-xs text-muted-foreground">{exportNote}</div>}
        {d.loading && !d.data ? (
          <Loading />
        ) : (d.data?.events.length ?? 0) === 0 ? (
          <div className="p-6">
            <Empty icon={ScrollText} title="No activity matches">
              Try a longer time range or clear the filters. Blocked actions appear here within a second or two.
            </Empty>
          </div>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-36">When</TableHead>
                  <TableHead className="w-44">Result</TableHead>
                  <TableHead>What</TableHead>
                  <TableHead>Why</TableHead>
                  <TableHead className="w-32">Agent</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {d.data!.events.map((e) => (
                  <TableRow key={e.rowid} className="cursor-pointer" onClick={() => setSel(e)}>
                    <TableCell className="text-sm whitespace-nowrap text-muted-foreground" title={fmtTime(e.timestamp)}>
                      {timeAgo(e.timestamp)}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <EffectBadge effect={e.decision} enforced={e.enforcement !== 'observed'} />
                        {e.count > 1 && <Badge variant="secondary">×{e.count}</Badge>}
                      </div>
                    </TableCell>
                    <TableCell className="max-w-[28rem]">
                      <div className="text-xs text-muted-foreground">{actionLabel(e.action)}</div>
                      <Mono className="block truncate">{tildify(e.resource_display, home)}</Mono>
                    </TableCell>
                    <TableCell className="max-w-72 truncate text-sm text-muted-foreground">{why(e)}</TableCell>
                    <TableCell className="text-sm">{e.agent === 'agentfence-ui' ? 'Console' : e.agent}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <Pagination page={d.data!.page} pages={d.data!.pages} total={d.data!.total} size={size} onPage={setPage} onSize={reset(setSize)} />
          </>
        )}
      </Card>

      <D.Root open={!!sel} onOpenChange={(o) => !o && setSel(null)}>
        <SheetContent>
          {sel && (
            <>
              <div>
                <D.Title className="text-lg font-semibold">{actionLabel(sel.action)}</D.Title>
                <D.Description className="mt-1 text-sm text-muted-foreground">{fmtTime(sel.timestamp)}</D.Description>
              </div>
              <div className="flex items-center gap-2">
                <EffectBadge effect={sel.decision} enforced={sel.enforcement !== 'observed'} />
                {sel.enforcement === 'enforced' && <span className="text-xs text-muted-foreground">Stopped by the macOS kernel sandbox</span>}
                {sel.enforcement === 'observed' && <span className="text-xs text-muted-foreground">Seen, but this kind of rule can’t be enforced yet</span>}
              </div>
              <div className="rounded-md border bg-muted/40 p-3">
                <Mono className="break-all">{sel.resource_display}</Mono>
              </div>
              {why(sel) && <div className="text-sm">{why(sel)}</div>}
              <dl className="grid grid-cols-[8rem_1fr] gap-x-4 gap-y-2 text-sm">
                {(
                  [
                    ['Agent', `${sel.agent}${sel.agent_version ? ` ${sel.agent_version}` : ''}`],
                    ['Rule', sel.policy ? `${policyLabel[sel.policy] ?? sel.policy}${sel.rule_id ? ` · ${sel.rule_id}` : ''}` : '—'],
                    ['Process chain', sel.chain_display || '—'],
                    ['Process id', sel.pid ?? '—'],
                    ['Session', sel.session],
                    ['User', sel.human],
                    ['Machine', sel.machine],
                    ['Source', sel.source],
                    ['Times seen', sel.count],
                    ['Event id', sel.id],
                  ] as const
                ).map(([k, v]) => (
                  <React.Fragment key={k}>
                    <dt className="text-muted-foreground">{k}</dt>
                    <dd className="min-w-0 break-all font-mono text-[12.5px]">{String(v)}</dd>
                  </React.Fragment>
                ))}
              </dl>
              {sel.policy && sel.policy !== 'agentfence-self' && sel.policy !== 'exec-persistence' && (
                <div className="rounded-md border px-3 py-2 text-xs text-muted-foreground">
                  To allow this, open{' '}
                  <a className="underline" href={'#/policies?tab=' + (sel.policy === 'protect-secrets' ? 'builtins' : 'rules')} onClick={() => setSel(null)}>
                    Policies
                  </a>
                  {sel.policy === 'protect-secrets' ? ' → Built-in protections.' : ' and add an allow rule.'}
                </div>
              )}
            </>
          )}
        </SheetContent>
      </D.Root>
    </>
  )
}

export default function ActivityPage({ query }: { query: URLSearchParams }) {
  return (
    <>
      <PageHeader title="Activity" description="The audit log: every action AgentFence blocked or observed, and every agent start, stop and rule change — stored locally on this Mac." />
      <EventsTable key={query.toString()} initial={{ kind: query.get('kind') ?? undefined, since: query.get('since') ?? undefined, q: query.get('q') ?? undefined, policy: query.get('policy') ?? undefined }} />
    </>
  )
}
