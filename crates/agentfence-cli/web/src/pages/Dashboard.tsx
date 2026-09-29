import { ArrowRight, Bot, FolderKanban, KeyRound, ShieldAlert, ShieldCheck, ShieldX, TriangleAlert } from 'lucide-react'
import { get, type AgentsResp, type Project, type Stats } from '@/lib/api'
import { useData, useInterval, navigate } from '@/lib/hooks'
import { useApp } from '@/lib/app-context'
import { actionLabel, baseName, explainRule, policyLabel, sinceUs, tildify } from '@/lib/format'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tooltip } from '@/components/ui/misc'
import { Command, Empty, Mono, PageHeader, Stat } from '@/components/app/common'

export default function Dashboard() {
  const { home } = useApp()
  const stats = useData(() => get<Stats>('/api/stats'))
  const agents = useData(() => get<AgentsResp>('/api/agents'))
  const projects = useData(() => get<{ projects: Project[] }>('/api/projects'))
  useInterval(() => {
    stats.reload()
    agents.reload()
  }, 10000)

  const running = agents.data?.running ?? []
  const protectedN = running.filter((r) => r.supervised).length
  const unprotected = running.filter((r) => !r.supervised)
  const c = stats.data?.counts_24h
  const tl = stats.data?.timeline_24h ?? []
  const max = Math.max(1, ...tl)

  return (
    <>
      <PageHeader title="Overview" description="Which AI coding agents are on this Mac, what they are allowed to touch, and what AgentFence stopped them from doing." />

      {unprotected.length > 0 && (
        <Card className="mb-6 border-amber-500/40 bg-amber-500/[0.05]">
          <CardContent className="flex flex-col gap-3 pt-5 sm:flex-row sm:items-center">
            <TriangleAlert className="size-5 shrink-0 text-amber-600" />
            <div className="flex-1 text-sm">
              <div className="font-medium">
                {unprotected.length} agent{unprotected.length > 1 ? 's are' : ' is'} running without AgentFence
              </div>
              <div className="text-muted-foreground">
                {unprotected.map((u) => `${u.name} in ${u.project ? baseName(u.project) : tildify(u.cwd, home) || 'unknown folder'}`).join(', ')} — these can read your secrets. Quit them and start again with <code className="font-mono">agentfence run -- &lt;agent&gt;</code>.
              </div>
            </div>
            <Button variant="outline" onClick={() => navigate('/agents')}>
              Review agents <ArrowRight />
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Blocked in last 24 h" value={(c?.blocked ?? 0).toLocaleString()} hint="Actions the kernel stopped" icon={ShieldX} tone="danger" onClick={() => navigate('/activity?kind=blocked&since=24h')} />
        <Stat label="Secret access blocked" value={(c?.secrets ?? 0).toLocaleString()} hint=".env, SSH keys, cloud credentials…" icon={KeyRound} tone="warning" onClick={() => navigate('/activity?kind=blocked&since=24h&policy=protect-secrets')} />
        <Stat label="Agents running" value={running.length} hint={`${protectedN} protected · ${running.length - protectedN} unprotected`} icon={Bot} tone={unprotected.length ? 'warning' : 'success'} onClick={() => navigate('/agents')} />
        <Stat label="Projects" value={projects.data?.projects.length ?? 0} hint="Folders agents work in" icon={FolderKanban} tone="brand" onClick={() => navigate('/projects')} />
      </div>

      <div className="mt-6 grid grid-cols-1 items-start gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Blocked actions · last 24 hours</CardTitle>
            <CardDescription>Each bar is one hour. Hover for the count.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex h-40 items-end gap-1">
              {tl.map((v, i) => (
                <Tooltip key={i} content={`${v} blocked · ${i === 23 ? 'this hour' : `${23 - i}–${24 - i}h ago`}`}>
                  <div className="flex h-full flex-1 items-end">
                    <div className={v ? 'w-full rounded-t-sm bg-red-500/80 transition-colors hover:bg-red-500' : 'w-full rounded-t-sm bg-muted'} style={{ height: `${Math.max(3, (v / max) * 100)}%` }} />
                  </div>
                </Tooltip>
              ))}
            </div>
            <div className="mt-2 flex justify-between text-xs text-muted-foreground">
              <span>24 h ago</span>
              <span>12 h ago</span>
              <span>now</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Most blocked</CardTitle>
            <CardDescription>What agents keep trying to reach</CardDescription>
          </CardHeader>
          <CardContent>
            {(stats.data?.top_blocked.length ?? 0) === 0 ? (
              <div className="py-8 text-center text-sm text-muted-foreground">Nothing blocked in the last 24 hours.</div>
            ) : (
              <ul className="flex flex-col gap-2.5">
                {stats.data!.top_blocked.map((t, i) => (
                  <li key={i} className="flex items-center gap-3">
                    <div className="min-w-0 flex-1">
                      <Mono className="block truncate">{tildify(t.resource, home)}</Mono>
                      <div className="text-xs text-muted-foreground">
                        {actionLabel(t.action)} · {explainRule(t.policy, t.rule_id, 'deny', policyLabel[t.policy ?? ''] ?? t.policy ?? '')}
                      </div>
                    </div>
                    <Badge variant="danger">{t.count}</Badge>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>Running agents</CardTitle>
            <CardDescription>Live, across every folder on this Mac</CardDescription>
          </div>
          <Button variant="ghost" size="sm" onClick={() => navigate('/agents')}>
            All agents <ArrowRight />
          </Button>
        </CardHeader>
        <CardContent>
          {running.length === 0 ? (
            <Empty icon={Bot} title="No agents are running right now">
              Start any coding agent through AgentFence from its project folder:
              <div className="mt-3 text-left">
                <Command>agentfence run -- claude</Command>
              </div>
            </Empty>
          ) : (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
              {running.map((r) => (
                <button key={r.pid} onClick={() => r.project && navigate('/projects/' + encodeURIComponent(r.project))} className="flex items-start gap-3 rounded-lg border p-4 text-left transition-colors hover:bg-accent/40">
                  <div className={r.supervised ? 'rounded-md bg-emerald-500/10 p-2 text-emerald-600' : 'rounded-md bg-amber-500/10 p-2 text-amber-600'}>
                    {r.supervised ? <ShieldCheck className="size-4" /> : <ShieldAlert className="size-4" />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{r.name}</span>
                      {r.supervised ? <Badge variant="success">Protected</Badge> : <Badge variant="warning">Not protected</Badge>}
                    </div>
                    <div className="mt-0.5 truncate text-sm text-muted-foreground">{r.project ? baseName(r.project) : tildify(r.cwd, home) || '—'}</div>
                    <div className="text-xs text-muted-foreground">
                      pid {r.pid} · started {sinceUs(r.started_us)}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </>
  )
}
