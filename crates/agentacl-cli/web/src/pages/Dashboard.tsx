import { ArrowRight, Bot, Globe, Inbox, KeyRound, ShieldAlert, ShieldCheck, ShieldX, TriangleAlert } from 'lucide-react'
import { get, type AgentsResp, type Stats } from '@/lib/api'
import { useData, useInterval, navigate } from '@/lib/hooks'
import { useApp } from '@/lib/app-context'
import { actionLabel, baseName, explainRule, policyLabel, sinceUs, tildify } from '@/lib/format'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Command, Empty, PageHeader, Stat } from '@/components/app/common'
import { BarList, CategoryBadge, Donut, StackedBars } from '@/components/app/charts'

export default function Dashboard() {
  const { home, inbox } = useApp()
  const stats = useData(() => get<Stats>('/api/stats'))
  const agents = useData(() => get<AgentsResp>('/api/agents'))
  useInterval(() => {
    stats.reload()
    agents.reload()
  }, 10000)

  const running = agents.data?.running ?? []
  const protectedN = running.filter((r) => r.supervised).length
  const unprotected = running.filter((r) => !r.supervised)
  const c = stats.data?.counts_24h
  const hourly = stats.data?.hourly ?? []
  const hourLabels = hourly.map((_, i) => (i === 23 ? 'now' : `${23 - i}h ago`))
  // Group blocked files by folder so one noisy cache doesn't fill the list.
  const files = Object.values(
    (stats.data?.top_blocked ?? [])
      .filter((t) => t.action !== 'network.connect')
      .reduce<Record<string, { resource: string; action: string; policy?: string; rule_id?: string; count: number }>>((m, t) => {
        const dir = t.resource.replace(/\/[^/]*$/, '') || '/'
        const cur = m[dir]
        m[dir] = cur ? { ...cur, count: cur.count + t.count } : { ...t, resource: dir }
        return m
      }, {}),
  )
    .sort((a, b) => b.count - a.count)
    .slice(0, 6)

  return (
    <>
      <PageHeader title="Overview" description="Which AI coding agents are on this Mac, what they are allowed to touch, and what AgentACL stopped them from doing." />

      {unprotected.length > 0 && (
        <Card className="mb-6 border-amber-500/40 bg-amber-500/[0.05]">
          <CardContent className="flex flex-col gap-3 pt-5 sm:flex-row sm:items-center">
            <TriangleAlert className="size-5 shrink-0 text-amber-600" />
            <div className="flex-1 text-sm">
              <div className="font-medium">
                {unprotected.length} agent{unprotected.length > 1 ? 's are' : ' is'} running without AgentACL
              </div>
              <div className="text-muted-foreground">
                {unprotected.map((u) => `${u.name} in ${u.project ? baseName(u.project) : tildify(u.cwd, home) || 'unknown folder'}`).join(', ')} — these can read your secrets. Quit them and start again with <code className="font-mono">agentacl run -- &lt;agent&gt;</code>.
              </div>
            </div>
            <Button variant="outline" onClick={() => navigate('/agents')}>
              Review agents <ArrowRight />
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Stat label="Blocked · 24 h" value={(c?.blocked ?? 0).toLocaleString()} hint="Stopped by the kernel or the proxy" icon={ShieldX} tone="danger" onClick={() => navigate('/activity?kind=blocked&since=24h')} />
        <Stat label="Secret access blocked" value={(c?.secrets ?? 0).toLocaleString()} hint=".env, SSH keys, cloud credentials…" icon={KeyRound} tone="warning" onClick={() => navigate('/activity?kind=blocked&since=24h&policy=protect-secrets')} />
        <Stat label="Sites blocked · 24 h" value={stats.data?.sites_blocked ?? 0} hint={`${stats.data?.sites_total ?? 0} sites contacted`} icon={Globe} tone="brand" onClick={() => navigate('/network')} />
        <Stat label="Requests waiting" value={(inbox?.approvals.length ?? 0) + (inbox?.requests_new ?? 0)} hint={(inbox?.approvals.length ?? 0) > 0 ? `${inbox!.approvals.length} need an answer now` : 'New in the last 24 h'} icon={Inbox} tone={(inbox?.approvals.length ?? 0) > 0 ? 'warning' : 'default'} onClick={() => navigate('/requests')} />
        <Stat label="Agents running" value={running.length} hint={`${protectedN} protected · ${running.length - protectedN} unprotected`} icon={Bot} tone={unprotected.length ? 'warning' : 'success'} onClick={() => navigate('/agents')} />
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Activity · last 24 hours</CardTitle>
            <CardDescription>Allowed and blocked actions per hour, across every protected agent.</CardDescription>
          </CardHeader>
          <CardContent>
            <StackedBars
              data={hourly as unknown as Record<string, number>[]}
              labels={hourLabels}
              series={[
                { key: 'blocked', label: 'Blocked', className: 'bg-red-500' },
                { key: 'allowed', label: 'Allowed', className: 'bg-emerald-500/70' },
              ]}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>What was blocked</CardTitle>
            <CardDescription>Last 24 hours, by kind</CardDescription>
          </CardHeader>
          <CardContent>
            <Donut items={(stats.data?.blocked_by_kind ?? []).map((k) => ({ label: k.kind, value: k.count }))} centerLabel="blocked" empty="Nothing blocked in the last 24 hours." />
          </CardContent>
        </Card>
      </div>

      <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <div>
              <CardTitle>Top blocked sites</CardTitle>
              <CardDescription>Where agents tried to connect</CardDescription>
            </div>
            <Button variant="ghost" size="sm" onClick={() => navigate('/network')}>
              Network <ArrowRight />
            </Button>
          </CardHeader>
          <CardContent>
            <BarList
              barClass="bg-red-500"
              empty="No site was blocked in the last 24 hours."
              items={(stats.data?.top_blocked_sites ?? []).map((h) => ({ key: h.host, label: h.host, value: h.count, sub: <CategoryBadge id={h.category.id} label={h.category.label} /> }))}
              onClick={() => navigate('/network')}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Most used sites</CardTitle>
            <CardDescription>Allowed connections</CardDescription>
          </CardHeader>
          <CardContent>
            <BarList
              barClass="bg-emerald-500"
              empty="No connections in the last 24 hours."
              items={(stats.data?.top_allowed_sites ?? []).map((h) => ({ key: h.host, label: h.host, value: h.count, sub: <CategoryBadge id={h.category.id} label={h.category.label} /> }))}
              onClick={() => navigate('/network')}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Most blocked files</CardTitle>
            <CardDescription>What agents keep trying to open</CardDescription>
          </CardHeader>
          <CardContent>
            <BarList
              barClass="bg-amber-500"
              empty="No file was blocked in the last 24 hours."
              items={files.map((t) => ({ key: t.resource + t.action, label: tildify(t.resource, home), value: t.count, sub: `${actionLabel(t.action)} · ${explainRule(t.policy, t.rule_id, 'deny', policyLabel[t.policy ?? ''] ?? t.policy ?? '')}` }))}
              onClick={() => navigate('/requests')}
            />
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
              Start any coding agent through AgentACL from its project folder:
              <div className="mt-3 text-left">
                <Command>agentacl run -- claude</Command>
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
