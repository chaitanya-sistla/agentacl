import * as React from 'react'
import { ArrowLeft, FolderOpen, Globe, FolderLock, ShieldAlert, ShieldCheck, Trash2, TriangleAlert, RotateCw } from 'lucide-react'
import { get, post, type AgentsResp, type Project, type Session } from '@/lib/api'
import { useData, useInterval, navigate } from '@/lib/hooks'
import { useApp } from '@/lib/app-context'
import { tildify, timeAgo } from '@/lib/format'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Command, Empty, Mono, PageHeader, Stat } from '@/components/app/common'
import { PolicyEditor, type EditorTab } from '@/features/policy/PolicyEditor'
import { useDiscardGuard } from '@/features/guard'
import { useSessionActions } from '@/features/session-actions'
import { useToast } from '@/components/ui/toast'
import { cn } from '@/lib/utils'
import { EventsTable } from '@/pages/Activity'

export default function ProjectDetail({ path, tab }: { path: string; tab: string }) {
  const { home } = useApp()
  const toast = useToast()
  const projects = useData(() => get<{ projects: Project[] }>('/api/projects'))
  const agents = useData(() => get<AgentsResp>('/api/agents'))
  const sessions = useData(() => get<{ sessions: Session[] }>('/api/sessions'))
  useInterval(() => {
    agents.reload()
    sessions.reload()
  }, 10000)
  const [scope, setScope] = React.useState<'project' | 'user'>('project')
  const [inner, setInner] = React.useState<EditorTab>('access')
  const g = useDiscardGuard()
  const actions = useSessionActions(sessions.reload)
  const p = projects.data?.projects.find((x) => x.path === path)
  const name = p?.name || path.split('/').pop() || path
  const running = (agents.data?.running ?? []).filter((r) => r.project === path)
  const mySessions = (sessions.data?.sessions ?? []).filter((s) => s.project === path)
  const t = ['overview', 'access', 'activity'].includes(tab) ? tab : 'overview'
  const go = (x: string) => g.guard(() => navigate('/projects/' + encodeURIComponent(path) + '?tab=' + x))

  return (
    <>
      <PageHeader
        back={
          <button onClick={() => g.guard(() => navigate('/projects'))} className="mb-2 flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="size-4" /> Projects
          </button>
        }
        title={name}
        description={<Mono>{tildify(path, home)}</Mono>}
        actions={
          <>
            <Button variant="outline" onClick={() => post('/api/reveal', { path })}>
              <FolderOpen /> Show in Finder
            </Button>
            {p?.saved && (
              <Button
                variant="ghost"
                onClick={async () => {
                  await post('/api/projects/remove', { path })
                  toast({ kind: 'success', title: 'Removed from the list', body: 'Its rules file (if any) was not touched.' })
                  navigate('/projects')
                }}
              >
                <Trash2 /> Remove from list
              </Button>
            )}
          </>
        }
      />
      <Tabs value={t} onValueChange={go}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="access">Access & rules</TabsTrigger>
          <TabsTrigger value="activity">Activity</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="flex flex-col gap-6">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <Stat label="Agents running here" value={running.length} hint={`${running.filter((r) => r.supervised).length} protected`} icon={running.some((r) => !r.supervised) ? ShieldAlert : ShieldCheck} tone={running.some((r) => !r.supervised) ? 'warning' : 'success'} />
            <Stat label="Blocked (24 h)" value={p?.blocked_24h ?? 0} icon={FolderLock} tone="danger" onClick={() => go('activity')} />
            <Stat label="Project rules" value={p?.has_project_rules ? 'Custom' : 'None'} hint={p?.has_project_rules ? (p.trusted ? 'Trusted — may allow' : 'Restrict only') : 'Only your rules apply'} icon={Globe} tone="brand" onClick={() => go('access')} />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Agents in this project</CardTitle>
              <CardDescription>Protected agents run inside the AgentACL sandbox.</CardDescription>
            </CardHeader>
            <CardContent>
              {running.length === 0 ? (
                <Empty title="No agents running here">
                  Start one from this folder:
                  <div className="mt-3 flex flex-col gap-2 text-left">
                    <Command>{`cd ${JSON.stringify(path)}`}</Command>
                    <Command>agentacl run -- claude</Command>
                  </div>
                </Empty>
              ) : (
                <ul className="flex flex-col divide-y rounded-md border">
                  {running.map((r) => {
                    const s = mySessions.find((x) => x.pid === r.pid) ?? r.session ?? null
                    return (
                      <li key={r.pid} className="flex flex-wrap items-center gap-3 px-4 py-3">
                        {r.supervised ? <ShieldCheck className="size-4 text-emerald-600" /> : <ShieldAlert className="size-4 text-amber-600" />}
                        <div className="min-w-0 flex-1">
                          <div className="font-medium">{r.name}</div>
                          <div className="text-xs text-muted-foreground">pid {r.pid}{s?.started_at ? ` · started ${timeAgo(s.started_at)}` : ''}</div>
                        </div>
                        {!r.supervised && <Badge variant="warning">Not protected</Badge>}
                        {s?.stale === true && (
                          <Badge variant="warning">
                            <TriangleAlert /> Rules changed
                          </Badge>
                        )}
                        {s && (
                          <Button size="sm" variant={s.stale === true ? 'brand' : 'outline'} disabled={actions.busy === s.session} onClick={() => actions.restart({ ...s, agent_name: r.name })}>
                            <RotateCw /> Restart
                          </Button>
                        )}
                      </li>
                    )
                  })}
                </ul>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="access">
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <span className="text-sm text-muted-foreground">Edit rules for</span>
            <div className="inline-flex rounded-lg border p-0.5">
              {(
                [
                  ['project', 'This project only', '.agentacl/policy.yaml'],
                  ['user', 'All projects (your rules)', '~/.config/agentacl/policy.yaml'],
                ] as const
              ).map(([k, l, f]) => (
                <button
                  key={k}
                  onClick={() => k !== scope && g.guard(() => setScope(k))}
                  className={cn('rounded-md px-3 py-1.5 text-left text-sm transition-colors', scope === k ? 'bg-brand text-white shadow-sm' : 'hover:bg-accent')}
                >
                  <div className="font-medium">{l}</div>
                  <div className={cn('font-mono text-[11px]', scope === k ? 'text-white/75' : 'text-muted-foreground')}>{f}</div>
                </button>
              ))}
            </div>
          </div>
          <PolicyEditor key={scope} scope={scope} project={path} tab={inner} onTab={setInner} onDirty={g.onDirty} />
        </TabsContent>

        <TabsContent value="activity">
          <EventsTable fixed={{ project: path }} />
        </TabsContent>
      </Tabs>
    </>
  )
}
