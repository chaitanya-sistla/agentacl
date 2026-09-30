import * as React from 'react'
import { BadgeCheck, Bot, FolderOpen, MoreHorizontal, RefreshCw, RotateCw, ShieldAlert, ShieldCheck, Square, TriangleAlert } from 'lucide-react'
import { get, post, type AgentsResp, type RunningAgent } from '@/lib/api'
import { useData, useInterval, navigate } from '@/lib/hooks'
import { useApp } from '@/lib/app-context'
import { baseName, sinceUs, timeAgo, tildify } from '@/lib/format'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger, Tooltip } from '@/components/ui/misc'
import { Command, Empty, ErrorText, Loading, Mono, PageHeader } from '@/components/app/common'
import { RestartBadge, useRestartState, useSessionActions } from '@/features/session-actions'
import { AgentAccess } from '@/features/agent-access'

const CMD: Record<string, string> = { 'claude-code': 'claude', codex: 'codex', 'gemini-cli': 'gemini', 'copilot-cli': 'copilot', opencode: 'opencode' }

export default function Agents() {
  const { home } = useApp()
  const [refreshing, setRefreshing] = React.useState(false)
  const d = useData(() => get<AgentsResp>('/api/agents'))
  useInterval(() => d.reload(), 8000)
  const [protect, setProtect] = React.useState<RunningAgent | null>(null)
  const actions = useSessionActions(d.reload)

  const rescan = async () => {
    setRefreshing(true)
    try {
      d.setData(await get<AgentsResp>('/api/agents', { refresh: 1 }))
    } finally {
      setRefreshing(false)
    }
  }
  const running = d.data?.running ?? []
  const installed = d.data?.installed ?? []

  return (
    <>
      <PageHeader
        title="Agents"
        description="Every AI coding agent on this Mac — found by scanning installed programs and running processes, no matter which folder you opened the console from."
        actions={
          <Button variant="outline" onClick={rescan} disabled={refreshing}>
            <RefreshCw className={refreshing ? 'animate-spin' : ''} /> Scan again
          </Button>
        }
      />
      <ErrorText error={d.error} />
      <Tabs defaultValue="running">
        <TabsList>
          <TabsTrigger value="running">
            Running <Badge variant="secondary">{running.length}</Badge>
          </TabsTrigger>
          <TabsTrigger value="installed">
            Installed <Badge variant="secondary">{installed.length}</Badge>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="running">
          <Card>
            {d.loading && !d.data ? (
              <Loading />
            ) : running.length === 0 ? (
              <div className="p-6">
                <Empty icon={Bot} title="No agents running">
                  Open a terminal in your project and start the agent through AgentACL:
                  <div className="mt-3 text-left">
                    <Command>agentacl run -- claude</Command>
                  </div>
                </Empty>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Agent</TableHead>
                    <TableHead>Working in</TableHead>
                    <TableHead>Protection</TableHead>
                    <TableHead>Rules</TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead className="w-12" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {running.map((r) => {
                    const s = r.session
                    return (
                      <TableRow key={r.pid}>
                        <TableCell>
                          <div className="font-medium">{r.name}</div>
                          <div className="text-xs text-muted-foreground">
                            pid {r.pid}
                            {r.version ? ` · v${r.version}` : ''}
                          </div>
                        </TableCell>
                        <TableCell className="max-w-72">
                          {r.project ? (
                            <button className="text-left hover:underline" onClick={() => navigate('/projects/' + encodeURIComponent(r.project!))}>
                              <div className="font-medium">{baseName(r.project)}</div>
                              <Mono className="block truncate text-muted-foreground">{tildify(r.project, home)}</Mono>
                            </button>
                          ) : (
                            <Mono className="text-muted-foreground">{tildify(r.cwd, home) || 'unknown'}</Mono>
                          )}
                        </TableCell>
                        <TableCell>
                          {r.supervised ? (
                            <Badge variant="success">
                              <ShieldCheck /> Protected
                            </Badge>
                          ) : (
                            <Button variant="outline" size="sm" className="h-7 border-amber-500/40 text-amber-700 dark:text-amber-400" onClick={() => setProtect(r)}>
                              <ShieldAlert /> Not protected — fix
                            </Button>
                          )}
                        </TableCell>
                        <TableCell>
                          {!s ? (
                            <span className="text-sm text-muted-foreground">—</span>
                          ) : (
                            <SessionRules session={s.session} stale={s.stale} />
                          )}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">{sinceUs(r.started_us)}</TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" className="size-8" disabled={actions.busy === s?.session}>
                                <MoreHorizontal />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent>
                              {s && (
                                <DropdownMenuItem onSelect={() => actions.restart({ ...s, agent_name: r.name })}>
                                  <RotateCw /> Restart with current rules
                                </DropdownMenuItem>
                              )}
                              {r.project && (
                                <DropdownMenuItem onSelect={() => navigate('/projects/' + encodeURIComponent(r.project!) + '?tab=access')}>
                                  <ShieldCheck /> View what it can access
                                </DropdownMenuItem>
                              )}
                              {(r.project || r.cwd) && (
                                <DropdownMenuItem onSelect={() => post('/api/reveal', { path: r.project || r.cwd })}>
                                  <FolderOpen /> Show folder in Finder
                                </DropdownMenuItem>
                              )}
                              {!r.supervised && (
                                <DropdownMenuItem onSelect={() => setProtect(r)}>
                                  <ShieldAlert /> How to protect it
                                </DropdownMenuItem>
                              )}
                              {s && (
                                <>
                                  <DropdownMenuSeparator />
                                  <DropdownMenuItem destructive onSelect={() => actions.stop({ ...s, agent_name: r.name })}>
                                    <Square /> Stop agent
                                  </DropdownMenuItem>
                                </>
                              )}
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            )}
          </Card>
        </TabsContent>

        <TabsContent value="installed">
          {installed.length === 0 && !d.loading ? (
            <Empty icon={Bot} title="No supported agents found">
              AgentACL looks for Claude Code, Codex, Gemini CLI, Copilot CLI and OpenCode on your PATH and in their usual install folders.
            </Empty>
          ) : (
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
              {installed.map((a) => (
                <Card key={a.path} className="p-5">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-semibold">{a.display_name}</div>
                      <div className="text-sm text-muted-foreground">{a.version ? `Version ${a.version}` : 'Version unknown'}</div>
                    </div>
                    {a.running_pids.length > 0 ? <Badge variant="success">{a.running_pids.length} running</Badge> : <Badge variant="secondary">Idle</Badge>}
                  </div>
                  <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
                    <dt className="text-muted-foreground">Command</dt>
                    <dd>
                      <Mono>{CMD[a.id] ?? a.id}</Mono>
                    </dd>
                    <dt className="text-muted-foreground">Location</dt>
                    <dd className="min-w-0">
                      <Mono className="block truncate">{tildify(a.resolved, home)}</Mono>
                    </dd>
                    <dt className="text-muted-foreground">Publisher</dt>
                    <dd>
                      {a.signature?.team_id ? (
                        <span className="inline-flex items-center gap-1">
                          <BadgeCheck className="size-4 text-emerald-500" />
                          {a.signature.authority[0]?.replace('Developer ID Application: ', '') ?? 'Signed'} <span className="text-xs text-muted-foreground">({a.signature.team_id})</span>
                        </span>
                      ) : (
                        <span className="text-muted-foreground">Not code-signed (script or npm install)</span>
                      )}
                    </dd>
                  </dl>
                  <div className="mt-4">
                    <div className="mb-1.5 text-xs text-muted-foreground">Start it protected, from your project folder:</div>
                    <Command>{`agentacl run -- ${CMD[a.id] ?? a.id}`}</Command>
                  </div>
                </Card>
              ))}
            </div>
          )}
          {d.data && <div className="mt-3 text-xs text-muted-foreground">Last scanned {timeAgo(d.data.discovered_at)}</div>}
        </TabsContent>
      </Tabs>

      <Dialog open={!!protect} onOpenChange={(o) => !o && setProtect(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Protect {protect?.name}</DialogTitle>
            <DialogDescription>This agent was started directly, so AgentACL isn’t enforcing any rules on it. It can currently read anything you can — including SSH keys and .env files.</DialogDescription>
          </DialogHeader>
          <ol className="flex list-decimal flex-col gap-3 pl-5 text-sm">
            <li>Quit the agent (your conversation is saved).</li>
            <li>
              In a terminal, go to the project folder:
              <div className="mt-1.5">
                <Command>{`cd ${JSON.stringify(protect?.project ?? protect?.cwd ?? '.')}`}</Command>
              </div>
            </li>
            <li>
              Start it through AgentACL:
              <div className="mt-1.5">
                <Command>{`agentacl run -- ${CMD[protect?.id ?? ''] ?? protect?.id ?? ''}`}</Command>
              </div>
            </li>
          </ol>
          <p className="text-xs text-muted-foreground">Tip: add a shell alias such as <Mono>alias claude=&quot;agentacl run -- claude&quot;</Mono> so it’s always protected.</p>
        </DialogContent>
      </Dialog>
      <AgentAccess />
    </>
  )
}

/** Rules status of a running session; after a restart from here, how it went. */
function SessionRules({ session, stale }: { session: string; stale: boolean | 'unknown' }) {
  const r = useRestartState(session)
  if (r) return <RestartBadge session={session} />
  if (stale === true)
    return (
      <Tooltip content="The rules changed after this agent started. Restart it to apply them.">
        <Badge variant="warning">
          <TriangleAlert /> Restart to apply
        </Badge>
      </Tooltip>
    )
  if (stale === 'unknown') return <Badge variant="outline">Unknown</Badge>
  return <Badge variant="secondary">Up to date</Badge>
}
