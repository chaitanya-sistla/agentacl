import * as React from 'react'
import { AccessGraph } from './AccessGraph'
import { ListTree, Network, ChevronDown, ChevronRight, File, Folder, FolderOpen, Link2, Loader2, Lock, ShieldCheck, ShieldX, Eye, Pencil, FolderKanban, House, KeyRound, Cpu } from 'lucide-react'
import { post, type FsList, type FsNode, type MapGroup, type Scope } from '@/lib/api'
import { useApp } from '@/lib/app-context'
import { explainRule, groupLabel, policyLabel, tildify } from '@/lib/format'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tooltip } from '@/components/ui/misc'
import { cn } from '@/lib/utils'
import { ErrorText, Mono, StatusBadge, statusMeta } from '@/components/app/common'
import { rulesOf, setRules, type SectionKey } from './sections'
import type { PolicyDraft } from './draft'

const GROUP_ICON: Record<string, React.ElementType> = { 'group:project': FolderKanban, 'group:home': House, 'group:secrets': KeyRound, 'group:system': Cpu }

function explain(d: FsNode['read'], verb: string): string {
  if (d.effect === 'allow') return d.policy.startsWith('provider:') || d.policy === 'runtime' ? `Can ${verb} — the agent needs this to run` : `Can ${verb}`
  const why = explainRule(d.policy, d.rule_id, d.effect, d.reason || 'blocked by a rule')
  return `Can’t ${verb} — ${why}`
}

export function AccessMap({ draft, scope, agent, onEditRules }: { draft: PolicyDraft; scope: Scope; agent: string; onEditRules: () => void }) {
  const { home, agents } = useApp()
  const agentName = agents.find((a) => a.id === agent)?.name ?? agent
  const [view, setView] = React.useState<'graph' | 'list'>(() => {
    try {
      return localStorage.getItem('af-map-view') === 'list' ? 'list' : 'graph'
    } catch {
      return 'graph'
    }
  })
  const pickView = (v: 'graph' | 'list') => {
    setView(v)
    try {
      localStorage.setItem('af-map-view', v)
    } catch {}
  }
  const [groups, setGroups] = React.useState<MapGroup[] | null>(null)
  const [noProject, setNoProject] = React.useState(false)
  const [kids, setKids] = React.useState<Record<string, FsList>>({})
  const [open, setOpen] = React.useState<Set<string>>(new Set())
  const [loading, setLoading] = React.useState<Set<string>>(new Set())
  const [sel, setSel] = React.useState<FsNode | null>(null)
  const [err, setErr] = React.useState<string | null>(null)
  const openRef = React.useRef(open)
  openRef.current = open
  // Responses for an older draft must not overwrite newer ones.
  const versionRef = React.useRef(draft.version)
  versionRef.current = draft.version

  const fetchDir = React.useCallback(
    async (path: string, count = 100) => {
      setLoading((s) => new Set(s).add(path))
      const v = versionRef.current
      try {
        const r = await post<FsList>('/api/fs/list', { ...draft.draftBody(), path, offset: 0, limit: Math.min(200, Math.max(100, count)) })
        if (v === versionRef.current) setKids((k) => ({ ...k, [path]: r }))
      } catch (e: any) {
        setErr(e.message)
      } finally {
        setLoading((s) => {
          const n = new Set(s)
          n.delete(path)
          return n
        })
      }
    },
    [draft.draftBody],
  )
  const more = async (path: string) => {
    const cur = kids[path]
    if (!cur) return
    const v = versionRef.current
    const r = await post<FsList>('/api/fs/list', { ...draft.draftBody(), path, offset: cur.entries.length, limit: 100 })
    if (v !== versionRef.current) return
    setKids((k) => ({ ...k, [path]: { ...r, entries: [...cur.entries, ...r.entries] } }))
  }

  // Refetch roots and every open folder whenever the draft changes.
  React.useEffect(() => {
    let live = true
    const t = setTimeout(async () => {
      try {
        const r = await post<{ roots: MapGroup[]; no_project: boolean }>('/api/map', draft.draftBody())
        if (!live) return
        setGroups(r.roots)
        setNoProject(r.no_project)
        setErr(null)
        setSel((s) => (s ? findNode(r.roots, s.path) ?? s : s))
        for (const p of openRef.current) fetchDir(p, kids[p]?.entries.length)
      } catch (e: any) {
        if (live) setErr(e.message)
      }
    }, 250)
    return () => {
      live = false
      clearTimeout(t)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft.version, draft.loaded])

  React.useEffect(() => {
    if (!sel) return
    for (const l of Object.values(kids)) {
      const n: FsNode | undefined = l.entries.find((e) => e.path === sel.path)
      if (n && n !== sel) setSel(n)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kids])

  const toggle = (n: FsNode) => {
    const s = new Set(open)
    if (s.has(n.path)) s.delete(n.path)
    else {
      s.add(n.path)
      if (!kids[n.path]) fetchDir(n.path)
    }
    setOpen(s)
  }

  const addRule = async (key: SectionKey, rule: string) => {
    if (draft.mode === 'yaml') {
      const e = await draft.toDoc()
      if (e) return setErr('Fix the YAML first: ' + e)
    }
    draft.updateDoc((d) => {
      const list = rulesOf(d, key)
      if (list.some((r) => r.pattern === rule)) return d
      return setRules(d, key, [...list, { kind: 'path', pattern: rule, except: [], id: null, reason: null }])
    })
  }
  const removeRule = async (key: SectionKey, rule: string) => {
    if (draft.mode === 'yaml') {
      const e = await draft.toDoc()
      if (e) return setErr('Fix the YAML first: ' + e)
    }
    draft.updateDoc((d) => setRules(d, key, rulesOf(d, key).filter((r) => r.pattern !== rule)))
  }

  const renderNode = (n: FsNode, depth: number): React.ReactNode => {
    const isOpen = open.has(n.path)
    const list = kids[n.path]
    const m = statusMeta[n.kind === 'missing' ? 'missing' : n.status]
    return (
      <React.Fragment key={n.path + depth}>
        <div
          role="treeitem"
          aria-expanded={n.expandable ? isOpen : undefined}
          onClick={() => setSel(n)}
          className={cn('group relative flex cursor-pointer items-center gap-2 rounded-md py-1.5 pr-2 text-sm hover:bg-accent/50', sel?.path === n.path && 'bg-accent ring-1 ring-border')}
          style={{ paddingLeft: depth * 20 + 6 }}
        >
          {depth > 0 && <span className="absolute top-0 bottom-0 w-px bg-border" style={{ left: depth * 20 - 8 }} />}
          <button
            className={cn('grid size-5 place-items-center rounded hover:bg-muted', !n.expandable && 'invisible')}
            onClick={(e) => {
              e.stopPropagation()
              toggle(n)
            }}
          >
            {loading.has(n.path) ? <Loader2 className="size-3.5 animate-spin" /> : isOpen ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
          </button>
          <span className={cn('h-5 w-1 shrink-0 rounded-full', m.dot)} />
          {n.kind === 'symlink' ? <Link2 className="size-4 text-muted-foreground" /> : n.is_dir ? isOpen ? <FolderOpen className="size-4 text-muted-foreground" /> : <Folder className="size-4 text-muted-foreground" /> : <File className="size-4 text-muted-foreground" />}
          <span className="min-w-0 flex-1 truncate">{n.display}</span>
          {n.builtin_lock && (
            <Tooltip content="Locked by a built-in protection">
              <Lock className="size-3.5 text-muted-foreground" />
            </Tooltip>
          )}
          {n.inner_rules > 0 && (
            <Tooltip content={`${n.inner_allow} allow and ${n.inner_deny} block rule(s) apply to things inside`}>
              <span className="hidden text-xs text-muted-foreground sm:inline">
                {n.inner_allow > 0 && <span className="text-emerald-600 dark:text-emerald-400">+{n.inner_allow} allowed inside </span>}
                {n.inner_deny > 0 && <span className="text-red-600 dark:text-red-400">−{n.inner_deny} blocked inside</span>}
              </span>
            </Tooltip>
          )}
          <StatusBadge status={n.status} />
        </div>
        {isOpen && list && (
          <>
            {list.needs_force && (
              <div className="py-1.5 text-xs text-muted-foreground" style={{ paddingLeft: (depth + 1) * 20 + 30 }}>
                macOS-protected folder — not listed.
              </div>
            )}
            {list.entries.map((c) => renderNode(c, depth + 1))}
            {list.entries.length < list.total && (
              <div style={{ paddingLeft: (depth + 1) * 20 + 30 }} className="py-1">
                <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => more(n.path)}>
                  Show more · {list.entries.length.toLocaleString()} of {list.total.toLocaleString()} shown
                </Button>
              </div>
            )}
            {list.total === 0 && !list.needs_force && (
              <div className="py-1 text-xs text-muted-foreground" style={{ paddingLeft: (depth + 1) * 20 + 30 }}>
                Empty folder
              </div>
            )}
          </>
        )}
      </React.Fragment>
    )
  }

  const summary = (g: MapGroup) => {
    const c: Record<string, number> = {}
    g.children.forEach((n) => (c[n.status] = (c[n.status] ?? 0) + 1))
    return c
  }

  return (
    <div className="flex flex-col gap-4">
      <ErrorText error={err} />
      {noProject && (
        <div className="rounded-md border border-dashed px-4 py-3 text-sm text-muted-foreground">
          No project selected — showing your machine-wide rules. Pick a project above to see what agents can do inside it.
        </div>
      )}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {(groups ?? []).map((g) => {
          const Icon = GROUP_ICON[g.id] ?? Folder
          const c = summary(g)
          const one = g.children.length === 1 ? g.children[0] : null
          return (
            <Card key={g.id} className="p-4">
              <div className="flex items-center gap-2 text-sm font-medium">
                <Icon className="size-4 text-muted-foreground" /> {g.name}
              </div>
              <div className="mt-2 min-h-6">
                {one ? (
                  <StatusBadge status={one.status} />
                ) : g.children.length === 0 ? (
                  <span className="text-xs text-muted-foreground">None found on this Mac</span>
                ) : (
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(c).map(([k, v]) => (
                      <Badge key={k} variant={statusMeta[k as keyof typeof statusMeta].variant}>
                        {v} {statusMeta[k as keyof typeof statusMeta].label.toLowerCase()}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
              <div className="mt-1.5 text-xs text-muted-foreground">{g.description}</div>
            </Card>
          )
        })}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Card className="overflow-hidden">
          <CardHeader className="flex-row flex-wrap items-center gap-x-4 gap-y-2 border-b pb-3">
            <CardTitle className="text-[15px]">What agents can reach</CardTitle>
            <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
              {(['full', 'read-only', 'partial', 'blocked'] as const).map((k) => (
                <Tooltip key={k} content={statusMeta[k].help}>
                  <span className="flex items-center gap-1.5">
                    <span className={cn('h-3 w-1 rounded-full', statusMeta[k].dot)} />
                    {statusMeta[k].label}
                  </span>
                </Tooltip>
              ))}
            </div>
            <div className="ml-auto flex items-center gap-2">
              {draft.dirty && <Badge variant="warning">Showing unsaved changes</Badge>}
              <div className="inline-flex rounded-md border p-0.5 text-xs">
                {(['graph', 'list'] as const).map((v) => (
                  <button key={v} onClick={() => pickView(v)} className={cn('flex items-center gap-1 rounded px-2 py-1 font-medium', view === v ? 'bg-accent text-foreground' : 'text-muted-foreground hover:text-foreground')}>
                    {v === 'graph' ? <Network className="size-3.5" /> : <ListTree className="size-3.5" />}
                    {v === 'graph' ? 'Graph' : 'List'}
                  </button>
                ))}
              </div>
            </div>
          </CardHeader>
          {groups && view === 'graph' ? (
            <AccessGraph agentName={agentName} noProject={noProject} groups={groups} kids={kids} open={open} loading={loading} sel={sel} onSelect={setSel} onToggle={toggle} onMore={more} />
          ) : (
          <CardContent className="max-h-[68vh] overflow-y-auto p-2" role="tree">
            {!groups ? (
              <div className="flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
                <Loader2 className="size-4 animate-spin" /> Evaluating rules…
              </div>
            ) : (
              groups.map((g) => (
                <div key={g.id} className="mb-2">
                  <div className="px-2 pt-2 pb-1 text-xs font-semibold tracking-wide text-muted-foreground uppercase">{g.name}</div>
                  {g.children.length === 0 ? <div className="px-3 py-1 text-xs text-muted-foreground">Nothing here</div> : g.children.map((n) => renderNode(n, 0))}
                </div>
              ))
            )}
          </CardContent>
          )}
        </Card>

        <div className="xl:sticky xl:top-20 xl:self-start">
          {!sel ? (
            <Card className="p-6 text-center text-sm text-muted-foreground">
              <ShieldCheck className="mx-auto mb-2 size-6" />
              Select any file or folder to see exactly what agents can do with it — and change it.
            </Card>
          ) : (
            <NodePanel node={sel} scope={scope} draft={draft} home={home} onAdd={addRule} onRemove={removeRule} onEditRules={onEditRules} />
          )}
        </div>
      </div>
    </div>
  )
}

function findNode(groups: MapGroup[], path: string): FsNode | undefined {
  for (const g of groups) for (const n of g.children) if (n.path === path) return n
  return undefined
}

function NodePanel({ node, scope, draft, home, onAdd, onRemove, onEditRules }: { node: FsNode; scope: Scope; draft: PolicyDraft; home: string; onAdd: (k: SectionKey, r: string) => void; onRemove: (k: SectionKey, r: string) => void; onEditRules: () => void }) {
  const actions: { key: keyof FsNode['actions']; section: SectionKey; label: string; icon: React.ElementType; tone: string }[] = [
    { key: 'allow_read', section: 'filesystem.allow_read', label: 'Allow reading', icon: Eye, tone: 'text-emerald-600' },
    { key: 'allow_write', section: 'filesystem.allow_write', label: 'Allow reading & changing', icon: Pencil, tone: 'text-emerald-600' },
    { key: 'deny_write', section: 'filesystem.deny_write', label: 'Make read-only', icon: Lock, tone: 'text-sky-600' },
    { key: 'deny_read', section: 'filesystem.deny_read', label: 'Block completely', icon: ShieldX, tone: 'text-red-600' },
  ]
  const inDraft = (a: (typeof actions)[number]) => {
    const r = node.actions[a.key]?.rule
    return !!r && !!draft.doc && rulesOf(draft.doc, a.section).some((x) => x.pattern === r)
  }
  const source = (d: FsNode['read']) => (d.policy ? policyLabel[d.policy] ?? d.policy : '')
  // A built-in block always wins over an allow rule, so an allow would do
  // nothing here: offer switching the secret group off instead (user rules
  // only), or explain that the protection is permanent.
  const lock = [node.read, node.write].find((d) => d.effect !== 'allow' && ['protect-secrets', 'exec-persistence', 'agentfence-self'].includes(d.policy))
  const group = lock?.policy === 'protect-secrets' ? lock.rule_id : null
  const groupOff = !!group && !!draft.doc?.builtin?.disable?.includes(group)
  const toggleGroup = async () => {
    if (!group) return
    if (draft.mode === 'yaml') {
      const e = await draft.toDoc()
      if (e) return
    }
    draft.updateDoc((d) => {
      const cur = d.builtin?.disable ?? []
      const next = groupOff ? cur.filter((x) => x !== group) : [...new Set([...cur, group])]
      return { ...d, builtin: next.length ? { disable: next } : null }
    })
  }
  return (
    <Card>
      <CardHeader className="border-b pb-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <CardTitle className="truncate text-[15px]">{node.display}</CardTitle>
            <CardDescription className="mt-1 break-all font-mono text-xs">{tildify(node.path, home)}</CardDescription>
          </div>
          <StatusBadge status={node.status} />
        </div>
        {node.link_target && (
          <div className="mt-2 text-xs text-muted-foreground">
            Symlink → {node.link_target}. Block rules apply to where it points now; if the link is changed later, the rule stays on the old target.
          </div>
        )}
      </CardHeader>
      <CardContent className="flex flex-col gap-4 pt-4">
        {[
          { d: node.read, verb: 'read', icon: Eye },
          { d: node.write, verb: 'change', icon: Pencil },
        ].map(({ d, verb, icon: I }) => (
          <div key={verb} className="flex gap-3">
            <div className={cn('mt-0.5 rounded-md p-1.5', d.effect === 'allow' ? 'bg-emerald-500/10 text-emerald-600' : 'bg-red-500/10 text-red-600')}>
              <I className="size-3.5" />
            </div>
            <div className="min-w-0 text-sm">
              <div className="font-medium">{explain(d, verb)}</div>
              {d.policy && (
                <div className="text-xs text-muted-foreground">
                  Decided by: {source(d)}
                  {d.rule_id && d.rule_id !== 'default' && !d.rule_id.includes('/') ? ` · ${d.rule_id}` : ''}
                </div>
              )}
            </div>
          </div>
        ))}
        {node.inner_rules > 0 && (
          <div className="rounded-md bg-muted px-3 py-2 text-xs text-muted-foreground">
            {node.inner_allow} allow and {node.inner_deny} block rule(s) target things inside this folder. Expand it to see them.
          </div>
        )}
        <div>
          <div className="mb-2 text-xs font-semibold tracking-wide text-muted-foreground uppercase">Change access {scope === 'project' ? '(this project)' : '(all projects)'}</div>
          <div className="flex flex-col gap-1.5">
            {lock && (
              <div className="mb-1 rounded-md border border-amber-500/30 bg-amber-500/[0.06] p-3 text-xs text-amber-900 dark:text-amber-200">
                {group ? (
                  <>
                    <div className="font-medium">Protected by “{groupLabel[group] ?? group}”</div>
                    <div className="mt-0.5">An allow rule can’t override a built-in protection — a block always wins. To let agents in, switch this protection off for every agent{scope === 'project' ? ' (in “All projects (your rules)”)' : ''}.</div>
                    {scope === 'user' && (
                      <Button size="sm" variant={groupOff ? 'secondary' : 'destructive'} className="mt-2 h-auto w-full py-1.5 whitespace-normal" onClick={toggleGroup}>
                        {groupOff ? `Undo: keep protecting ${groupLabel[group] ?? group}` : `Stop protecting ${groupLabel[group] ?? group}`}
                      </Button>
                    )}
                  </>
                ) : (
                  <div>This is always protected ({policyLabel[lock.policy] ?? lock.policy}) and can’t be opened up.</div>
                )}
              </div>
            )}
            {actions.filter((a) => !(lock && a.key.startsWith('allow'))).map((a) => {
              const act = node.actions[a.key]
              const on = inDraft(a)
              const disabled = !act || !!act.unavailable
              const btn = (
                <Button
                  variant={on ? 'secondary' : 'outline'}
                  className="w-full justify-start"
                  disabled={disabled}
                  onClick={() => (on ? onRemove(a.section, act!.rule!) : onAdd(a.section, act!.rule!))}
                >
                  <a.icon className={a.tone} />
                  <span className="flex-1 text-left">{on ? `Undo: ${a.label.toLowerCase()}` : a.label}</span>
                  {act?.display && <Mono className="max-w-40 truncate text-[11px] text-muted-foreground">{act.display}</Mono>}
                </Button>
              )
              return act?.unavailable ? (
                <Tooltip key={a.key} content={act.unavailable}>
                  <span>{btn}</span>
                </Tooltip>
              ) : (
                <React.Fragment key={a.key}>{btn}</React.Fragment>
              )
            })}
          </div>
          <p className="mt-2 text-xs text-muted-foreground">
            Changes stay a draft until you review and save.{' '}
            <button className="underline underline-offset-2" onClick={onEditRules}>
              See all rules
            </button>
          </p>
        </div>
      </CardContent>
    </Card>
  )
}
