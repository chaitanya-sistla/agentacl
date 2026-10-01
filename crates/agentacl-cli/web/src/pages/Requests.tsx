import * as React from 'react'
import { ArrowRight, Ban, Check, ChevronDown, EyeOff, FileLock2, FolderSearch, Globe, Inbox, KeyRound, Lock, Terminal, Undo2 } from 'lucide-react'
import { get, post, type RequestGroup, type RequestsResp } from '@/lib/api'
import { useData, navigate } from '@/lib/hooks'
import { useApp } from '@/lib/app-context'
import { actionLabel, baseName, groupLabel, timeAgo, tildify } from '@/lib/format'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { NativeSelect } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useToast } from '@/components/ui/toast'
import { Empty, ErrorText, Loading, Mono, PageHeader, Pagination } from '@/components/app/common'
import { CategoryBadge } from '@/components/app/charts'
import { SiteRuleDialog, type SiteRuleIntent } from '@/features/site-rule'
import { AccessDialog, type AccessIntent } from '@/features/access-dialog'
import { WaitingList } from '@/features/approvals'
import { NotifyControls } from '@/features/notify-controls'
import { RestartBar } from '@/features/restart-bar'
import { cn } from '@/lib/utils'

const KIND: Record<RequestGroup['kind'], { icon: React.ElementType; label: string; tone: string }> = {
  network: { icon: Globe, label: 'Network', tone: 'bg-sky-500/10 text-sky-600 dark:text-sky-400' },
  file: { icon: FolderSearch, label: 'Files', tone: 'bg-amber-500/10 text-amber-600 dark:text-amber-400' },
  secret: { icon: KeyRound, label: 'Secret', tone: 'bg-red-500/10 text-red-600 dark:text-red-400' },
  locked: { icon: Lock, label: 'Protected settings', tone: 'bg-violet-500/10 text-violet-600 dark:text-violet-400' },
  program: { icon: Terminal, label: 'Program', tone: 'bg-zinc-500/10 text-zinc-600 dark:text-zinc-300' },
  other: { icon: FileLock2, label: 'Other', tone: 'bg-zinc-500/10 text-zinc-600 dark:text-zinc-300' },
}

function title(g: RequestGroup, home: string): React.ReactNode {
  switch (g.kind) {
    case 'network':
      return <>Tried to reach <Mono className="font-semibold">{g.display}</Mono></>
    case 'secret':
      return <>Tried to access <b>{groupLabel[g.target] ?? g.target}</b></>
    case 'locked':
      return <>Tried to change protected files in <Mono>{tildify(g.display, home)}</Mono></>
    case 'program':
      return <>Tried to run <Mono>{g.display}</Mono></>
    case 'file':
      return <>{g.actions.every((a) => a === 'filesystem.read') ? 'Tried to read' : 'Tried to change'} files in <Mono>{tildify(g.display, home)}</Mono></>
    default:
      return <>{g.actions.map(actionLabel).join(', ')} <Mono>{g.display}</Mono></>
  }
}

function explanation(g: RequestGroup): string {
  switch (g.kind) {
    case 'network':
      return g.category?.advice ?? ''
    case 'secret':
      return 'A built-in secret protection blocked this. Agents can only get in if you switch that protection off.'
    case 'locked':
      return 'Changing these could run code outside the sandbox later, or change what the agent is allowed to do. They stay protected.'
    case 'program':
      return 'A rule blocks this program.'
    case 'file':
      return g.policy === 'seatbelt-baseline' ? 'Blocked by the base macOS sandbox, which covers only what agents need to run. Often harmless caches.' : 'Outside the project, and no rule allows it.'
    default:
      return g.reason
  }
}

export default function RequestsPage() {
  const { home, refreshInbox, inbox } = useApp()
  const toast = useToast()
  const [days, setDays] = React.useState(7)
  const [kind, setKind] = React.useState<'all' | RequestGroup['kind']>('all')
  const [showDismissed, setShowDismissed] = React.useState(false)
  const [intent, setIntent] = React.useState<SiteRuleIntent | null>(null)
  const [access, setAccess] = React.useState<AccessIntent | null>(null)
  const [saved, setSaved] = React.useState(0)
  const [page, setPage] = React.useState(1)
  const [size, setSize] = React.useState(25)
  const d = useData(() => get<RequestsResp>('/api/requests', { days, dismissed: showDismissed ? 1 : 0, kind, page, size }), [days, showDismissed, kind, page, size])
  const list = d.data?.requests ?? []
  const counts = d.data?.counts ?? {}
  // Any filter change starts from the first page.
  const reset = <T,>(f: (v: T) => void) => (v: T) => {
    f(v)
    setPage(1)
  }

  const dismiss = async (g: RequestGroup, undo = false) => {
    try {
      await post('/api/requests/dismiss', { key: g.key, undo })
      if (!undo) toast({ kind: 'info', title: 'Dismissed', body: 'It comes back if the agent tries again.' })
    } catch (e: any) {
      toast({ kind: 'error', title: 'Could not dismiss', body: e.message })
    }
    d.reload()
    refreshInbox()
  }

  return (
    <>
      <PageHeader
        title="Requests"
        description="What your agents tried to do and couldn't, grouped into decisions. Allow what a task genuinely needs; keep the rest blocked."
        actions={
          <div className="flex flex-wrap items-center gap-3">
          <NotifyControls />
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            From the last
            <NativeSelect value={days} onChange={(e) => reset(setDays)(Number(e.target.value))}>
              <option value={1}>24 hours</option>
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
            </NativeSelect>
          </label>
          </div>
        }
      />
      <RestartBar refresh={saved} />
      {(inbox?.approvals.length ?? 0) > 0 && (
        <section className="mb-6">
          <h2 className="mb-2 text-sm font-semibold">Waiting for you now</h2>
          <WaitingList />
        </section>
      )}
      {inbox?.mode !== 'ask' && (
        <Card className="mb-4 flex flex-col gap-3 border-brand/30 bg-brand/[0.04] p-4 sm:flex-row sm:items-center">
          <Globe className="size-5 shrink-0 text-brand" />
          <div className="flex-1 text-sm">
            <div className="font-medium">Want to decide on new sites as agents reach for them?</div>
            <div className="text-muted-foreground">Turn on “Ask me” in Network: the agent waits while you allow or block, live, with no restart.</div>
          </div>
          <Button variant="outline" onClick={() => navigate('/network')}>
            Open Network <ArrowRight />
          </Button>
        </Card>
      )}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <Tabs value={kind} onValueChange={(v) => reset(setKind)(v as any)}>
          <TabsList>
            <TabsTrigger value="all">All <Badge variant="secondary">{d.data?.all ?? 0}</Badge></TabsTrigger>
            <TabsTrigger value="network">Network <Badge variant="secondary">{counts.network ?? 0}</Badge></TabsTrigger>
            <TabsTrigger value="file">Files <Badge variant="secondary">{counts.file ?? 0}</Badge></TabsTrigger>
            <TabsTrigger value="secret">Secrets <Badge variant="secondary">{counts.secret ?? 0}</Badge></TabsTrigger>
            <TabsTrigger value="program">Programs <Badge variant="secondary">{counts.program ?? 0}</Badge></TabsTrigger>
          </TabsList>
        </Tabs>
        {(d.data?.keys.length ?? 0) > 0 && (
          <Button
            variant="outline"
            size="sm"
            className="ml-auto"
            onClick={async () => {
              const keys = d.data?.keys ?? []
              try {
                await post('/api/requests/dismiss', { keys })
                toast({ kind: 'info', title: `Dismissed ${keys.length}`, body: 'Each comes back if the agent tries again.' })
              } catch (e: any) {
                toast({ kind: 'error', title: 'Could not dismiss', body: e.message })
              }
              d.reload()
              refreshInbox()
            }}
          >
            <EyeOff /> Dismiss all {d.data?.keys.length}
          </Button>
        )}
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <input type="checkbox" checked={showDismissed} onChange={(e) => reset(setShowDismissed)(e.target.checked)} />
          Show dismissed ({d.data?.dismissed ?? 0})
        </label>
      </div>
      <ErrorText error={d.error} />
      {d.loading && !d.data ? (
        <Loading />
      ) : list.length === 0 ? (
        <Empty icon={Inbox} title="Nothing waiting">
          When an agent is blocked, it shows up here as a request you can allow, keep blocked or dismiss.
        </Empty>
      ) : (
        <>
          <div className="flex flex-col gap-3">
            {list.map((g) => (
              <RequestCard key={g.key} g={g} home={home} onDismiss={dismiss} onSite={setIntent} onAccess={setAccess} />
            ))}
          </div>
          <Card className="mt-4 overflow-hidden [&>div]:border-t-0">
            <Pagination page={d.data!.page} pages={d.data!.pages} total={d.data!.total} size={size} sizes={[10, 25, 50, 100]} onPage={setPage} onSize={reset(setSize)} />
          </Card>
        </>
      )}
      <SiteRuleDialog intent={intent} onClose={() => setIntent(null)} onDone={() => { d.reload(); refreshInbox() }} />
      <AccessDialog
        intent={access}
        onClose={() => setAccess(null)}
        onDone={() => {
          d.reload()
          refreshInbox()
          setSaved((n) => n + 1)
        }}
      />
    </>
  )
}

function RequestCard({
  g,
  home,
  onDismiss,
  onSite,
  onAccess,
}: {
  g: RequestGroup
  home: string
  onDismiss: (g: RequestGroup, undo?: boolean) => void
  onSite: (i: SiteRuleIntent) => void
  onAccess: (i: AccessIntent) => void
}) {
  const [open, setOpen] = React.useState(false)
  const { agents } = useApp()
  const K = KIND[g.kind]
  return (
    <Card className={cn('p-4', g.dismissed && 'opacity-60')}>
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start">
        <div className={cn('grid size-10 shrink-0 place-items-center rounded-lg', K.tone)}>
          <K.icon className="size-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[15px]">{title(g, home)}</span>
            {g.category && <CategoryBadge id={g.category.id} label={g.category.label} />}
            <Badge variant="danger">{g.count.toLocaleString()}×</Badge>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">{explanation(g)}</p>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
            <span>Last {timeAgo(g.last_seen)}</span>
            <span>First {timeAgo(g.first_seen)}</span>
            {g.agents.length > 0 && <span>{g.agents.map((id) => agents.find((x) => x.id === id)?.name ?? id).join(', ')}</span>}
            {g.projects.length > 0 && <span>in {g.projects.map(baseName).join(', ')}</span>}
          </div>
          {g.samples.length > 0 && g.kind !== 'network' && (
            <button className="mt-2 flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground" onClick={() => setOpen(!open)}>
              <ChevronDown className={cn('size-3.5 transition-transform', open && 'rotate-180')} /> {open ? 'Hide' : 'Show'} what exactly
            </button>
          )}
          {open && (
            <ul className="mt-2 flex flex-col gap-0.5 rounded-md border bg-muted/40 p-2">
              {g.samples.map((s) => (
                <li key={s}>
                  <Mono className="text-[12px] break-all">{tildify(s, home)}</Mono>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="flex shrink-0 flex-wrap gap-2 lg:justify-end">
          {g.kind === 'network' && g.manageable && (
            <>
              {g.effective?.allowable ? (
                <Button
                  size="sm"
                  variant="brand"
                  onClick={() =>
                    // Your own block is replaced in your rules; otherwise pick who and where.
                    g.effective?.by === 'you'
                      ? onSite({ host: g.target, effect: 'allow', category: g.category, wasBlockedByYou: true })
                      : onAccess({ kind: 'site', target: g.target, agents: g.agents, projects: g.projects, category: g.category })
                  }
                >
                  <Check /> Allow…
                </Button>
              ) : (
                <span className="self-center text-xs text-muted-foreground">{g.effective?.effect === 'allow' ? 'Allowed now' : `Blocked by ${g.effective?.by === 'builtin' ? 'a built-in rule' : 'a rule'}`}</span>
              )}
              <Button size="sm" variant="outline" onClick={() => onSite({ host: g.target, effect: 'block', category: g.category })}>
                <Ban /> Always block
              </Button>
            </>
          )}
          {g.kind === 'file' && (
            <>
              <Button size="sm" variant="brand" onClick={() => onAccess({ kind: 'file', target: g.target, files: g.paths ?? [], truncated: g.paths_truncated, agents: g.agents, projects: g.projects, write: g.actions.some((a) => a !== 'filesystem.read') })}>
                <Check /> Allow…
              </Button>
              <Button size="sm" variant="outline" onClick={() => navigate('/policies?focus=' + encodeURIComponent(g.target))}>
                <FolderSearch /> Access map
              </Button>
            </>
          )}
          {g.kind === 'secret' && (
            <Button size="sm" variant="outline" onClick={() => navigate('/policies?tab=builtins')}>
              <KeyRound /> Manage protection
            </Button>
          )}
          {g.kind === 'program' && (
            <Button size="sm" variant="outline" onClick={() => navigate('/policies?tab=rules')}>
              Review rules
            </Button>
          )}
          {g.dismissed ? (
            <Button size="sm" variant="ghost" onClick={() => onDismiss(g, true)}>
              <Undo2 /> Restore
            </Button>
          ) : (
            <Button size="sm" variant="ghost" onClick={() => onDismiss(g)}>
              <EyeOff /> Dismiss
            </Button>
          )}
        </div>
      </div>
    </Card>
  )
}
