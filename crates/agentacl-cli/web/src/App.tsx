import * as React from 'react'
import { Activity, AlertTriangle, Bot, FolderKanban, LayoutDashboard, Moon, Settings, ShieldCheck, Sun, KeyRound } from 'lucide-react'
import { bootstrap, get, setUnauthorizedHandler, type Status } from '@/lib/api'
import { AppContext } from '@/lib/app-context'
import { useInterval, useRoute, navigate } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { Toaster } from '@/components/ui/toast'
import { TooltipProvider } from '@/components/ui/misc'
import { Button } from '@/components/ui/button'
import { Loading } from '@/components/app/common'
import { useGlobalGuard } from '@/features/guard'
import Dashboard from '@/pages/Dashboard'
import Agents from '@/pages/Agents'
import Projects from '@/pages/Projects'
import ProjectDetail from '@/pages/ProjectDetail'
import Policies from '@/pages/Policies'
import ActivityPage from '@/pages/Activity'
import SettingsPage from '@/pages/Settings'

const NAV = [
  { path: '/', label: 'Overview', icon: LayoutDashboard },
  { path: '/agents', label: 'Agents', icon: Bot },
  { path: '/projects', label: 'Projects', icon: FolderKanban },
  { path: '/policies', label: 'Policies', icon: KeyRound },
  { path: '/activity', label: 'Activity', icon: Activity },
  { path: '/settings', label: 'Settings', icon: Settings },
]

function useTheme() {
  const [dark, setDark] = React.useState(() => {
    try {
      const v = localStorage.getItem('af-theme')
      if (v) return v === 'dark'
    } catch {}
    return matchMedia('(prefers-color-scheme: dark)').matches
  })
  React.useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
    try {
      localStorage.setItem('af-theme', dark ? 'dark' : 'light')
    } catch {}
  }, [dark])
  return [dark, setDark] as const
}

export default function App() {
  const [phase, setPhase] = React.useState<'boot' | 'ready' | 'signedout'>('boot')
  const [bootMsg, setBootMsg] = React.useState<string | null>(null)
  const [status, setStatus] = React.useState<Status | null>(null)
  const [agents, setAgents] = React.useState<{ id: string; name: string }[]>([])
  const [dark, setDark] = useTheme()
  const route = useRoute()
  const nav = useGlobalGuard()

  const refreshStatus = React.useCallback(() => {
    get<Status>('/api/status').then(setStatus).catch(() => {})
  }, [])

  React.useEffect(() => {
    setUnauthorizedHandler(() => setPhase('signedout'))
    ;(async () => {
      const r = await bootstrap()
      if (r !== 'ok' && r !== 'none') setBootMsg(r)
      try {
        const s = await get<Status>('/api/status')
        setStatus(s)
        const o = await get<{ agents: { id: string; name: string }[] }>('/api/overview')
        setAgents(o.agents)
        setPhase('ready')
      } catch {
        setPhase('signedout')
      }
    })()
  }, [])
  useInterval(refreshStatus, 15000)

  if (phase === 'boot') return <Loading label="Connecting to AgentACL…" />
  if (phase === 'signedout' && !status) return <SignedOut message={bootMsg} />

  const p = route.path
  let page: React.ReactNode
  if (p === '/' || p === '') page = <Dashboard />
  else if (p === '/agents') page = <Agents />
  else if (p === '/projects') page = <Projects />
  else if (p.startsWith('/projects/')) page = <ProjectDetail path={decodeURIComponent(p.slice('/projects/'.length))} tab={route.query.get('tab') ?? 'overview'} />
  else if (p === '/policies') page = <Policies tab={route.query.get('tab') ?? 'rules'} />
  else if (p === '/activity') page = <ActivityPage query={route.query} />
  else if (p === '/settings') page = <SettingsPage />
  else page = <Dashboard />

  const active = (path: string) => (path === '/' ? p === '/' : p === path || p.startsWith(path + '/'))

  return (
    <AppContext.Provider value={{ status, home: status?.home ?? '', agents, refreshStatus, setDirty: nav.setDirty, guard: nav.guard }}>
      <TooltipProvider>
        <Toaster>
          <div className="flex min-h-screen">
            <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r bg-sidebar md:flex">
              <div className="flex items-center gap-2.5 px-5 py-5">
                <div className="grid size-8 place-items-center rounded-lg bg-brand text-white shadow-sm">
                  <ShieldCheck className="size-4.5" />
                </div>
                <div>
                  <div className="text-sm font-semibold leading-tight">AgentACL</div>
                  <div className="text-[11px] text-muted-foreground">AI agent access control</div>
                </div>
              </div>
              <nav className="flex flex-1 flex-col gap-0.5 px-3">
                {NAV.map((n) => (
                  <a
                    key={n.path}
                    href={'#' + n.path}
                    className={cn(
                      'flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground',
                      active(n.path) && 'bg-accent text-foreground',
                    )}
                  >
                    <n.icon className="size-4" />
                    {n.label}
                  </a>
                ))}
              </nav>
              <div className="border-t px-4 py-4 text-xs text-muted-foreground">
                <div className="flex items-center gap-2">
                  <span className="relative flex size-2">
                    <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-60" />
                    <span className="relative inline-flex size-2 rounded-full bg-emerald-500" />
                  </span>
                  <span className="font-medium text-foreground">Console connected</span>
                </div>
                <div className="mt-1.5 truncate">
                  {status?.human}@{status?.hostname ?? 'this Mac'} · v{status?.version}
                </div>
              </div>
            </aside>
            <div className="flex min-w-0 flex-1 flex-col">
              <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-background/85 px-4 backdrop-blur md:px-8">
                <div className="flex gap-1 overflow-x-auto md:hidden">
                  {NAV.map((n) => (
                    <a key={n.path} href={'#' + n.path} className={cn('rounded-md px-2 py-1 text-sm', active(n.path) && 'bg-accent')}>
                      {n.label}
                    </a>
                  ))}
                </div>
                <div className="hidden text-sm text-muted-foreground md:block">
                  Enforcing with <span className="font-medium text-foreground">macOS Seatbelt</span> — the kernel sandbox, applied to every agent started with <code className="rounded bg-muted px-1 font-mono text-xs">agentacl run</code>
                </div>
                <div className="ml-auto flex items-center gap-1">
                  <Button variant="ghost" size="icon" onClick={() => setDark(!dark)} title="Toggle theme">
                    {dark ? <Sun /> : <Moon />}
                  </Button>
                </div>
              </header>
              {status && status.warnings.length > 0 && (
                <div className="border-b border-amber-500/30 bg-amber-500/[0.07] px-4 py-2 text-sm text-amber-900 md:px-8 dark:text-amber-200">
                  {status.warnings.map((w, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <AlertTriangle className="size-4 shrink-0" />
                      <span>{w.message}</span>
                      {w.kind === 'old-supervisor' && (
                        <button className="ml-1 font-medium underline underline-offset-2" onClick={() => navigate('/agents')}>
                          Review agents
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
              <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-8 md:px-8">{page}</main>
              {nav.dialog}
              {phase === 'signedout' && (
                // An overlay, so an unsaved draft underneath survives until a new link signs in.
                <div className="fixed inset-0 z-[90] bg-background/70 backdrop-blur-sm">
                  <SignedOut message="This console session ended (a newer link was opened, or the console restarted). Unsaved changes stay on this page while it is open, but they can’t be saved from here." />
                </div>
              )}
            </div>
          </div>
        </Toaster>
      </TooltipProvider>
    </AppContext.Provider>
  )
}

function SignedOut({ message }: { message: string | null }) {
  return (
    <div className="grid min-h-screen place-items-center p-6">
      <div className="w-full max-w-md rounded-xl border bg-card p-8 text-center shadow-sm">
        <div className="mx-auto mb-4 grid size-11 place-items-center rounded-xl bg-brand text-white">
          <ShieldCheck className="size-5" />
        </div>
        <h1 className="text-lg font-semibold">Open the console from your terminal</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          For your security, the console only opens through a one-time link. Go to the terminal running <code className="font-mono">agentacl ui</code> and press <kbd className="rounded border bg-muted px-1.5 font-mono text-xs">Enter</kbd> to open a fresh link.
        </p>
        {message && <p className="mt-4 rounded-md bg-muted px-3 py-2 text-xs text-muted-foreground">{message}</p>}
      </div>
    </div>
  )
}
