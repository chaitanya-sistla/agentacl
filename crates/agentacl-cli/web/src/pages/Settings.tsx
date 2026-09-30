import { CheckCircle2, CircleSlash, FolderOpen } from 'lucide-react'
import { post } from '@/lib/api'
import { useApp } from '@/lib/app-context'
import { tildify } from '@/lib/format'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Command, Mono, PageHeader } from '@/components/app/common'

export default function SettingsPage() {
  const { status: s, home } = useApp()
  if (!s) return null
  const row = (k: string, v: React.ReactNode) => (
    <>
      <dt className="text-muted-foreground">{k}</dt>
      <dd className="min-w-0">{v}</dd>
    </>
  )
  const pathRow = (k: string, p: string) =>
    row(
      k,
      <span className="flex items-center gap-2">
        <Mono className="truncate">{tildify(p, home)}</Mono>
        <Button variant="ghost" size="icon" className="size-7" title="Show in Finder" onClick={() => post('/api/reveal', { path: p })}>
          <FolderOpen className="size-3.5" />
        </Button>
      </span>,
    )
  return (
    <>
      <PageHeader title="Settings" description="How AgentACL is set up on this Mac." />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>This Mac</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[9rem_1fr] gap-x-4 gap-y-2.5 text-sm">
              {row('User', s.human)}
              {row('Computer', s.hostname ?? '—')}
              {row('Machine id', <Mono className="break-all">{s.machine}</Mono>)}
              {row('AgentACL', `v${s.version}`)}
            </dl>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Enforcement</CardTitle>
            <CardDescription>What actually stops agents.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 text-sm">
            <div className="flex gap-3">
              <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-emerald-500" />
              <div>
                <div className="font-medium">macOS Seatbelt — active</div>
                <div className="text-muted-foreground">{s.backend.description}. File and program rules are enforced by the kernel; network rules by AgentACL’s local proxy, which is the only way out of the sandbox.</div>
              </div>
            </div>
            <div className="flex gap-3">
              <CircleSlash className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
              <div>
                <div className="font-medium">Endpoint Security — not available</div>
                <div className="text-muted-foreground">{s.endpoint_security.description}</div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Files</CardTitle>
            <CardDescription>Everything is stored locally. Agents can’t read or change these.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[9rem_1fr] gap-x-4 gap-y-2 text-sm">
              {pathRow('Your rules', s.paths.user_policy)}
              {pathRow('Configuration', s.paths.config)}
              {pathRow('Audit database', s.paths.database)}
              {pathRow('State', s.paths.state)}
            </dl>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Command line</CardTitle>
            <CardDescription>Everything here is also available in the terminal.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <Command>agentacl run -- claude</Command>
            <Command>agentacl restart</Command>
            <Command>agentacl stop</Command>
            <Command>agentacl status</Command>
            <Command>agentacl discover</Command>
            <Command>agentacl policy check</Command>
            <Command>agentacl events --blocked</Command>
            <Command>agentacl policy trust</Command>
          </CardContent>
        </Card>
      </div>
    </>
  )
}
