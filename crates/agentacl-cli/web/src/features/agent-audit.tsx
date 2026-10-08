import * as React from 'react'
import { AlertTriangle, CheckCircle2, Info, ShieldAlert } from 'lucide-react'
import { get, type AuditItem, type AuditReport, type Project } from '@/lib/api'
import { baseName } from '@/lib/format'
import { useData } from '@/lib/hooks'
import { useApp } from '@/lib/app-context'
import { Badge } from '@/components/ui/badge'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { NativeSelect } from '@/components/ui/input'
import { ErrorText, Loading, Mono } from '@/components/app/common'
import { cn } from '@/lib/utils'

const SEV = {
  high: { label: 'High', icon: ShieldAlert, tone: 'border-red-500/40 bg-red-500/[0.05]', badge: 'danger' as const },
  medium: { label: 'Medium', icon: AlertTriangle, tone: 'border-amber-500/40 bg-amber-500/[0.05]', badge: 'warning' as const },
  info: { label: 'Info', icon: Info, tone: 'border-sky-500/30 bg-sky-500/[0.04]', badge: 'info' as const },
}

const OPEN = new Set(['readable', 'reachable', 'granted'])

function Row({ label, items, empty }: { label: string; items: AuditItem[]; empty: string }) {
  return (
    <div className="grid grid-cols-[8.5rem_1fr] gap-3 py-1.5 text-sm">
      <div className="text-muted-foreground">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {items.length === 0 ? (
          <span className="text-muted-foreground">{empty}</span>
        ) : (
          items.map((i) => (
            <Badge key={i.name + i.detail} variant={OPEN.has(i.status) ? 'danger' : i.status === 'asks' ? 'warning' : 'secondary'} title={i.detail}>
              {i.name} · {i.status}
            </Badge>
          ))
        )}
      </div>
    </div>
  )
}

/** "What can this agent reach?": `agentacl audit` in the console. */
export function AgentAudit() {
  const { agents } = useApp()
  const [agent, setAgent] = React.useState('claude-code')
  const projects = useData(() => get<{ projects: Project[] }>('/api/projects'))
  const known = (projects.data?.projects ?? []).filter((p) => p.exists)
  const [project, setProject] = React.useState<string | null>(null)
  // Default to the first known project (its rules and MCP servers count).
  const chosen = project ?? known[0]?.path ?? ''
  const d = useData(() => (projects.data ? get<AuditReport>('/api/audit', { agent, project: chosen }) : new Promise<AuditReport>(() => {})), [agent, chosen, !!projects.data])
  const r = d.data
  const count = (s: string) => r?.findings.filter((f) => f.severity === s).length ?? 0
  return (
    <Card className="mt-6">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div>
          <CardTitle>What can this agent reach?</CardTitle>
          <CardDescription>
            Credentials, cloud drives, company data services and MCP servers, checked against the rules it would run under. Same as <Mono>agentacl audit</Mono>. No secret values are shown.
          </CardDescription>
        </div>
        <div className="flex flex-wrap gap-2">
          <NativeSelect value={agent} onChange={(e) => setAgent(e.target.value)}>
            {agents.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </NativeSelect>
          <NativeSelect value={chosen} onChange={(e) => setProject(e.target.value)}>
            {known.map((p) => (
              <option key={p.path} value={p.path}>
                in {baseName(p.path)}
              </option>
            ))}
            <option value="">no project</option>
          </NativeSelect>
        </div>
      </CardHeader>
      <div className="flex flex-col gap-3 px-6 pb-6">
        <ErrorText error={d.error} />
        {!r ? (
          <Loading />
        ) : (
          <>
            <div className="flex flex-wrap gap-2 text-sm">
              <Badge variant={count('high') ? 'danger' : 'success'}>{count('high')} high</Badge>
              <Badge variant={count('medium') ? 'warning' : 'secondary'}>{count('medium')} medium</Badge>
              <Badge variant="secondary">{count('info')} info</Badge>
            </div>
            {r.findings.length === 0 ? (
              <div className="flex items-center gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/[0.05] p-3 text-sm">
                <CheckCircle2 className="size-4 text-emerald-600" /> Nothing to fix: no credential, cloud drive or company data service is open to this agent.
              </div>
            ) : (
              <ul className="flex flex-col gap-2">
                {r.findings.map((f, i) => {
                  const S = SEV[f.severity]
                  return (
                    <li key={i} className={cn('rounded-md border p-3 text-sm', S.tone)}>
                      <div className="flex items-start gap-2">
                        <S.icon className="mt-0.5 size-4 shrink-0" />
                        <div className="min-w-0">
                          <div className="font-medium">
                            {f.title} <Badge variant={S.badge}>{S.label}</Badge>
                          </div>
                          <p className="mt-1 text-muted-foreground">{f.detail}</p>
                          <p className="mt-1">
                            <span className="font-medium">Fix:</span> {f.fix}
                          </p>
                        </div>
                      </div>
                    </li>
                  )
                })}
              </ul>
            )}
            <div className="divide-y rounded-md border px-3">
              <Row label="Credentials" items={r.credentials} empty="none found" />
              <Row label="Cloud drives" items={r.cloud_drives} empty="none found" />
              <Row label="Data services" items={r.data_services.filter((s) => s.status !== 'blocked')} empty={`all ${r.data_services.length} checked are blocked`} />
              <Row label="MCP servers" items={r.mcp_servers} empty="none configured" />
              <Row label="Keychain" items={[r.keychain]} empty="" />
              <Row label="Grants" items={r.grants} empty="none from the console" />
            </div>
            <p className="text-xs text-muted-foreground">Checked with the console’s environment; a token set only in the shell you start agents from changes the keychain answer.</p>
          </>
        )}
      </div>
    </Card>
  )
}
