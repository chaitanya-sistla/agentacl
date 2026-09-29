import * as React from 'react'
import { CheckCircle2, FlaskConical, XCircle } from 'lucide-react'
import { post, type EvalResp } from '@/lib/api'
import { policyLabel } from '@/lib/format'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input, NativeSelect } from '@/components/ui/input'
import { ErrorText, Mono } from '@/components/app/common'
import type { PolicyDraft } from './draft'

const EXAMPLES: Record<string, string[]> = {
  path: ['~/.ssh/id_ed25519', '~/.aws/credentials', '/etc/hosts'],
  exec: ['git push', 'terraform apply', 'rm -rf /'],
  host: ['api.github.com', 'registry.npmjs.org', '169.254.169.254:80'],
}

export function TestAccess({ draft, home }: { draft: PolicyDraft; home: string }) {
  const [kind, setKind] = React.useState<'path' | 'exec' | 'host'>('path')
  const [action, setAction] = React.useState('read')
  const [value, setValue] = React.useState('')
  const [res, setRes] = React.useState<(EvalResp & { asked: string }) | null>(null)
  const [err, setErr] = React.useState<string | null>(null)
  const expand = (v: string) => (v.startsWith('~/') ? home + v.slice(1) : v)
  const run = async (v = value) => {
    setErr(null)
    if (!v.trim()) return
    const request = kind === 'path' ? { kind, path: expand(v.trim()), action } : kind === 'exec' ? { kind, command: v.trim() } : { kind, host: v.trim() }
    try {
      const r = await post<EvalResp>('/api/evaluate', { ...draft.draftBody(), request })
      setRes({ ...r, asked: v })
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const allowed = res?.effect === 'allow'
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FlaskConical className="size-4" /> Test access
        </CardTitle>
        <CardDescription>Ask “could an agent do this?” against the rules as they are now{draft.dirty ? ', including your unsaved changes' : ''}.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <form
          className="flex flex-col gap-2 md:flex-row"
          onSubmit={(e) => {
            e.preventDefault()
            run()
          }}
        >
          <NativeSelect value={kind} onChange={(e) => { setKind(e.target.value as any); setRes(null) }} className="md:w-48">
            <option value="path">A file or folder</option>
            <option value="exec">A command</option>
            <option value="host">A website / host</option>
          </NativeSelect>
          {kind === 'path' && (
            <NativeSelect value={action} onChange={(e) => setAction(e.target.value)} className="md:w-36">
              <option value="read">Read it</option>
              <option value="write">Change it</option>
              <option value="rename">Rename/move it</option>
            </NativeSelect>
          )}
          <Input className="flex-1 font-mono text-[13px]" value={value} onChange={(e) => setValue(e.target.value)} placeholder={EXAMPLES[kind][0]} />
          <Button type="submit" variant="brand">
            Test
          </Button>
        </form>
        <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
          Try:
          {EXAMPLES[kind].map((x) => (
            <button key={x} className="rounded border px-2 py-0.5 font-mono hover:bg-accent" onClick={() => { setValue(x); run(x) }}>
              {x}
            </button>
          ))}
        </div>
        <ErrorText error={err} />
        {res && (
          <div className={allowed ? 'rounded-lg border border-emerald-500/30 bg-emerald-500/[0.06] p-4' : 'rounded-lg border border-red-500/30 bg-red-500/[0.06] p-4'}>
            <div className="flex items-center gap-2 font-medium">
              {allowed ? <CheckCircle2 className="size-5 text-emerald-600" /> : <XCircle className="size-5 text-red-600" />}
              {allowed ? 'Allowed' : res.effect === 'ask' ? 'Blocked (needs approval)' : 'Blocked'} — <Mono>{res.asked}</Mono>
            </div>
            <div className="mt-1 text-sm">{res.reason}</div>
            <div className="mt-1 text-xs text-muted-foreground">
              Decided by {policyLabel[res.policy] ?? res.policy}
              {res.rule_id && !res.rule_id.includes('/') ? ` · rule ${res.rule_id}` : ''}
            </div>
            {res.trace.length > 0 && (
              <details className="mt-3 text-xs">
                <summary className="cursor-pointer text-muted-foreground">How this was decided ({res.trace.length} steps)</summary>
                <ol className="mt-2 flex list-decimal flex-col gap-0.5 pl-5 font-mono">
                  {res.trace.map((t, i) => (
                    <li key={i}>{t}</li>
                  ))}
                </ol>
              </details>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
