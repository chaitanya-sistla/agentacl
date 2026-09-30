import { Lock, ShieldCheck } from 'lucide-react'
import { get, type Builtins as B } from '@/lib/api'
import { useData } from '@/lib/hooks'
import { groupLabel } from '@/lib/format'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Switch, Tooltip } from '@/components/ui/misc'
import { Loading, Mono } from '@/components/app/common'
import type { PolicyDraft } from './draft'

export function BuiltinProtections({ draft }: { draft: PolicyDraft }) {
  const b = useData(() => get<B>('/api/builtins'))
  if (!b.data) return <Loading />
  const disabled = draft.doc?.builtin?.disable ?? []
  const set = (id: string, on: boolean) =>
    draft.updateDoc((d) => {
      const cur = d.builtin?.disable ?? []
      const next = on ? cur.filter((x) => x !== id) : [...new Set([...cur, id])]
      return { ...d, builtin: next.length ? { disable: next } : null }
    })
  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Secret protection</CardTitle>
          <CardDescription>On for every agent, in every project. Agents can’t read or change these — even inside the project. Switch a group off only if your agents truly need it.</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {b.data.groups.map((g) => {
            const on = !disabled.includes(g.id)
            return (
              <div key={g.id} className="flex gap-3 rounded-lg border p-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 font-medium">
                    {groupLabel[g.id] ?? g.id}
                    {!on && <Badge variant="warning">Off</Badge>}
                  </div>
                  <div className="mt-0.5 text-xs text-muted-foreground">{g.reason}</div>
                  <details className="mt-2 text-xs">
                    <summary className="cursor-pointer text-muted-foreground hover:text-foreground">{g.patterns.length} path pattern{g.patterns.length > 1 ? 's' : ''}</summary>
                    <ul className="mt-1.5 flex flex-col gap-0.5">
                      {g.patterns.map((p) => (
                        <li key={p}>
                          <Mono className="text-[11.5px] break-all">{p}</Mono>
                        </li>
                      ))}
                    </ul>
                  </details>
                </div>
                <Tooltip content={on ? 'Protected — click to allow agents access' : 'Not protected — click to protect'}>
                  <span>
                    <Switch checked={on} onCheckedChange={(v) => set(g.id, v)} />
                  </span>
                </Tooltip>
              </div>
            )
          })}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Always on</CardTitle>
          <CardDescription>These keep the sandbox itself safe and can’t be switched off.</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {b.data.always_on.map((g) => (
            <div key={g.id} className="flex gap-3 rounded-lg border bg-muted/30 p-4">
              <ShieldCheck className="mt-0.5 size-4 shrink-0 text-emerald-500" />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 font-medium">
                  {groupLabel[g.id] ?? g.id} <Lock className="size-3 text-muted-foreground" />
                </div>
                <div className="mt-0.5 text-xs text-muted-foreground">{g.reason}</div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}
