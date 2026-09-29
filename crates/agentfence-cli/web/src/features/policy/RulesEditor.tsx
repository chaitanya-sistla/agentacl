import * as React from 'react'
import { FolderSearch, Info, Lock, Plus, Trash2 } from 'lucide-react'
import type { FsNode, RawRule, Scope } from '@/lib/api'
import { useApp } from '@/lib/app-context'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input, NativeSelect } from '@/components/ui/input'
import { Tooltip } from '@/components/ui/misc'
import { useToast } from '@/components/ui/toast'
import { cn } from '@/lib/utils'
import { Mono } from '@/components/app/common'
import { SECTIONS, rulesOf, setRules, type SectionDef } from './sections'
import { PathPicker } from './PathPicker'
import type { PolicyDraft } from './draft'

const EFFECT_OPTS = [
  { v: '', l: 'Not set (use built-in)' },
  { v: 'allow', l: 'Allow' },
  { v: 'deny', l: 'Block' },
  { v: 'ask', l: 'Needs approval (blocked for now)' },
]

export function RulesEditor({ draft, scope, pickerStart }: { draft: PolicyDraft; scope: Scope; pickerStart: string }) {
  const { agents } = useApp()
  const doc = draft.doc
  if (!doc) return null
  const groups = ['Files & folders', 'Programs', 'Network'] as const
  const matchAgents = doc.match_?.agents ?? []

  return (
    <div className="flex flex-col gap-6">
      {groups.map((g) => (
        <div key={g}>
          <h3 className="mb-3 text-sm font-semibold tracking-wide text-muted-foreground uppercase">{g}</h3>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {SECTIONS.filter((s) => s.group === g && (s.key !== 'process.allow' || rulesOf(doc, s.key).length > 0)).map((s) => (
              <SectionCard key={s.key} def={s} draft={draft} scope={scope} pickerStart={pickerStart} />
            ))}
          </div>
        </div>
      ))}

      <div>
        <h3 className="mb-3 text-sm font-semibold tracking-wide text-muted-foreground uppercase">When no rule matches</h3>
        <Card>
          <CardContent className="grid grid-cols-1 gap-4 pt-5 md:grid-cols-3">
            {(['filesystem', 'network', 'process'] as const).map((k) => (
              <label key={k} className="flex flex-col gap-1.5 text-sm">
                <span className="font-medium">{k === 'filesystem' ? 'Files outside the project' : k === 'network' ? 'Network' : 'Programs'}</span>
                <NativeSelect
                  value={doc.defaults[k] ?? ''}
                  onChange={(e) => draft.updateDoc((d) => ({ ...d, defaults: { ...d.defaults, [k]: e.target.value || null } }))}
                >
                  {EFFECT_OPTS.filter((o) => o.v === (doc.defaults[k] ?? '') || ((scope === 'user' || o.v !== 'allow') && (k !== 'process' || o.v === '' || o.v === 'allow'))).map((o) => (
                    <option key={o.v} value={o.v}>
                      {o.l}
                    </option>
                  ))}
                </NativeSelect>
              </label>
            ))}
            <p className="text-xs text-muted-foreground md:col-span-3">The strictest setting across all rule files wins. Built-in: files outside the project and network are blocked; programs are allowed. Blocking every program by default isn’t supported by the macOS sandbox — block specific programs instead.</p>
          </CardContent>
        </Card>
      </div>

      {scope === 'user' && (
        <div>
          <h3 className="mb-3 text-sm font-semibold tracking-wide text-muted-foreground uppercase">Applies to</h3>
          <Card>
            <CardContent className="flex flex-col gap-3 pt-5 text-sm">
              <div className="flex flex-wrap gap-2">
                <label className="flex items-center gap-2 rounded-md border px-3 py-1.5">
                  <input
                    type="checkbox"
                    checked={matchAgents.length === 0}
                    onChange={() => draft.updateDoc((d) => ({ ...d, match_: d.match_?.projects?.length ? { ...d.match_, agents: [] } : null }))}
                  />
                  Every agent
                </label>
                {agents.map((a) => (
                  <label key={a.id} className="flex items-center gap-2 rounded-md border px-3 py-1.5">
                    <input
                      type="checkbox"
                      checked={matchAgents.includes(a.id)}
                      onChange={(e) =>
                        draft.updateDoc((d) => {
                          const cur = d.match_?.agents ?? []
                          const agentsNext = e.target.checked ? [...cur, a.id] : cur.filter((x) => x !== a.id)
                          const projects = d.match_?.projects ?? []
                          return { ...d, match_: agentsNext.length || projects.length ? { agents: agentsNext, projects } : null }
                        })
                      }
                    />
                    {a.name}
                  </label>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">Built-in protections always apply to every agent.</p>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}

function SectionCard({ def, draft, scope, pickerStart }: { def: SectionDef; draft: PolicyDraft; scope: Scope; pickerStart: string }) {
  const rules = rulesOf(draft.doc!, def.key)
  const locked = scope === 'project' && def.allow
  const [pattern, setPattern] = React.useState('')
  const [reason, setReason] = React.useState('')
  const [picker, setPicker] = React.useState(false)
  const toast = useToast()

  const add = (p: string, r = reason) => {
    const v = p.trim()
    if (!v) return
    if (rules.some((x) => x.pattern === v)) {
      toast({ kind: 'info', title: 'Already in this list', body: v })
      return
    }
    const rule: RawRule = { kind: def.kind, pattern: v, except: [], id: null, reason: r.trim() || null }
    draft.updateDoc((d) => setRules(d, def.key, [...rulesOf(d, def.key), rule]))
    setPattern('')
    setReason('')
  }
  const remove = (i: number) => draft.updateDoc((d) => setRules(d, def.key, rulesOf(d, def.key).filter((_, j) => j !== i)))
  const picked = (n: FsNode) => {
    const k = def.key.split('.')[1] as keyof FsNode['actions']
    const a = n.actions[k]
    if (!a || a.unavailable || !a.rule) {
      toast({ kind: 'error', title: 'Can’t add this path', body: a?.unavailable ?? 'Not available' })
      return
    }
    setPattern(a.rule)
  }

  return (
    <Card className={cn(locked && 'opacity-60')}>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <span className={cn('size-2 rounded-full', def.tone === 'allow' ? 'bg-emerald-500' : def.tone === 'deny' ? 'bg-red-500' : 'bg-violet-500')} />
          <CardTitle className="text-[15px]">{def.title}</CardTitle>
          <Badge variant="secondary" className="ml-auto">
            {rules.length}
          </Badge>
        </div>
        <CardDescription>{def.help}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {locked ? (
          <div className="flex items-start gap-2 rounded-md bg-muted px-3 py-2 text-xs text-muted-foreground">
            <Lock className="mt-0.5 size-3.5 shrink-0" /> Project rules can only restrict. Add allows in “Your rules” so a cloned repository can’t grant itself access.
          </div>
        ) : null}
        {rules.length > 0 && (
          <ul className="flex flex-col divide-y rounded-md border">
            {rules.map((r, i) => (
              <li key={i} className="group flex items-start gap-2 px-3 py-2">
                <div className="min-w-0 flex-1">
                  <Mono className="block break-all">{r.pattern}</Mono>
                  {(r.reason || r.except.length > 0) && (
                    <div className="mt-0.5 text-xs text-muted-foreground">
                      {r.reason}
                      {r.except.length > 0 && <span> · except {r.except.join(', ')}</span>}
                    </div>
                  )}
                </div>
                <Tooltip content="Remove rule">
                  <Button variant="ghost" size="icon" className="size-7 opacity-50 group-hover:opacity-100" onClick={() => remove(i)} disabled={locked}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </Tooltip>
              </li>
            ))}
          </ul>
        )}
        {!locked && (
          <form
            className="flex flex-col gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              add(pattern)
            }}
          >
            <div className="flex gap-2">
              <Input className="font-mono text-[13px]" placeholder={def.placeholder} value={pattern} onChange={(e) => setPattern(e.target.value)} />
              {def.kind === 'path' && (
                <Tooltip content="Browse files and folders">
                  <Button type="button" variant="outline" size="icon" onClick={() => setPicker(true)}>
                    <FolderSearch />
                  </Button>
                </Tooltip>
              )}
            </div>
            {pattern && (
              <div className="flex gap-2">
                <Input placeholder="Why? (shown when something is blocked — optional)" value={reason} onChange={(e) => setReason(e.target.value)} />
                <Button type="submit" variant="secondary">
                  <Plus /> Add
                </Button>
              </div>
            )}
            {def.kind === 'path' && !pattern && (
              <p className="flex items-center gap-1 text-xs text-muted-foreground">
                <Info className="size-3" /> <Mono>/**</Mono> means “everything inside”. Use <Mono>${'{HOME}'}</Mono> and <Mono>${'{PROJECT}'}</Mono> for portable rules.
              </p>
            )}
          </form>
        )}
      </CardContent>
      {def.kind === 'path' && <PathPicker open={picker} onOpenChange={setPicker} start={pickerStart} body={draft.draftBody} onPick={picked} />}
    </Card>
  )
}
