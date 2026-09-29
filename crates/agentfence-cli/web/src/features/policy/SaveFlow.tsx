import * as React from 'react'
import { AlertTriangle, CheckCircle2, FileDiff, Loader2, Minus, Plus, RotateCw, Save, Undo2 } from 'lucide-react'
import { ApiError, post, type PreviewResp, type SaveResp, type Session } from '@/lib/api'
import { useApp } from '@/lib/app-context'
import { baseName, tildify } from '@/lib/format'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Alert } from '@/components/ui/misc'
import { useToast } from '@/components/ui/toast'
import { ErrorText, Mono } from '@/components/app/common'
import { useSessionActions } from '@/features/session-actions'
import type { PolicyDraft } from './draft'

const SECTION_WORDS: Record<string, [string, string]> = {
  'filesystem.read': ['read', 'read'],
  'filesystem.write': ['change', 'change'],
  'process.exec': ['run', 'run'],
  'network.connect': ['connect to', 'connect to'],
  'network.listen': ['listen on', 'listen on'],
}

/** "deny filesystem.read /x/** enforced[ except a, b]" → words */
function describe(key: string): { allow: boolean; text: string; pattern: string } {
  const m = key.match(/^(\w+) (\S+) (.*?) (enforced|enforced-coarse|observed|requires-es)(?: except (.*))?$/)
  if (!m) return { allow: false, text: key, pattern: '' }
  const [, effect, section, pat, , except] = m
  const pattern = except ? `${pat} (except ${except})` : pat
  const verb = SECTION_WORDS[section]?.[0] ?? section
  const allow = effect === 'allow'
  return { allow, text: allow ? `Agents can ${verb}` : effect === 'ask' ? `Agents need approval to ${verb}` : `Agents can’t ${verb}`, pattern }
}

const needsConfirm = (p: PreviewResp | null) => !!p && (!!p.effective?.project_unreadable || (p.unreadable_projects?.length ?? 0) > 0)

type Phase = { k: 'closed' } | { k: 'review'; p: PreviewResp | null; err?: string } | { k: 'saving' } | { k: 'done'; file: string; affected: Session[] }

export function SaveBar({ draft, onSaved }: { draft: PolicyDraft; onSaved?: () => void }) {
  const { home } = useApp()
  const toast = useToast()
  const [phase, setPhase] = React.useState<Phase>({ k: 'closed' })
  const [confirmUnreadable, setConfirmUnreadable] = React.useState(false)
  const [saveErr, setSaveErr] = React.useState<string | null>(null)
  const [conflict, setConflict] = React.useState<SaveResp | null>(null)
  const [showDiff, setShowDiff] = React.useState(false)
  const [restarted, setRestarted] = React.useState<Set<string>>(new Set())
  const actions = useSessionActions()
  const file = draft.loaded?.file ?? ''

  const review = async () => {
    setSaveErr(null)
    setConflict(null)
    setConfirmUnreadable(false)
    setShowDiff(false)
    setPhase({ k: 'review', p: null })
    try {
      const body = draft.draftBody()
      // Always send the draft, even if unchanged (e.g. first save of the starter rules).
      const p = await post<PreviewResp>('/api/policy/preview', draft.mode === 'doc' ? { ...body, doc: draft.doc } : { ...body, yaml: draft.yaml })
      setPhase({ k: 'review', p })
    } catch (e: any) {
      setPhase({ k: 'review', p: null, err: e.message })
    }
  }

  const save = async (baseOverride?: string) => {
    if (phase.k !== 'review' || !phase.p?.ok) return
    const prev = phase
    setSaveErr(null)
    setPhase({ k: 'saving' })
    try {
      const r = await post<SaveResp>('/api/policy/save', {
        ...draft.draftBody(),
        yaml: prev.p!.yaml,
        doc: undefined,
        base_sha256: baseOverride ?? draft.loaded?.sha256 ?? null,
        confirm: confirmUnreadable ? ['project-unreadable'] : [],
      })
      if (!r.ok) {
        setPhase(prev)
        if (r.conflict) {
          // Re-review against what is on disk now, so the overwrite is informed.
          setConflict(r)
          try {
            const body = draft.draftBody()
            const p2 = await post<PreviewResp>('/api/policy/preview', draft.mode === 'doc' ? { ...body, doc: draft.doc } : { ...body, yaml: draft.yaml })
            setPhase({ k: 'review', p: p2 })
            setShowDiff(true)
          } catch {}
        }
        else if (r.needs_confirm) setSaveErr('Confirm below that agents will lose read access to the project.')
        else setSaveErr(r.error ?? 'Save failed')
        return
      }
      setRestarted(new Set())
      setPhase({ k: 'done', file, affected: r.affected_sessions ?? [] })
      await draft.reload()
      onSaved?.()
    } catch (e: any) {
      setPhase(prev)
      setSaveErr(e instanceof ApiError ? e.message : String(e))
    }
  }

  const restartOne = async (s: Session) => {
    if (await actions.restart(s)) setRestarted((x) => new Set(x).add(s.session))
  }
  const restartAll = async (list: Session[]) => {
    for (const s of list.filter((s) => s.restartable && !restarted.has(s.session))) await restartOne(s)
  }

  const p = phase.k === 'review' ? phase.p : null
  const firstSave = !!draft.loaded && !draft.loaded.exists && draft.loaded.scope === 'user'
  const visible = draft.dirty || firstSave

  return (
    <>
      {visible && (
        <div className="sticky bottom-4 z-20 mt-6 flex flex-wrap items-center gap-3 rounded-xl border bg-popover/95 px-4 py-3 shadow-lg backdrop-blur">
          <span className="relative flex size-2.5">
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-amber-400 opacity-70" />
            <span className="relative inline-flex size-2.5 rounded-full bg-amber-500" />
          </span>
          <div className="flex-1 text-sm">
            <div className="font-medium">{draft.dirty ? 'You have unsaved changes' : 'These starter rules aren’t saved yet'}</div>
            <div className="text-xs text-muted-foreground">
              Nothing changes for agents until you save to <Mono>{tildify(file, home)}</Mono>.
            </div>
          </div>
          {draft.dirty && (
            <Button variant="ghost" onClick={draft.discard}>
              <Undo2 /> Discard
            </Button>
          )}
          <Button variant="brand" onClick={review}>
            <Save /> Review & save
          </Button>
        </div>
      )}

      <Dialog open={phase.k === 'review' || phase.k === 'saving'} onOpenChange={(o) => !o && phase.k !== 'saving' && setPhase({ k: 'closed' })}>
        <DialogContent wide>
          <DialogHeader>
            <DialogTitle>Review changes before saving</DialogTitle>
            <DialogDescription>
              Saving writes <Mono>{tildify(file, home)}</Mono>. A backup of the previous version is kept next to it.
            </DialogDescription>
          </DialogHeader>
          {phase.k === 'review' && !p && !phase.err && (
            <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground justify-center">
              <Loader2 className="size-4 animate-spin" /> Checking the rules…
            </div>
          )}
          {phase.k === 'review' && phase.err && <ErrorText error={phase.err} />}
          {p && !p.ok && (
            <Alert variant="danger">
              <AlertTriangle />
              <div>
                <div className="font-medium">These rules can’t be saved</div>
                <div className="mt-1 font-mono text-xs whitespace-pre-wrap">{p.error}</div>
              </div>
            </Alert>
          )}
          {p?.ok && (
            <div className="flex flex-col gap-4">
              <div>
                <div className="mb-2 text-sm font-medium">What changes for agents</div>
                {(p.effective_diff?.added.length ?? 0) + (p.effective_diff?.removed.length ?? 0) === 0 ? (
                  <div className="rounded-md border px-3 py-2 text-sm text-muted-foreground">No change in what agents can do{firstSave ? ' — this saves the starter rules as your own file so you can edit them.' : ' (formatting or comments only).'}</div>
                ) : (
                  <ul className="flex max-h-64 flex-col divide-y overflow-y-auto rounded-md border">
                    {p.effective_diff!.added.map(({ key: k, agents }) => {
                      const d = describe(k)
                      return (
                        <li key={'a' + k} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
                          <Plus className="size-3.5 shrink-0 text-emerald-600" />
                          <Badge variant={d.allow ? 'success' : 'danger'}>{d.allow ? 'Allow' : 'Block'}</Badge>
                          <span>{d.text}</span>
                          <Mono className="truncate">{d.pattern}</Mono>
                          {agents.length > 0 && <span className="text-xs text-muted-foreground">· only {agents.join(', ')}</span>}
                        </li>
                      )
                    })}
                    {p.effective_diff!.removed.map(({ key: k, agents }) => {
                      const d = describe(k)
                      return (
                        <li key={'r' + k} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm text-muted-foreground">
                          <Minus className="size-3.5 shrink-0 text-red-600" />
                          <Badge variant="outline">Removed</Badge>
                          <span className="line-through">{d.text}</span>
                          <Mono className="truncate line-through">{d.pattern}</Mono>
                          {agents.length > 0 && <span className="text-xs">· only {agents.join(', ')}</span>}
                        </li>
                      )
                    })}
                  </ul>
                )}
              </div>
              {(p.effective?.warnings.length ?? 0) > 0 && (
                <Alert variant="warning">
                  <AlertTriangle />
                  <ul className="flex list-disc flex-col gap-1 pl-4">
                    {p.effective!.warnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                </Alert>
              )}
              {p.comments_lost && (
                <Alert variant="info">
                  <AlertTriangle />
                  <div>Comments in the current file will be removed because you edited it visually. Use the YAML tab to keep them.</div>
                </Alert>
              )}
              {needsConfirm(p) && (
                <Alert variant="danger">
                  <AlertTriangle />
                  <div className="flex flex-col gap-2">
                    {(p.unreadable_projects?.length ?? 0) > 0 && (
                      <div>
                        Agents couldn’t read these projects:
                        <ul className="mt-1 list-disc pl-5 font-mono text-xs">
                          {p.unreadable_projects!.slice(0, 8).map((x) => (
                            <li key={x}>{tildify(x, home)}</li>
                          ))}
                          {p.unreadable_projects!.length > 8 && <li>…and {p.unreadable_projects!.length - 8} more</li>}
                        </ul>
                      </div>
                    )}
                    <label className="flex items-start gap-2">
                      <input type="checkbox" className="mt-1" checked={confirmUnreadable} onChange={(e) => setConfirmUnreadable(e.target.checked)} />
                      <span>With these rules agents can’t read the project folder, so they won’t be able to work there. I understand.</span>
                    </label>
                  </div>
                </Alert>
              )}
              <div>
                <button className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground" onClick={() => setShowDiff(!showDiff)}>
                  <FileDiff className="size-4" /> {showDiff ? 'Hide' : 'Show'} file changes
                </button>
                {showDiff && (
                  <pre className="mt-2 max-h-72 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs leading-5">
                    {p.file_diff?.map((l, i) => (
                      <div key={i} className={l.op === '+' ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300' : l.op === '-' ? 'bg-red-500/10 text-red-700 dark:text-red-300' : 'text-muted-foreground'}>
                        {l.op} {l.line}
                      </div>
                    ))}
                  </pre>
                )}
              </div>
              <Alert variant="info">
                <RotateCw />
                <div>Agents already running keep the rules they started with. After saving you can restart them here to apply the change — they resume where they left off.</div>
              </Alert>
            </div>
          )}
          {conflict && (
            <Alert variant="warning">
              <AlertTriangle />
              <div className="flex flex-col gap-2">
                <div>{conflict.error} The changes and file diff above now compare your draft with the version on disk.</div>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => { setPhase({ k: 'closed' }); draft.reload(); toast({ kind: 'info', title: 'Loaded the latest version', body: 'Your draft was discarded.' }) }}>
                    Load latest (discard mine)
                  </Button>
                  <Button size="sm" variant="destructive" onClick={() => save(conflict.current_sha256)}>
                    Save mine anyway
                  </Button>
                </div>
              </div>
            </Alert>
          )}
          <ErrorText error={saveErr} />
          <DialogFooter>
            <Button variant="ghost" onClick={() => setPhase({ k: 'closed' })} disabled={phase.k === 'saving'}>
              Keep editing
            </Button>
            <Button variant="brand" onClick={() => save()} disabled={phase.k === 'saving' || !p?.ok || (needsConfirm(p) && !confirmUnreadable)}>
              {phase.k === 'saving' ? <Loader2 className="animate-spin" /> : <Save />} Save rules
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={phase.k === 'done'} onOpenChange={(o) => !o && setPhase({ k: 'closed' })}>
        <DialogContent>
          {phase.k === 'done' && (
            <>
              <DialogHeader>
                <div className="mb-1 grid size-10 place-items-center rounded-full bg-emerald-500/10">
                  <CheckCircle2 className="size-5 text-emerald-600" />
                </div>
                <DialogTitle>Rules saved</DialogTitle>
                <DialogDescription>
                  Written to <Mono>{tildify(phase.file, home)}</Mono>.
                </DialogDescription>
              </DialogHeader>
              {phase.affected.length === 0 ? (
                <div className="rounded-md border bg-muted/40 px-4 py-3 text-sm">
                  <div className="font-medium">No restart needed</div>
                  <div className="mt-0.5 text-muted-foreground">No protected agent is running with these rules. Every agent you start with <Mono>agentfence run</Mono> from now on uses them automatically.</div>
                </div>
              ) : (
                <div className="flex flex-col gap-3">
                  <Alert variant="warning">
                    <AlertTriangle />
                    <div>
                      <div className="font-medium">
                        {phase.affected.length} running agent{phase.affected.length > 1 ? 's' : ''} may still be using the old rules
                      </div>
                      <div className="mt-0.5">macOS fixes an agent’s sandbox when it starts, so a restart is needed to apply the change. Agents that support it, like Claude Code, pick up the conversation where they left off.</div>
                    </div>
                  </Alert>
                  <ul className="flex flex-col divide-y rounded-md border">
                    {phase.affected.map((s) => (
                      <li key={s.session} className="flex items-center gap-3 px-3 py-2.5 text-sm">
                        <div className="min-w-0 flex-1">
                          <div className="font-medium">{s.agent_name ?? s.agent}</div>
                          <div className="truncate text-xs text-muted-foreground">
                            {baseName(s.project)} · pid {s.pid}
                            {s.maybe ? ' · may use these rules (started by an older AgentFence)' : ''}
                          </div>
                        </div>
                        {restarted.has(s.session) ? (
                          <Badge variant="success">Restarting</Badge>
                        ) : s.restartable ? (
                          <Button size="sm" variant="outline" disabled={actions.busy === s.session} onClick={() => restartOne(s)}>
                            <RotateCw /> Restart
                          </Button>
                        ) : (
                          <span className="text-right text-xs text-muted-foreground">Quit and run again</span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <DialogFooter>
                <Button variant="ghost" onClick={() => setPhase({ k: 'closed' })}>
                  {phase.affected.length ? 'Restart later' : 'Done'}
                </Button>
                {phase.affected.some((s) => s.restartable && !restarted.has(s.session)) && (
                  <Button variant="brand" onClick={() => restartAll(phase.affected)}>
                    <RotateCw /> Restart all now
                  </Button>
                )}
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  )
}
