import * as React from 'react'
import { Check, Loader2 } from 'lucide-react'
import { post, type Category } from '@/lib/api'
import { useApp } from '@/lib/app-context'
import { baseName, tildify } from '@/lib/format'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { NativeSelect, Label } from '@/components/ui/input'
import { useToast } from '@/components/ui/toast'
import { ErrorText, Mono } from '@/components/app/common'
import { CategoryBadge } from '@/components/app/charts'

/** What a request asked for, and who asked. */
export interface AccessIntent {
  kind: 'file' | 'site'
  /** Folder (files) or host (sites). */
  target: string
  /** Agent ids that asked; the first is the default. */
  agents: string[]
  /** Projects they asked from; the first is the default. */
  projects: string[]
  /** The request included a change, not only a read. */
  write?: boolean
  /** Files: the exact paths that were refused, who asked, and whether for a change. */
  files?: { path: string; agents: string[]; write: boolean }[]
  /** More paths were refused than listed. */
  truncated?: boolean
  category?: Category
}

const EVERY = '*'

/**
 * Allow what a request asked for, for one agent or all, in one project or
 * everywhere. Saved to an access file in the AgentACL config directory.
 */
export function AccessDialog({ intent, onClose, onDone }: { intent: AccessIntent | null; onClose: () => void; onDone: () => void }) {
  const { home, agents } = useApp()
  const toast = useToast()
  const [agent, setAgent] = React.useState(EVERY)
  const [project, setProject] = React.useState(EVERY)
  const [write, setWrite] = React.useState(false)
  const [whole, setWhole] = React.useState(false)
  const [busy, setBusy] = React.useState(false)
  const [err, setErr] = React.useState<string | null>(null)
  React.useEffect(() => {
    setErr(null)
    setAgent(intent?.agents[0] ?? EVERY)
    setProject(intent?.projects[0] ?? EVERY)
    setWrite(!!intent?.write)
    setWhole(false)
  }, [intent])
  if (!intent) return null
  const name = (id: string) => agents.find((a) => a.id === id)?.name ?? id
  const forAgent = intent.agents[0] ?? 'claude-code'
  const who = agent === EVERY ? 'every agent' : name(agent)
  const where = project === EVERY ? 'every project' : baseName(project)
  const shown = intent.kind === 'site' ? intent.target : tildify(intent.target, home)
  // Only what the chosen agent asked for (every agent: all of them).
  const files = (intent.files ?? []).filter((f) => agent === EVERY || f.agents.includes(agent))
  // Exact files unless the human chose the whole folder (or there's no list).
  // A folder only when chosen, or when the request has no file list at all
  // (never because the chosen agent has nothing listed).
  const folder = intent.kind === 'file' && (whole || (intent.files ?? []).length === 0)
  const nothing = intent.kind === 'file' && !folder && files.length === 0

  const apply = async () => {
    setBusy(true)
    setErr(null)
    try {
      const scope = { agent: agent === EVERY ? null : agent, project: project === EVERY ? null : project, for_agent: agent === EVERY ? forAgent : agent }
      if (intent.kind === 'file' && !folder) {
        // Change only what was refused for a change; the rest is read.
        const changes = write ? files.filter((f) => f.write).map((f) => f.path) : []
        const reads = files.map((f) => f.path).filter((p) => !changes.includes(p))
        if (changes.length) await post('/api/access/allow', { kind: 'write', targets: changes, ...scope })
        if (reads.length) await post('/api/access/allow', { kind: 'read', targets: reads, ...scope })
      } else {
        await post('/api/access/allow', { kind: intent.kind === 'site' ? 'site' : write ? 'write' : 'read', target: intent.target, dir: folder, ...scope })
      }
      toast({
        kind: 'success',
        title: intent.kind === 'file' && !folder ? `Allowed ${files.length} file${files.length > 1 ? 's' : ''} for ${who}` : `Allowed ${shown} for ${who}`,
        body:
          intent.kind === 'site'
            ? 'Running agents can reach it now.'
            : 'macOS fixes an agent’s sandbox when it starts: restart it to apply this (the conversation resumes).',
      })
      onDone()
      onClose()
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {intent.kind === 'file' ? (
              <>
                Allow access in <span className="font-mono break-all">{shown}</span>?
              </>
            ) : (
              <>
                Allow <span className="font-mono break-all">{shown}</span>?
              </>
            )}
          </DialogTitle>
          <DialogDescription>
            {intent.category && <CategoryBadge id={intent.category.id} label={intent.category.label} />} {intent.category?.advice}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <Label>For</Label>
            <NativeSelect value={agent} onChange={(e) => setAgent(e.target.value)}>
              {intent.agents.map((a) => (
                <option key={a} value={a}>
                  Only {name(a)}
                </option>
              ))}
              <option value={EVERY}>Every agent</option>
            </NativeSelect>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>Where</Label>
            <NativeSelect value={project} onChange={(e) => setProject(e.target.value)}>
              {intent.projects.map((p) => (
                <option key={p} value={p}>
                  Only in {baseName(p)}
                </option>
              ))}
              <option value={EVERY}>In every project</option>
            </NativeSelect>
          </div>
          {intent.kind === 'file' && (intent.files ?? []).length > 0 && (
            <div className="flex flex-col gap-1.5 sm:col-span-2">
              <Label>What</Label>
              <NativeSelect value={whole ? 'folder' : 'exact'} onChange={(e) => setWhole(e.target.value === 'folder')}>
                <option value="exact">
                  Exactly the {files.length} file{files.length > 1 ? 's' : ''} it asked for (recommended)
                </option>
                <option value="folder">Everything in {shown}</option>
              </NativeSelect>
              {!whole ? (
                <>
                  <ul className="max-h-32 overflow-auto rounded-md border bg-muted/40 p-2">
                    {files.map((f) => (
                      <li key={f.path} className="flex items-center gap-2">
                        <Mono className="min-w-0 flex-1 text-[12px] break-all">{tildify(f.path, home)}</Mono>
                        {write && f.write && <span className="text-[11px] text-muted-foreground">change</span>}
                      </li>
                    ))}
                  </ul>
                  {intent.truncated && <p className="text-xs text-muted-foreground">Only the first 50 refused files are listed; anything else comes back as a new request.</p>}
                </>
              ) : (
                <p className="rounded-md border border-amber-500/40 bg-amber-500/[0.06] p-2 text-xs">
                  This also covers files the agent hasn’t asked for, now and later. Reads that this allows aren’t recorded in the audit log: only refusals are.
                </p>
              )}
            </div>
          )}
          {intent.kind === 'file' && (
            <div className="flex flex-col gap-1.5 sm:col-span-2">
              <Label>Access</Label>
              <NativeSelect value={write ? 'write' : 'read'} onChange={(e) => setWrite(e.target.value === 'write')}>
                <option value="read">Read</option>
                <option value="write">{folder ? 'Read and change' : 'Read, and change what it tried to change'}</option>
              </NativeSelect>
            </div>
          )}
        </div>
        <ul className="flex list-disc flex-col gap-1.5 pl-5 text-sm text-muted-foreground">
          <li>
            {intent.kind === 'file' ? (
              folder ? (
                <>
                  <Mono>{shown}</Mono> and everything in it, for <b>{who}</b> in <b>{where}</b>.
                </>
              ) : (
                <>
                  Only the file{files.length > 1 ? 's' : ''} listed, for <b>{who}</b> in <b>{where}</b>. Anything else it asks for comes back as a new request.
                </>
              )
            ) : (
              <>
                Only this exact host (any port), for <b>{who}</b> in <b>{where}</b>. Subdomains stay blocked.
              </>
            )}
          </li>
          <li>Built-in protections (keys, cloud credentials, git hooks…) inside it stay blocked.</li>
          <li>
            {intent.kind === 'file'
              ? 'Files can’t be opened for an agent that’s already running: restart it afterwards (the conversation resumes).'
              : 'Applies to running agents now.'}
          </li>
          <li>Undo it any time on the Agents page, under Access.</li>
        </ul>
        <ErrorText error={err} />
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          {nothing && <span className="self-center text-xs text-muted-foreground">{name(agent)} didn’t ask for any of these files.</span>}
          <Button variant="brand" onClick={apply} disabled={busy || nothing}>
            {busy ? <Loader2 className="animate-spin" /> : <Check />} Allow
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
