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
  const [busy, setBusy] = React.useState(false)
  const [err, setErr] = React.useState<string | null>(null)
  React.useEffect(() => {
    setErr(null)
    setAgent(intent?.agents[0] ?? EVERY)
    setProject(intent?.projects[0] ?? EVERY)
    setWrite(!!intent?.write)
  }, [intent])
  if (!intent) return null
  const name = (id: string) => agents.find((a) => a.id === id)?.name ?? id
  const forAgent = intent.agents[0] ?? 'claude-code'
  const who = agent === EVERY ? 'every agent' : name(agent)
  const where = project === EVERY ? 'every project' : baseName(project)
  const shown = intent.kind === 'site' ? intent.target : tildify(intent.target, home)

  const apply = async () => {
    setBusy(true)
    setErr(null)
    try {
      await post('/api/access/allow', {
        kind: intent.kind === 'site' ? 'site' : write ? 'write' : 'read',
        target: intent.target,
        dir: intent.kind === 'file',
        agent: agent === EVERY ? null : agent,
        project: project === EVERY ? null : project,
        for_agent: agent === EVERY ? forAgent : agent,
      })
      toast({
        kind: 'success',
        title: `Allowed ${shown} for ${who}`,
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
            Allow <span className="font-mono break-all">{shown}</span>
            {intent.kind === 'file' ? ' (folder)' : ''}?
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
          {intent.kind === 'file' && (
            <div className="flex flex-col gap-1.5 sm:col-span-2">
              <Label>Access</Label>
              <NativeSelect value={write ? 'write' : 'read'} onChange={(e) => setWrite(e.target.value === 'write')}>
                <option value="read">Read</option>
                <option value="write">Read and change</option>
              </NativeSelect>
            </div>
          )}
        </div>
        <ul className="flex list-disc flex-col gap-1.5 pl-5 text-sm text-muted-foreground">
          <li>
            {intent.kind === 'file' ? (
              <>
                <Mono>{shown}</Mono> and everything in it, for <b>{who}</b> in <b>{where}</b>.
              </>
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
          <Button variant="brand" onClick={apply} disabled={busy}>
            {busy ? <Loader2 className="animate-spin" /> : <Check />} Allow
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
