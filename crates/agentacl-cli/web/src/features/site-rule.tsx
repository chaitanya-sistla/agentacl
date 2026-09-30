import * as React from 'react'
import { Ban, Check, Loader2, Trash2 } from 'lucide-react'
import { post, type Category } from '@/lib/api'
import { useApp } from '@/lib/app-context'
import { tildify } from '@/lib/format'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Alert } from '@/components/ui/misc'
import { useToast } from '@/components/ui/toast'
import { ErrorText, Mono } from '@/components/app/common'
import { CategoryBadge } from '@/components/app/charts'

export interface SiteRuleIntent {
  host: string
  effect: 'allow' | 'block' | 'none'
  category?: Category
  /** The site is currently blocked by the user's own rule. */
  wasBlockedByYou?: boolean
}

/** Confirms a site rule: what is saved where, and what happens to running agents. */
export function SiteRuleDialog({ intent, onClose, onDone }: { intent: SiteRuleIntent | null; onClose: () => void; onDone: () => void }) {
  const { status, home } = useApp()
  const toast = useToast()
  const [busy, setBusy] = React.useState(false)
  const [err, setErr] = React.useState<string | null>(null)
  React.useEffect(() => setErr(null), [intent])
  if (!intent) return null
  const file = tildify(status?.paths.user_policy ?? '~/.config/agentacl/policy.yaml', home)
  const verb = intent.effect === 'allow' ? 'Allow' : intent.effect === 'block' ? 'Block' : 'Remove the rule for'

  const apply = async () => {
    setBusy(true)
    setErr(null)
    try {
      const r = await post<{ ok: boolean; comments_lost?: boolean }>('/api/network/rule', { host: intent.host, effect: intent.effect })
      toast({
        kind: 'success',
        title: intent.effect === 'allow' ? `Allowed ${intent.host}` : intent.effect === 'block' ? `Blocked ${intent.host}` : `Removed the rule for ${intent.host}`,
        body: r.comments_lost ? 'Saved. Comments in your policy file were not kept.' : `Saved to ${file}.`,
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
            {verb} <span className="font-mono">{intent.host}</span>?
          </DialogTitle>
          <DialogDescription>{intent.category && <CategoryBadge id={intent.category.id} label={intent.category.label} />} {intent.category?.advice}</DialogDescription>
        </DialogHeader>
        <ul className="flex list-disc flex-col gap-1.5 pl-5 text-sm">
          {intent.effect === 'allow' && (
            <>
              <li>
                Adds <Mono>{intent.host}</Mono> to <Mono>network.allow</Mono> in <Mono>{file}</Mono> (all agents, all projects).
              </li>
              {intent.wasBlockedByYou ? (
                <li>Replaces your block. Agents started since you blocked it keep it blocked until they restart; everything else can reach it right away.</li>
              ) : (
                <li>Running agents can reach it right away. No restart needed.</li>
              )}
              <li>Only this exact host (any port): subdomains stay blocked.</li>
            </>
          )}
          {intent.effect === 'block' && (
            <>
              <li>
                Adds <Mono>{intent.host}</Mono> to <Mono>network.deny</Mono> in <Mono>{file}</Mono>.
              </li>
              <li>Applies immediately to every running agent. A block always wins over an allow.</li>
            </>
          )}
          {intent.effect === 'none' && (
            <>
              <li>
                Removes <Mono>{intent.host}</Mono> from your rules. Sites no rule names follow your Network setting (block or ask).
              </li>
              <li>Takes effect now for running agents that relied on it.</li>
            </>
          )}
        </ul>
        {intent.category?.id === 'cloud' && intent.effect === 'allow' && (
          <Alert variant="warning">
            <Ban />
            <div>Cloud APIs can change real infrastructure. Allow only if the agent's task needs it.</div>
          </Alert>
        )}
        <ErrorText error={err} />
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant={intent.effect === 'block' ? 'destructive' : intent.effect === 'allow' ? 'brand' : 'outline'} onClick={apply} disabled={busy}>
            {busy ? <Loader2 className="animate-spin" /> : intent.effect === 'allow' ? <Check /> : intent.effect === 'block' ? <Ban /> : <Trash2 />}
            {verb} site
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
