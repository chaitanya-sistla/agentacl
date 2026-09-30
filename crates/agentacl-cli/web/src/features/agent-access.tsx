import { FolderOpen, Globe, Trash2 } from 'lucide-react'
import { get, post, type AccessEntry, type AccessResp, type AccessRule } from '@/lib/api'
import { useData } from '@/lib/hooks'
import { useApp } from '@/lib/app-context'
import { baseName, tildify } from '@/lib/format'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from '@/components/ui/toast'
import { Mono } from '@/components/app/common'

const SECTION: Record<AccessRule['section'], string> = { allow_read: 'Read', allow_write: 'Read and change', 'network.allow': 'Site' }

/** What you allowed from requests, per agent and place, with Remove. */
export function AgentAccess() {
  const { home } = useApp()
  const toast = useToast()
  const d = useData(() => get<AccessResp>('/api/access'), [])
  const list = d.data?.access ?? []
  const remove = async (e: AccessEntry, r: AccessRule) => {
    try {
      await post('/api/access/remove', { file: e.file, section: r.section, pattern: r.pattern })
      // "Read and change" was saved as both; remove the read too.
      if (r.section === 'allow_write' && e.rules.some((x) => x.section === 'allow_read' && x.pattern === r.pattern)) {
        await post('/api/access/remove', { file: e.file, section: 'allow_read', pattern: r.pattern })
      }
      toast({
        kind: 'success',
        title: `Removed ${r.section === 'network.allow' ? r.display : tildify(r.display, home)}`,
        body: r.section === 'network.allow' ? 'Applies to running agents now.' : 'Running agents keep it until they restart.',
      })
    } catch (err: any) {
      toast({ kind: 'error', title: 'Could not remove', body: err.message })
    }
    d.reload()
  }
  const removeBroken = async (file: string) => {
    try {
      await post('/api/access/remove', { file, broken: true })
      toast({ kind: 'success', title: `Removed ${file}` })
    } catch (err: any) {
      toast({ kind: 'error', title: 'Could not remove', body: err.message })
    }
    d.reload()
  }
  // Reading is implied by change; don't list a folder twice.
  const shown = (e: AccessEntry) => e.rules.filter((r) => !(r.section === 'allow_read' && e.rules.some((w) => w.section === 'allow_write' && w.pattern === r.pattern)))
  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Access you granted</CardTitle>
        <CardDescription>
          Allowed from requests, beyond your rules. Built-in protections always stay on. Stored in <Mono>{tildify(d.data?.dir ?? '', home)}</Mono>.
        </CardDescription>
      </CardHeader>
      <div className="px-6 pb-6">
        {(d.data?.broken ?? []).map((b) => (
          <div key={b.file} className="mb-3 flex flex-wrap items-center gap-3 rounded-md border border-amber-500/40 bg-amber-500/[0.06] px-3 py-2 text-sm">
            <span className="min-w-0 flex-1">
              <Mono>{b.file}</Mono> is ignored: {b.error}
            </span>
            <Button size="sm" variant="outline" onClick={() => removeBroken(b.file)}>
              <Trash2 /> Remove file
            </Button>
          </div>
        ))}
        {list.length === 0 ? (
          <p className="text-sm text-muted-foreground">Nothing yet. Use Allow… on a request to give one agent access to a folder or site.</p>
        ) : (
          <ul className="flex flex-col divide-y rounded-md border">
            {list.flatMap((e) =>
              shown(e).map((r) => (
                <li key={e.file + r.section + r.pattern} className="flex flex-wrap items-center gap-3 px-3 py-2 text-sm">
                  {r.section === 'network.allow' ? <Globe className="size-4 text-muted-foreground" /> : <FolderOpen className="size-4 text-muted-foreground" />}
                  <Mono className="min-w-0 flex-1 break-all">{r.section === 'network.allow' ? r.display : tildify(r.display, home)}</Mono>
                  <Badge variant="secondary">{SECTION[r.section]}</Badge>
                  <Badge variant={e.agent ? 'info' : 'outline'}>{e.agent_name ?? 'Every agent'}</Badge>
                  <Badge variant="outline">{e.project ? `in ${baseName(e.project)}` : 'Every project'}</Badge>
                  <Button size="sm" variant="ghost" onClick={() => remove(e, r)} title="Remove">
                    <Trash2 />
                  </Button>
                </li>
              )),
            )}
          </ul>
        )}
      </div>
    </Card>
  )
}
