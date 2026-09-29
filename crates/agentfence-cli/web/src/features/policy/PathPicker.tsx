import * as React from 'react'
import { ArrowUp, ChevronRight, File, Folder, FolderSearch, FileSearch, Link2, Loader2 } from 'lucide-react'
import { post, type FsList, type FsNode } from '@/lib/api'
import { useApp } from '@/lib/app-context'
import { tildify } from '@/lib/format'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { ErrorText, StatusBadge } from '@/components/app/common'

/** Browse the disk (names only) or use Finder; returns the chosen node. */
export function PathPicker({ open, onOpenChange, start, body, onPick, title = 'Choose a file or folder' }: {
  open: boolean
  onOpenChange: (o: boolean) => void
  start: string
  body: () => Record<string, unknown>
  onPick: (n: FsNode) => void
  title?: string
}) {
  const { home } = useApp()
  const [dir, setDir] = React.useState(start)
  const [list, setList] = React.useState<FsList | null>(null)
  const [err, setErr] = React.useState<string | null>(null)
  const [busy, setBusy] = React.useState(false)

  const load = React.useCallback(async (path: string, offset = 0, force = false) => {
    setBusy(true)
    setErr(null)
    try {
      const r = await post<FsList>('/api/fs/list', { ...body(), path, offset, limit: 100, force })
      setList((prev) => (offset > 0 && prev && prev.path === r.path ? { ...r, entries: [...prev.entries, ...r.entries] } : r))
      setDir(r.path)
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }, [body])

  React.useEffect(() => {
    if (open) load(start)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, start])

  const finder = async (purpose: 'folder' | 'file') => {
    setErr(null)
    const r = await post<{ path?: string; cancelled?: boolean; error?: string }>('/api/pick-folder', { purpose })
    if (r.error) return setErr(r.error)
    if (!r.path) return
    try {
      onPick(await post<FsNode>('/api/fs/node', { ...body(), path: r.path }))
      onOpenChange(false)
    } catch (e: any) {
      setErr(e.message)
    }
  }
  const crumbs = dir.split('/').filter(Boolean)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent wide className="gap-3">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>Only names are shown — AgentFence never reads file contents here.</DialogDescription>
        </DialogHeader>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={() => finder('folder')}>
            <FolderSearch /> Pick folder in Finder…
          </Button>
          <Button variant="outline" size="sm" onClick={() => finder('file')}>
            <FileSearch /> Pick file in Finder…
          </Button>
        </div>
        <div className="flex items-center gap-1 overflow-x-auto rounded-md border bg-muted/40 px-2 py-1.5 text-sm">
          <Button variant="ghost" size="icon" className="size-7" disabled={dir === '/'} onClick={() => load(list?.parent ?? '/')} title="Up one level">
            <ArrowUp className="size-3.5" />
          </Button>
          <button className="rounded px-1 hover:bg-accent" onClick={() => load('/')}>
            /
          </button>
          {crumbs.map((c, i) => (
            <React.Fragment key={i}>
              <ChevronRight className="size-3 shrink-0 text-muted-foreground" />
              <button className="rounded px-1 whitespace-nowrap hover:bg-accent" onClick={() => load('/' + crumbs.slice(0, i + 1).join('/'))}>
                {c}
              </button>
            </React.Fragment>
          ))}
          {busy && <Loader2 className="ml-auto size-4 animate-spin text-muted-foreground" />}
        </div>
        <ErrorText error={err} />
        <div className="h-[46vh] overflow-y-auto rounded-md border">
          {list?.needs_force ? (
            <div className="flex flex-col items-center gap-3 p-10 text-center text-sm text-muted-foreground">
              macOS protects this folder. Listing it may show a permission prompt.
              <Button variant="outline" size="sm" onClick={() => load(dir, 0, true)}>
                List it anyway
              </Button>
            </div>
          ) : (
            <ul className="divide-y">
              <li className="flex items-center gap-3 bg-muted/30 px-3 py-2 text-sm">
                <Folder className="size-4 text-brand" />
                <span className="flex-1 font-medium">This folder ({tildify(dir, home) || '/'})</span>
                <Button
                  size="sm"
                  variant="brand"
                  className="h-7"
                  onClick={async () => {
                    try {
                      onPick(await post<FsNode>('/api/fs/node', { ...body(), path: dir }))
                      onOpenChange(false)
                    } catch (e: any) {
                      setErr(e.message)
                    }
                  }}
                >
                  Select
                </Button>
              </li>
              {list?.entries.map((e) => (
                <li key={e.path} className="group flex items-center gap-3 px-3 py-1.5 text-sm hover:bg-accent/40">
                  {e.kind === 'symlink' ? <Link2 className="size-4 text-muted-foreground" /> : e.is_dir ? <Folder className="size-4 text-muted-foreground" /> : <File className="size-4 text-muted-foreground" />}
                  {e.expandable ? (
                    <button className="min-w-0 flex-1 truncate text-left hover:underline" onClick={() => load(e.path)}>
                      {e.display}
                    </button>
                  ) : (
                    <span className="min-w-0 flex-1 truncate">{e.display}</span>
                  )}
                  <StatusBadge status={e.status} />
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 opacity-70 group-hover:opacity-100"
                    onClick={() => {
                      onPick(e)
                      onOpenChange(false)
                    }}
                  >
                    Select
                  </Button>
                </li>
              ))}
              {list && list.entries.length < list.total && (
                <li className="p-2 text-center">
                  <Button variant="ghost" size="sm" onClick={() => load(dir, list.entries.length)}>
                    Show more ({(list.total - list.entries.length).toLocaleString()} left)
                  </Button>
                </li>
              )}
              {list && list.total === 0 && <li className="p-6 text-center text-sm text-muted-foreground">This folder is empty.</li>}
            </ul>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
