import * as React from 'react'
import { FolderSearch, Plus } from 'lucide-react'
import { post } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input, Label } from '@/components/ui/input'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { ErrorText } from '@/components/app/common'
import { useToast } from '@/components/ui/toast'

/** Adds a project via the macOS folder picker or a typed path. */
export function AddProjectButton({ onAdded, variant = 'brand' }: { onAdded: (path: string) => void; variant?: 'brand' | 'outline' }) {
  const [open, setOpen] = React.useState(false)
  const [path, setPath] = React.useState('')
  const [err, setErr] = React.useState<string | null>(null)
  const [busy, setBusy] = React.useState(false)
  const toast = useToast()

  const add = async (p: string) => {
    setBusy(true)
    setErr(null)
    try {
      const r = await post<{ path: string }>('/api/projects/add', { path: p })
      toast({ kind: 'success', title: 'Project added', body: r.path })
      setOpen(false)
      setPath('')
      onAdded(r.path)
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }
  const finder = async () => {
    setBusy(true)
    setErr(null)
    try {
      const r = await post<{ path?: string; cancelled?: boolean; error?: string }>('/api/pick-folder', {})
      if (r.error) setErr(r.error)
      else if (r.path) await add(r.path)
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <Button variant={variant} onClick={() => setOpen(true)}>
        <Plus /> Add project
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add a project</DialogTitle>
            <DialogDescription>A project is a folder an agent works in. AgentACL uses the Git repository root when there is one.</DialogDescription>
          </DialogHeader>
          <Button variant="outline" size="lg" className="justify-start" onClick={finder} disabled={busy}>
            <FolderSearch /> Choose a folder in Finder…
          </Button>
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <div className="h-px flex-1 bg-border" /> or type a path <div className="h-px flex-1 bg-border" />
          </div>
          <form
            className="flex flex-col gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              if (path.trim()) add(path.trim())
            }}
          >
            <Label htmlFor="proj-path">Folder path</Label>
            <Input id="proj-path" placeholder="/Users/you/code/my-app" value={path} onChange={(e) => setPath(e.target.value)} className="font-mono" />
            <ErrorText error={err} />
            <DialogFooter className="mt-2">
              <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="brand" disabled={busy || !path.trim()}>
                Add project
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  )
}
