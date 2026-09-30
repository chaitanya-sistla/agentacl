import * as React from 'react'
import { useApp } from '@/lib/app-context'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { setNavGuard } from '@/lib/hooks'

/** App-wide "discard unsaved changes?" guard for in-app actions and hash navigation. */
export function useGlobalGuard() {
  const dirty = React.useRef(false)
  const [pending, setPending] = React.useState<(() => void) | null>(null)
  const guard = React.useCallback((f: () => void) => (dirty.current ? setPending(() => f) : f()), [])
  const setDirty = React.useCallback((d: boolean) => {
    dirty.current = d
  }, [])
  React.useEffect(() => {
    setNavGuard((to) => {
      if (!dirty.current) return true
      setPending(() => () => {
        location.hash = to
      })
      return false
    })
    return () => setNavGuard(null)
  }, [])
  const dialog = (
    <Dialog open={!!pending} onOpenChange={(o) => !o && setPending(null)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Discard unsaved changes?</DialogTitle>
          <DialogDescription>You have rule changes that aren’t saved. They’ll be lost if you continue.</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="ghost" onClick={() => setPending(null)}>
            Keep editing
          </Button>
          <Button
            variant="destructive"
            onClick={() => {
              const f = pending
              setPending(null)
              dirty.current = false
              f?.()
            }}
          >
            Discard changes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
  return { guard, setDirty, dialog }
}

/** Page-level access to the global guard. */
export function useDiscardGuard() {
  const { guard, setDirty } = useApp()
  return { guard, onDirty: setDirty, dialog: null as React.ReactNode }
}
