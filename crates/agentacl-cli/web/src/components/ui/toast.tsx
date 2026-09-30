import * as React from 'react'
import { CheckCircle2, AlertTriangle, Info, X } from 'lucide-react'
import { cn } from '@/lib/utils'

type Toast = { id: number; title: string; body?: string; kind: 'success' | 'error' | 'info' }
const Ctx = React.createContext<(t: Omit<Toast, 'id'>) => void>(() => {})
export const useToast = () => React.useContext(Ctx)

export function Toaster({ children }: { children: React.ReactNode }) {
  const [items, setItems] = React.useState<Toast[]>([])
  const push = React.useCallback((t: Omit<Toast, 'id'>) => {
    const id = Date.now() + Math.random()
    setItems((x) => [...x, { ...t, id }])
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), t.kind === 'error' ? 9000 : 5000)
  }, [])
  return (
    <Ctx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed top-16 right-4 z-[100] flex w-full max-w-sm flex-col gap-2">
        {items.map((t) => {
          const Icon = t.kind === 'success' ? CheckCircle2 : t.kind === 'error' ? AlertTriangle : Info
          return (
            <div key={t.id} className="pointer-events-auto flex items-start gap-3 rounded-lg border bg-popover p-4 text-sm shadow-lg">
              <Icon className={cn('mt-0.5 size-4 shrink-0', t.kind === 'success' ? 'text-emerald-500' : t.kind === 'error' ? 'text-red-500' : 'text-brand')} />
              <div className="min-w-0 flex-1">
                <div className="font-medium">{t.title}</div>
                {t.body && <div className="mt-0.5 text-muted-foreground">{t.body}</div>}
              </div>
              <button className="opacity-50 hover:opacity-100" onClick={() => setItems((x) => x.filter((i) => i.id !== t.id))}>
                <X className="size-3.5" />
              </button>
            </div>
          )
        })}
      </div>
    </Ctx.Provider>
  )
}
