import * as React from 'react'
import { Check, ChevronLeft, ChevronRight, Copy, Inbox, Loader2 } from 'lucide-react'
import { Badge, type BadgeVariant } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { NativeSelect } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import type { Effect, NodeStatus } from '@/lib/api'

export function PageHeader({ title, description, actions, back }: { title: React.ReactNode; description?: React.ReactNode; actions?: React.ReactNode; back?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {back}
        <h1 className="truncate text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Empty({ icon: Icon = Inbox, title, children, action }: { icon?: React.ElementType; title: string; children?: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-6 py-12 text-center">
      <div className="rounded-full bg-muted p-3">
        <Icon className="size-5 text-muted-foreground" />
      </div>
      <div className="font-medium">{title}</div>
      {children && <div className="max-w-md text-sm text-muted-foreground">{children}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-10 text-sm text-muted-foreground justify-center">
      <Loader2 className="size-4 animate-spin" /> {label}
    </div>
  )
}

export function ErrorText({ error }: { error: string | null }) {
  if (!error) return null
  return <div className="rounded-md border border-red-500/30 bg-red-500/[0.06] px-3 py-2 text-sm text-red-700 dark:text-red-300">{error}</div>
}

export function CopyButton({ text, className }: { text: string; className?: string }) {
  const [done, setDone] = React.useState(false)
  return (
    <Button
      variant="ghost"
      size="icon"
      className={cn('size-7', className)}
      title="Copy"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setDone(true)
          setTimeout(() => setDone(false), 1200)
        })
      }}
    >
      {done ? <Check className="size-3.5 text-emerald-500" /> : <Copy className="size-3.5" />}
    </Button>
  )
}

export function Command({ children }: { children: string }) {
  return (
    <div className="flex items-center justify-between gap-2 rounded-md border bg-muted/60 py-1 pr-1 pl-3 font-mono text-[13px]">
      <span className="truncate">
        <span className="text-muted-foreground select-none">$ </span>
        {children}
      </span>
      <CopyButton text={children} />
    </div>
  )
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn('font-mono text-[12.5px]', className)}>{children}</span>
}

export const statusMeta: Record<NodeStatus | 'missing', { label: string; variant: BadgeVariant; dot: string; help: string }> = {
  full: { label: 'Read & write', variant: 'success', dot: 'bg-emerald-500', help: 'The agent can read and change this.' },
  'read-only': { label: 'Read only', variant: 'info', dot: 'bg-sky-500', help: 'The agent can read this but not change it.' },
  blocked: { label: 'Blocked', variant: 'danger', dot: 'bg-red-500', help: 'The agent can neither read nor change this.' },
  partial: { label: 'Partly allowed', variant: 'warning', dot: 'bg-amber-500', help: 'Blocked, but some things inside are allowed.' },
  ask: { label: 'Needs approval', variant: 'violet', dot: 'bg-violet-500', help: 'Treated as blocked until approval prompts ship.' },
  missing: { label: 'Missing', variant: 'outline', dot: 'bg-zinc-400', help: 'This path does not exist.' },
}

export function StatusBadge({ status }: { status: NodeStatus }) {
  const m = statusMeta[status]
  return (
    <Badge variant={m.variant}>
      <span className={cn('size-1.5 rounded-full', m.dot)} />
      {m.label}
    </Badge>
  )
}

export function EffectBadge({ effect, enforced = true }: { effect?: Effect | null; enforced?: boolean }) {
  if (!effect) return <Badge variant="outline">Info</Badge>
  if (effect === 'allow') return <Badge variant="success">Allowed</Badge>
  if (!enforced) return <Badge variant="warning">Would block</Badge>
  return <Badge variant="danger">{effect === 'ask' ? 'Blocked (needs approval)' : 'Blocked'}</Badge>
}

export function Pagination({ page, pages, total, size, onPage, onSize, sizes = [25, 50, 100] }: { page: number; pages: number; total: number; size: number; onPage: (p: number) => void; onSize?: (s: number) => void; sizes?: number[] }) {
  const from = total === 0 ? 0 : (page - 1) * size + 1
  const to = Math.min(total, page * size)
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t px-3 py-3 text-sm text-muted-foreground">
      <div>
        Showing <span className="font-medium text-foreground">{from.toLocaleString()}–{to.toLocaleString()}</span> of <span className="font-medium text-foreground">{total.toLocaleString()}</span>
      </div>
      <div className="flex items-center gap-2">
        {onSize && (
          <label className="flex items-center gap-2">
            Rows
            <NativeSelect className="h-8" value={size} onChange={(e) => onSize(Number(e.target.value))}>
              {sizes.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </NativeSelect>
          </label>
        )}
        <span className="px-1">
          Page <span className="font-medium text-foreground">{page}</span> of {pages}
        </span>
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(1)}>
          First
        </Button>
        <Button variant="outline" size="icon" className="size-8" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          <ChevronLeft />
        </Button>
        <Button variant="outline" size="icon" className="size-8" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          <ChevronRight />
        </Button>
        <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => onPage(pages)}>
          Last
        </Button>
      </div>
    </div>
  )
}

export function Stat({ label, value, hint, icon: Icon, tone = 'default', onClick }: { label: string; value: React.ReactNode; hint?: React.ReactNode; icon: React.ElementType; tone?: 'default' | 'danger' | 'warning' | 'success' | 'brand'; onClick?: () => void }) {
  const tones = {
    default: 'bg-muted text-muted-foreground',
    danger: 'bg-red-500/10 text-red-600 dark:text-red-400',
    warning: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
    success: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
    brand: 'bg-brand/10 text-brand',
  }
  return (
    <button onClick={onClick} disabled={!onClick} className={cn('rounded-xl border bg-card p-5 text-left shadow-xs transition-colors', onClick && 'cursor-pointer hover:bg-accent/40')}>
      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">{label}</span>
        <span className={cn('rounded-md p-1.5', tones[tone])}>
          <Icon className="size-4" />
        </span>
      </div>
      <div className="mt-3 text-3xl font-semibold tracking-tight tabular-nums">{value}</div>
      {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
    </button>
  )
}
