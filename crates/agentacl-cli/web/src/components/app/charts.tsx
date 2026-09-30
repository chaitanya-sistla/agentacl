import * as React from 'react'
import { Tooltip } from '@/components/ui/misc'
import { cn } from '@/lib/utils'

/** A "nice" axis maximum: 1, 2 or 5 × 10^n, at least `v`. */
function niceMax(v: number): number {
  if (v <= 0) return 4
  const p = Math.pow(10, Math.floor(Math.log10(v)))
  for (const m of [1, 2, 5, 10]) if (m * p >= v) return m * p
  return 10 * p
}
const fmt = (n: number) => (n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)}M` : n >= 10_000 ? `${Math.round(n / 1000)}k` : n >= 1000 ? `${(n / 1000).toFixed(1)}k` : `${n}`)

export interface Series {
  key: string
  label: string
  /** Tailwind background class for bars and legend. */
  className: string
}

/** Stacked vertical bars with a y-axis, gridlines and a tooltip per bar. */
export function StackedBars({ data, series, labels, height = 190, empty = 'No activity yet' }: { data: Record<string, number>[]; series: Series[]; labels: string[]; height?: number; empty?: string }) {
  const totals = data.map((d) => series.reduce((s, x) => s + (d[x.key] ?? 0), 0))
  const max = niceMax(Math.max(0, ...totals))
  const ticks = [max, max / 2, 0]
  const allZero = totals.every((t) => t === 0)
  return (
    <div>
      <div className="flex gap-3">
        <div className="flex w-10 flex-col justify-between text-right text-[11px] text-muted-foreground tabular-nums" style={{ height }}>
          {ticks.map((t) => (
            <span key={t} className="-translate-y-1/2 first:translate-y-0 last:translate-y-0">
              {fmt(t)}
            </span>
          ))}
        </div>
        <div className="relative flex-1" style={{ height }}>
          {ticks.map((t, i) => (
            <div key={t} className={cn('absolute right-0 left-0 border-t', i === ticks.length - 1 ? 'border-border' : 'border-dashed border-border/60')} style={{ top: `${(i / (ticks.length - 1)) * 100}%` }} />
          ))}
          {allZero && <div className="absolute inset-0 grid place-items-center text-sm text-muted-foreground">{empty}</div>}
          <div className="absolute inset-0 flex items-end gap-[3px]">
            {data.map((d, i) => (
              <Tooltip
                key={i}
                content={
                  <div className="flex flex-col gap-0.5">
                    <div className="font-medium">{labels[i]}</div>
                    {series.map((s) => (
                      <div key={s.key} className="flex items-center gap-1.5">
                        <span className={cn('size-2 rounded-sm', s.className)} />
                        {s.label}: <b className="tabular-nums">{(d[s.key] ?? 0).toLocaleString()}</b>
                      </div>
                    ))}
                  </div>
                }
              >
                <div className="group flex h-full flex-1 flex-col-reverse">
                  {series.map((s) => {
                    const v = d[s.key] ?? 0
                    return v > 0 ? <div key={s.key} className={cn('w-full transition-opacity first:rounded-b-[2px] last:rounded-t-[3px] group-hover:opacity-80', s.className)} style={{ height: `${(v / max) * 100}%` }} /> : null
                  })}
                </div>
              </Tooltip>
            ))}
          </div>
        </div>
      </div>
      <div className="mt-2 ml-13 flex justify-between text-[11px] text-muted-foreground">
        {labels.filter((_, i) => i % 6 === 0 || i === labels.length - 1).map((l, i) => (
          <span key={i}>{l}</span>
        ))}
      </div>
      <div className="mt-3 flex gap-4 text-xs text-muted-foreground">
        {series.map((s) => (
          <span key={s.key} className="flex items-center gap-1.5">
            <span className={cn('size-2.5 rounded-sm', s.className)} />
            {s.label}
          </span>
        ))}
      </div>
    </div>
  )
}

/** Ranked horizontal bars. */
export function BarList({ items, barClass, empty, onClick }: { items: { label: React.ReactNode; value: number; sub?: React.ReactNode; key: string }[]; barClass: string; empty: string; onClick?: (key: string) => void }) {
  if (items.length === 0) return <div className="py-8 text-center text-sm text-muted-foreground">{empty}</div>
  const max = Math.max(...items.map((i) => i.value))
  return (
    <ul className="flex flex-col gap-2">
      {items.map((it) => (
        <li key={it.key}>
          <button disabled={!onClick} onClick={() => onClick?.(it.key)} className={cn('relative w-full overflow-hidden rounded-md px-3 py-2 text-left', onClick && 'hover:ring-1 hover:ring-border')}>
            <span className={cn('absolute inset-y-0 left-0 rounded-md opacity-15', barClass)} style={{ width: `${Math.max(4, (it.value / max) * 100)}%` }} />
            <span className="relative flex items-center gap-3">
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono text-[12.5px]">{it.label}</span>
                {it.sub && <span className="block truncate text-[11px] text-muted-foreground">{it.sub}</span>}
              </span>
              <span className="text-sm font-semibold tabular-nums">{it.value.toLocaleString()}</span>
            </span>
          </button>
        </li>
      ))}
    </ul>
  )
}

const DONUT_COLORS = ['#ef4444', '#f59e0b', '#8b5cf6', '#0ea5e9', '#10b981', '#ec4899', '#71717a']

/** Donut with a legend; share of a total. */
export function Donut({ items, centerLabel, empty }: { items: { label: string; value: number }[]; centerLabel: string; empty: string }) {
  const total = items.reduce((s, i) => s + i.value, 0)
  if (total === 0) return <div className="py-8 text-center text-sm text-muted-foreground">{empty}</div>
  const R = 52
  const C = 2 * Math.PI * R
  let acc = 0
  const sorted = [...items].sort((a, b) => b.value - a.value)
  return (
    <div className="flex flex-wrap items-center gap-6">
      <svg viewBox="0 0 140 140" className="size-36 shrink-0 -rotate-90">
        <circle cx="70" cy="70" r={R} fill="none" stroke="var(--muted)" strokeWidth="16" />
        {sorted.map((it, i) => {
          const len = (it.value / total) * C
          const el = <circle key={it.label} cx="70" cy="70" r={R} fill="none" stroke={DONUT_COLORS[i % DONUT_COLORS.length]} strokeWidth="16" strokeDasharray={`${Math.max(0, len - 1.5)} ${C}`} strokeDashoffset={-acc} />
          acc += len
          return el
        })}
        <text x="70" y="66" textAnchor="middle" className="fill-foreground text-[20px] font-semibold" transform="rotate(90 70 70)">
          {fmt(total)}
        </text>
        <text x="70" y="84" textAnchor="middle" className="fill-muted-foreground text-[9px]" transform="rotate(90 70 70)">
          {centerLabel}
        </text>
      </svg>
      <ul className="flex min-w-40 flex-1 flex-col gap-1.5 text-sm">
        {sorted.map((it, i) => (
          <li key={it.label} className="flex items-center gap-2">
            <span className="size-2.5 shrink-0 rounded-sm" style={{ background: DONUT_COLORS[i % DONUT_COLORS.length] }} />
            <span className="flex-1 truncate">{it.label}</span>
            <span className="tabular-nums text-muted-foreground">{Math.round((it.value / total) * 100)}%</span>
            <span className="w-14 text-right font-medium tabular-nums">{it.value.toLocaleString()}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function CategoryBadge({ id, label }: { id: string; label: string }) {
  const tone: Record<string, string> = {
    'ai-provider': 'border-violet-500/25 bg-violet-500/10 text-violet-700 dark:text-violet-300',
    'package-registry': 'border-sky-500/25 bg-sky-500/10 text-sky-700 dark:text-sky-300',
    'source-hosting': 'border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
    telemetry: 'border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-300',
    docs: 'border-teal-500/25 bg-teal-500/10 text-teal-700 dark:text-teal-300',
    cloud: 'border-rose-500/25 bg-rose-500/10 text-rose-700 dark:text-rose-300',
    unknown: 'border-border bg-muted text-muted-foreground',
  }
  return <span className={cn('inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap', tone[id] ?? tone.unknown)}>{label}</span>
}
