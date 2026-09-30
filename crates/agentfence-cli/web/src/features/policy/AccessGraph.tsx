import * as React from 'react'
import { Bot, Cpu, File, Folder, FolderKanban, House, KeyRound, Link2, Loader2, Lock, Maximize2, Minus, Plus } from 'lucide-react'
import type { FsList, FsNode, MapGroup, NodeStatus } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Tooltip } from '@/components/ui/misc'
import { statusMeta } from '@/components/app/common'
import { cn } from '@/lib/utils'

// Layout constants (px, in graph space).
const NODE_W = 232
const NODE_H = 52
const COL_W = NODE_W + 96
const ROW_H = 64
const PAGE = 12

const COLOR: Record<NodeStatus | 'mixed' | 'missing', string> = {
  full: '#10b981',
  'read-only': '#0ea5e9',
  partial: '#f59e0b',
  blocked: '#ef4444',
  ask: '#8b5cf6',
  mixed: '#f59e0b',
  missing: '#a1a1aa',
}
const GROUP_ICON: Record<string, React.ElementType> = { 'group:project': FolderKanban, 'group:home': House, 'group:secrets': KeyRound, 'group:system': Cpu }

type GNode = {
  id: string
  kind: 'agent' | 'group' | 'fs' | 'more'
  label: string
  sub?: string
  status: NodeStatus | 'mixed' | 'missing'
  fs?: FsNode
  group?: MapGroup
  /** For "more" nodes: whose children to page. */
  owner?: string
  hidden?: number
  children: GNode[]
  parent?: GNode
  depth: number
  x: number
  y: number
}

function aggregate(nodes: FsNode[]): GNode['status'] {
  if (nodes.length === 0) return 'missing'
  const s = new Set(nodes.map((n) => n.status))
  return s.size === 1 ? nodes[0].status : 'mixed'
}

function summary(nodes: FsNode[]): string {
  if (nodes.length === 0) return 'None on this Mac'
  if (nodes.length === 1) return statusMeta[nodes[0].status].label
  const c: Record<string, number> = {}
  nodes.forEach((n) => (c[n.status] = (c[n.status] ?? 0) + 1))
  return Object.entries(c)
    .map(([k, v]) => `${v} ${statusMeta[k as NodeStatus].label.toLowerCase()}`)
    .join(' · ')
}

export function AccessGraph({ agentName, noProject, groups, kids, open, loading, sel, onSelect, onToggle, onMore }: {
  agentName: string
  noProject?: boolean
  groups: MapGroup[]
  kids: Record<string, FsList>
  open: Set<string>
  loading: Set<string>
  sel: FsNode | null
  onSelect: (n: FsNode) => void
  onToggle: (n: FsNode) => void
  onMore: (path: string) => Promise<void> | void
}) {
  const [limits, setLimits] = React.useState<Record<string, number>>({})
  // Big groups start folded into one node so the graph stays readable.
  const [openGroups, setOpenGroups] = React.useState<Set<string>>(() => new Set(['group:project', 'group:home']))
  const toggleGroup = (id: string) =>
    setOpenGroups((s) => {
      const n = new Set(s)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })

  // ---- build + lay out the tree -------------------------------------------
  const { nodes, edges, width, height } = React.useMemo(() => {
    const root: GNode = { id: 'agent', kind: 'agent', label: agentName, sub: 'AI agent', status: 'full', children: [], depth: 0, x: 0, y: 0 }
    const fsNode = (n: FsNode, parent: GNode): GNode => {
      const label = noProject && parent.id === 'group:project' ? 'No project selected' : n.display
      const g: GNode = { id: `${parent.id}>${n.path}`, kind: 'fs', label, status: n.kind === 'missing' ? 'missing' : n.status, fs: n, children: [], parent, depth: parent.depth + 1, x: 0, y: 0 }
      const list = open.has(n.path) ? kids[n.path] : undefined
      if (list) {
        const lim = limits[n.path] ?? PAGE
        g.children = list.entries.slice(0, lim).map((c) => fsNode(c, g))
        const hidden = list.total - Math.min(lim, list.entries.length)
        if (hidden > 0) g.children.push({ id: `${g.id}>more`, kind: 'more', label: `${hidden.toLocaleString()} more`, status: 'missing', owner: n.path, hidden, children: [], parent: g, depth: g.depth + 1, x: 0, y: 0 })
      }
      return g
    }
    for (const grp of groups) {
      const g: GNode = { id: grp.id, kind: 'group', label: grp.name, sub: summary(grp.children), status: aggregate(grp.children), group: grp, children: [], parent: root, depth: 1, x: 0, y: 0 }
      if (!openGroups.has(grp.id)) {
        root.children.push(g)
        continue
      }
      const lim = limits[grp.id] ?? PAGE
      g.children = grp.children.slice(0, lim).map((c) => fsNode(c, g))
      if (grp.children.length > lim) g.children.push({ id: `${grp.id}>more`, kind: 'more', label: `${grp.children.length - lim} more`, status: 'missing', owner: grp.id, hidden: grp.children.length - lim, children: [], parent: g, depth: 2, x: 0, y: 0 })
      root.children.push(g)
    }
    // Leaves take one row each; a parent sits centred on its children.
    let row = 0
    let maxDepth = 0
    const place = (n: GNode) => {
      n.x = n.depth * COL_W
      maxDepth = Math.max(maxDepth, n.depth)
      if (n.children.length === 0) {
        n.y = row * ROW_H
        row++
      } else {
        n.children.forEach(place)
        n.y = (n.children[0].y + n.children[n.children.length - 1].y) / 2
      }
    }
    place(root)
    const all: GNode[] = []
    const walk = (n: GNode) => {
      all.push(n)
      n.children.forEach(walk)
    }
    walk(root)
    const es = all.filter((n) => n.parent).map((n) => ({ from: n.parent!, to: n }))
    return { nodes: all, edges: es, width: (maxDepth + 1) * COL_W - (COL_W - NODE_W), height: Math.max(1, row) * ROW_H - (ROW_H - NODE_H) }
  }, [agentName, noProject, groups, kids, open, limits, openGroups])

  // ---- selection path highlight --------------------------------------------
  const selNode = sel ? nodes.find((n) => n.fs?.path === sel.path) ?? nodes.find((n) => n.kind === 'group' && n.group?.children.some((c) => c.path === sel.path)) : undefined
  const onPath = React.useMemo(() => {
    const s = new Set<string>()
    for (let n: GNode | undefined = selNode; n; n = n.parent) s.add(n.id)
    return s
  }, [selNode])

  // ---- pan & zoom -----------------------------------------------------------
  const box = React.useRef<HTMLDivElement>(null)
  const [view, setView] = React.useState({ x: 24, y: 24, k: 1 })
  const fitted = React.useRef(false)
  const fit = React.useCallback(() => {
    const el = box.current
    if (!el) return
    const pad = 32
    const k = Math.min(1, (el.clientWidth - pad * 2) / width, (el.clientHeight - pad * 2) / height)
    const kk = Math.max(0.6, k)
    const agentY = nodes[0]?.y ?? 0
    const y = height * kk <= el.clientHeight - pad * 2 ? (el.clientHeight - height * kk) / 2 : el.clientHeight / 2 - (agentY + NODE_H / 2) * kk
    setView({ k: kk, x: Math.max(pad, (el.clientWidth - width * kk) / 2), y })
  }, [width, height, nodes])
  React.useEffect(() => {
    if (!fitted.current && groups.length) {
      fitted.current = true
      fit()
    }
  }, [groups.length, fit])

  const zoomAt = (factor: number, cx?: number, cy?: number) =>
    setView((v) => {
      const el = box.current
      const px = cx ?? (el ? el.clientWidth / 2 : 0)
      const py = cy ?? (el ? el.clientHeight / 2 : 0)
      const k = Math.min(2, Math.max(0.3, v.k * factor))
      return { k, x: px - ((px - v.x) * k) / v.k, y: py - ((py - v.y) * k) / v.k }
    })

  React.useEffect(() => {
    const el = box.current
    if (!el) return
    // Pinch / ctrl+wheel zooms; plain wheel pans. Non-passive so the page doesn't scroll.
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const r = el.getBoundingClientRect()
      if (e.ctrlKey || e.metaKey) zoomAt(Math.exp(-e.deltaY * 0.01), e.clientX - r.left, e.clientY - r.top)
      else setView((v) => ({ ...v, x: v.x - e.deltaX, y: v.y - e.deltaY }))
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [])

  const drag = React.useRef<{ x: number; y: number; vx: number; vy: number; moved: boolean } | null>(null)
  const onPointerDown = (e: React.PointerEvent) => {
    if ((e.target as HTMLElement).closest('[data-node]')) return
    drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y, moved: false }
    ;(e.currentTarget as HTMLElement).setPointerCapture(e.pointerId)
  }
  const onPointerMove = (e: React.PointerEvent) => {
    const d = drag.current
    if (!d) return
    d.moved = true
    setView((v) => ({ ...v, x: d.vx + e.clientX - d.x, y: d.vy + e.clientY - d.y }))
  }
  const onPointerUp = () => {
    drag.current = null
  }

  // Keep a newly selected node in view.
  React.useEffect(() => {
    const el = box.current
    if (!el || !selNode) return
    setView((v) => {
      const sx = selNode.x * v.k + v.x
      const sy = selNode.y * v.k + v.y
      const inside = sx > 0 && sy > 0 && sx + NODE_W * v.k < el.clientWidth && sy + NODE_H * v.k < el.clientHeight
      return inside ? v : { ...v, x: el.clientWidth / 2 - (selNode.x + NODE_W / 2) * v.k, y: el.clientHeight / 2 - (selNode.y + NODE_H / 2) * v.k }
    })
  }, [selNode])

  // After expanding, keep the expanded node on screen (left third, vertically
  // centred) while its children load and the layout grows.
  const focus = React.useRef<{ key: string; until: number } | null>(null)
  const expand = (f: FsNode) => {
    if (!open.has(f.path)) focus.current = { key: f.path, until: Date.now() + 3000 }
    onToggle(f)
  }
  const expandGroup = (id: string) => {
    if (!openGroups.has(id)) focus.current = { key: id, until: Date.now() + 1500 }
    toggleGroup(id)
  }
  React.useEffect(() => {
    const f = focus.current
    const el = box.current
    if (!f || !el) return
    if (Date.now() > f.until) {
      focus.current = null
      return
    }
    const n = nodes.find((x) => x.fs?.path === f.key || x.id === f.key)
    if (!n) return
    setView((v) => ({ ...v, x: el.clientWidth * 0.18 - n.x * v.k, y: el.clientHeight / 2 - (n.y + NODE_H / 2) * v.k }))
    if (n.children.length > 0) focus.current = null
  }, [nodes])

  const more = async (n: GNode) => {
    if (!n.owner) return
    const next = (limits[n.owner] ?? PAGE) + PAGE
    const list = kids[n.owner]
    if (list && next > list.entries.length && list.entries.length < list.total) await onMore(n.owner)
    setLimits((l) => ({ ...l, [n.owner!]: next }))
  }

  return (
    <div className="relative">
      <div
        ref={box}
        className="af-graph relative h-[68vh] cursor-grab touch-none overflow-hidden select-none active:cursor-grabbing"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
      >
        <div className="absolute top-0 left-0 origin-top-left" style={{ transform: `translate(${view.x}px, ${view.y}px) scale(${view.k})`, width, height }}>
          <svg className="absolute inset-0 overflow-visible" width={width} height={height} aria-hidden>
            {edges.map(({ from, to }) => {
              const x1 = from.x + NODE_W
              const y1 = from.y + NODE_H / 2
              const x2 = to.x
              const y2 = to.y + NODE_H / 2
              const mx = (x1 + x2) / 2
              const color = to.kind === 'more' ? '#a1a1aa' : COLOR[to.status]
              const hot = onPath.has(to.id)
              const dim = onPath.size > 0 && !hot
              const blocked = to.status === 'blocked' || to.status === 'ask'
              return (
                <g key={to.id} opacity={dim ? 0.28 : 1}>
                  <path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none" stroke={color} strokeOpacity={0.18} strokeWidth={hot ? 9 : 6} strokeLinecap="round" />
                  <path
                    d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
                    fill="none"
                    stroke={color}
                    strokeWidth={hot ? 2.75 : 1.75}
                    strokeLinecap="round"
                    strokeDasharray={blocked ? '5 6' : to.kind === 'more' ? '2 5' : undefined}
                    className={!blocked && to.kind !== 'more' ? 'af-flow' : undefined}
                  />
                  {blocked && to.kind !== 'more' && (
                    <g transform={`translate(${x2 - 14},${y2})`}>
                      <circle r={7} fill="var(--background)" stroke={color} strokeWidth={1.5} />
                      <path d="M-3,-3 L3,3 M3,-3 L-3,3" stroke={color} strokeWidth={1.6} strokeLinecap="round" />
                    </g>
                  )}
                </g>
              )
            })}
            {edges.length > 0 && (
              <circle cx={NODE_W} cy={nodes[0].y + NODE_H / 2} r={4} fill="var(--brand)" />
            )}
          </svg>

          {nodes.map((n) => {
            const pos = { left: n.x, top: n.y, width: NODE_W, height: NODE_H }
            const dim = onPath.size > 0 && !onPath.has(n.id) && n.kind !== 'agent'
            if (n.kind === 'agent') {
              return (
                <div key={n.id} data-node className="absolute flex items-center gap-3 rounded-2xl bg-linear-to-br from-brand to-brand/70 px-4 text-white shadow-lg ring-1 ring-white/10" style={pos}>
                  <div className="grid size-8 place-items-center rounded-lg bg-white/15">
                    <Bot className="size-4.5" />
                  </div>
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold">{n.label}</div>
                    <div className="text-[11px] text-white/75">What it can reach →</div>
                  </div>
                </div>
              )
            }
            if (n.kind === 'more') {
              return (
                <button
                  key={n.id}
                  data-node
                  onClick={() => more(n)}
                  className={cn('absolute flex items-center justify-center gap-2 rounded-xl border border-dashed bg-card/60 text-xs text-muted-foreground transition hover:border-foreground/30 hover:text-foreground', dim && 'opacity-40')}
                  style={pos}
                >
                  <Plus className="size-3.5" /> Show {Math.min(PAGE, n.hidden ?? PAGE)} of {n.label}
                </button>
              )
            }
            if (n.kind === 'group') {
              const Icon = GROUP_ICON[n.id] ?? Folder
              return (
                <div key={n.id} data-node className={cn('absolute flex items-center gap-3 rounded-xl border bg-card px-3 shadow-sm transition-opacity', dim && 'opacity-40')} style={pos}>
                  <div className="grid size-8 shrink-0 place-items-center rounded-lg" style={{ background: COLOR[n.status] + '1f', color: COLOR[n.status] }}>
                    <Icon className="size-4" />
                  </div>
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold">{n.label}</div>
                    <div className="truncate text-[11px] text-muted-foreground">{n.sub}</div>
                  </div>
                  {(n.group?.children.length ?? 0) > 0 && (
                    <button
                      title={openGroups.has(n.id) ? 'Collapse' : `Show ${n.group!.children.length}`}
                      onClick={() => expandGroup(n.id)}
                      className="absolute top-1/2 -right-3 grid h-6 min-w-6 -translate-y-1/2 place-items-center rounded-full border bg-background px-1 text-[10px] font-semibold text-muted-foreground shadow-sm transition hover:text-foreground"
                    >
                      {openGroups.has(n.id) ? <Minus className="size-3" /> : n.group!.children.length}
                    </button>
                  )}
                </div>
              )
            }
            const f = n.fs!
            const isSel = sel?.path === f.path
            const isOpen = open.has(f.path)
            const Icon = f.kind === 'symlink' ? Link2 : f.is_dir ? Folder : File
            const color = COLOR[n.status]
            return (
              <div
                key={n.id}
                data-node
                role="button"
                tabIndex={0}
                onClick={() => onSelect(f)}
                onDoubleClick={() => f.expandable && expand(f)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') onSelect(f)
                  if (e.key === ' ' && f.expandable) {
                    e.preventDefault()
                    expand(f)
                  }
                }}
                className={cn(
                  'group absolute flex cursor-pointer items-center gap-2.5 overflow-visible rounded-xl border bg-card pr-2 pl-0 shadow-sm transition-[box-shadow,opacity] outline-none hover:shadow-md focus-visible:ring-2 focus-visible:ring-ring',
                  isSel && 'shadow-md ring-2',
                  dim && 'opacity-40',
                )}
                style={{ ...pos, ...(isSel ? { ['--tw-ring-color' as string]: color } : {}) }}
              >
                <span className="h-full w-1.5 shrink-0 rounded-l-xl" style={{ background: color }} />
                <Icon className="size-4 shrink-0 text-muted-foreground" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1">
                    <span className="truncate text-[13px] font-medium">{n.label}</span>
                    {f.builtin_lock && <Lock className="size-3 shrink-0 text-muted-foreground" />}
                  </div>
                  <div className="truncate text-[11px]" style={{ color }}>
                    {statusMeta[f.kind === 'missing' ? 'missing' : f.status].label}
                    {f.inner_rules > 0 && (
                      <span className="text-muted-foreground">
                        {' · '}
                        {f.inner_allow > 0 && `+${f.inner_allow}`}
                        {f.inner_allow > 0 && f.inner_deny > 0 && ' '}
                        {f.inner_deny > 0 && `−${f.inner_deny}`} inside
                      </span>
                    )}
                  </div>
                </div>
                {f.expandable && (
                  <button
                    title={isOpen ? 'Collapse' : 'Expand'}
                    onClick={(e) => {
                      e.stopPropagation()
                      expand(f)
                    }}
                    className="absolute top-1/2 -right-3 grid size-6 -translate-y-1/2 place-items-center rounded-full border bg-background text-muted-foreground shadow-sm transition hover:text-foreground"
                  >
                    {loading.has(f.path) ? <Loader2 className="size-3 animate-spin" /> : isOpen ? <Minus className="size-3" /> : <Plus className="size-3" />}
                  </button>
                )}
              </div>
            )
          })}
        </div>
      </div>

      <div className="absolute right-3 bottom-3 flex flex-col overflow-hidden rounded-lg border bg-background/90 shadow-sm backdrop-blur">
        <Tooltip content="Zoom in">
          <Button variant="ghost" size="icon" className="size-8 rounded-none" onClick={() => zoomAt(1.2)}>
            <Plus />
          </Button>
        </Tooltip>
        <Tooltip content="Zoom out">
          <Button variant="ghost" size="icon" className="size-8 rounded-none border-t" onClick={() => zoomAt(1 / 1.2)}>
            <Minus />
          </Button>
        </Tooltip>
        <Tooltip content="Fit to screen">
          <Button variant="ghost" size="icon" className="size-8 rounded-none border-t" onClick={fit}>
            <Maximize2 />
          </Button>
        </Tooltip>
      </div>
      <div className="pointer-events-none absolute bottom-3 left-3 rounded-md bg-background/80 px-2.5 py-1.5 text-[11px] text-muted-foreground backdrop-blur">
        Click to inspect · <b>+</b> or double-click to expand · drag to move · pinch or ⌘-scroll to zoom
      </div>
    </div>
  )
}
