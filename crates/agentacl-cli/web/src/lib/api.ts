// Typed client for the local AgentACL console API. Auth is an HttpOnly
// cookie plus the X-AgentACL header (a cross-site page can't send it).

export class ApiError extends Error {
  status: number
  body: any
  constructor(status: number, message: string, body?: any) {
    super(message)
    this.status = status
    this.body = body
  }
}

let onUnauthorized: () => void = () => {}
export function setUnauthorizedHandler(f: () => void) {
  onUnauthorized = f
}

async function call<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { 'X-AgentACL': '1' }
  if (method === 'POST') headers['Content-Type'] = 'application/json'
  const r = await fetch(path, { method, headers, credentials: 'same-origin', body: method === 'POST' ? JSON.stringify(body ?? {}) : undefined })
  const text = await r.text()
  let data: any = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = null
  }
  if (r.status === 401) {
    onUnauthorized()
    throw new ApiError(401, text || 'Not signed in', data)
  }
  // 409 carries structured JSON (conflict / needs confirm) the caller handles.
  if (!r.ok && r.status !== 409) throw new ApiError(r.status, (data && data.error) || text || `HTTP ${r.status}`, data)
  return data as T
}

export const get = <T,>(path: string, q?: Record<string, string | number | undefined | null>) => {
  const qs = q
    ? Object.entries(q)
        .filter(([, v]) => v !== undefined && v !== null && v !== '')
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
        .join('&')
    : ''
  return call<T>('GET', qs ? `${path}?${qs}` : path)
}
export const post = <T,>(path: string, body?: unknown) => call<T>('POST', path, body)

/** Redeems the one-time code from the URL fragment for a session cookie. */
export async function bootstrap(): Promise<'ok' | 'none' | string> {
  const m = location.hash.match(/code=([0-9a-fA-F]+)/)
  if (!m) return 'none'
  history.replaceState(null, '', location.pathname + '#/')
  const r = await fetch('/api/session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify({ code: m[1] }) })
  if (r.ok) return 'ok'
  const t = await r.text()
  try {
    return JSON.parse(t).error ?? t
  } catch {
    return t || 'The link could not be used.'
  }
}

// ---------- types ----------
export type Effect = 'allow' | 'deny' | 'ask'

export interface Status {
  version: string
  human: string
  home: string
  machine: string
  hostname?: string
  backend: { name: string; available: boolean; description: string }
  endpoint_security: { available: boolean; description: string }
  paths: { state: string; config: string; user_policy: string; database: string }
  warnings: { kind: string; message: string; sessions?: string[] }[]
}

export interface Session {
  session: string
  agent: string
  agent_name?: string
  pid: number
  project: string
  policy?: string
  started_at?: string
  stale: boolean | 'unknown'
  restartable: boolean
  sources?: string[]
  supervisor_pid?: number
  /** Save result: the session didn't record its rule files, so it may use this one. */
  maybe?: boolean
}

export interface InstalledAgent {
  id: string
  display_name: string
  path: string
  resolved: string
  version?: string
  confidence: 'low' | 'medium' | 'high'
  signature?: { team_id?: string; signing_id?: string; authority: string[] } | null
  sha256?: string
  running_pids: number[]
}

export interface RunningAgent {
  id: string
  name: string
  pid: number
  exe?: string
  version?: string
  cwd?: string
  project?: string | null
  started_us: number
  supervised: boolean
  session?: Session | null
}

export interface AgentsResp {
  installed: InstalledAgent[]
  running: RunningAgent[]
  discovered_at: string
}

export interface Project {
  path: string
  name: string
  sessions: number
  active_sessions: number
  last_seen: string | null
  blocked_24h: number
  unprotected_agents: number
  exists: boolean
  has_project_rules: boolean
  trusted: boolean
  saved: boolean
}

export interface Stats extends StatsExtra {
  counts_24h: { blocked: number; secrets: number; observed: number; allowed: number }
  timeline_24h: number[]
  top_blocked: { resource: string; action: string; policy?: string; rule_id?: string; count: number }[]
}

export interface Builtins {
  groups: { id: string; reason: string; patterns: string[]; enabled: boolean }[]
  always_on: { id: string; reason: string }[]
}

export interface AuditEvent {
  rowid: number
  id: string
  timestamp: string
  agent: string
  agent_version?: string
  session: string
  pid?: number
  action: string
  resource: string
  resource_display: string
  reason_display: string
  chain_display: string
  decision?: Effect | null
  enforcement?: 'enforced' | 'observed' | null
  backend: string
  source: string
  policy?: string | null
  rule_id?: string | null
  count: number
  human: string
  machine: string
}

export interface EventsResp {
  events: AuditEvent[]
  total: number
  page: number
  size: number
  pages: number
  counts_24h: Stats['counts_24h']
}

export interface RawRule {
  kind: 'path' | 'command' | 'host'
  pattern: string
  except: string[]
  id?: string | null
  reason?: string | null
}
export interface RawDoc {
  name: string
  layer: string
  match_?: { agents: string[]; projects: string[] } | null
  defaults: { filesystem?: Effect | null; network?: Effect | null; process?: Effect | null }
  filesystem: { allow_read: RawRule[]; allow_write: RawRule[]; deny_read: RawRule[]; deny_write: RawRule[] }
  process: { allow: RawRule[]; deny: RawRule[]; require_approval: RawRule[] }
  network: { allow: RawRule[]; deny: RawRule[]; listen: RawRule[] }
  builtin?: { disable: string[] } | null
}

export interface RuleView {
  policy: string
  id: string
  section: string
  effect: Effect
  pattern: string
  excepts: string[]
  reason: string
  enforceability: 'enforced' | 'enforced-coarse' | 'observed' | 'requires-es'
}

export interface Effective {
  rules: RuleView[]
  warnings: string[]
  project_unreadable: boolean
}

export type Scope = 'user' | 'project'

export interface PolicyResp {
  scope: Scope
  project: string
  agent: string
  file: string
  exists: boolean
  sha256: string | null
  yaml: string
  doc: RawDoc | null
  trusted: boolean
  effective: Effective | null
  error: string | null
}

export interface PreviewResp {
  ok: boolean
  yaml: string
  doc?: RawDoc | null
  effective?: Effective
  /** `agents` is empty when a change applies to every agent. */
  effective_diff?: { added: { key: string; agents: string[] }[]; removed: { key: string; agents: string[] }[] }
  /** Known projects (and agents) that couldn't read their project under this draft. */
  unreadable_projects?: string[]
  current_sha256?: string | null
  file_diff?: { op: ' ' | '+' | '-'; line: string }[]
  comments_lost?: boolean
  error?: string
}

export interface SaveResp {
  ok: boolean
  sha256?: string
  affected_sessions?: Session[]
  needs_confirm?: string[]
  conflict?: boolean
  current_sha256?: string
  current_yaml?: string
  unreadable_projects?: string[]
  error?: string
}

export interface Decision {
  effect: Effect
  policy: string
  rule_id: string
  reason: string
}
export type NodeStatus = 'full' | 'read-only' | 'blocked' | 'ask' | 'partial'
export interface Action {
  section?: string
  rule?: string
  display?: string
  unavailable?: string
}
export interface FsNode {
  id: string
  path: string
  name: string
  display: string
  kind: 'dir' | 'file' | 'symlink' | 'missing' | 'group'
  link_target?: string | null
  is_dir: boolean
  expandable: boolean
  read: Decision
  write: Decision
  status: NodeStatus
  inner_allow: number
  inner_deny: number
  inner_rules: number
  builtin_lock: boolean
  tcc: boolean
  actions: Record<'allow_read' | 'allow_write' | 'deny_read' | 'deny_write', Action>
}
export interface MapGroup {
  id: string
  name: string
  description: string
  children: FsNode[]
}
export interface FsList {
  path: string
  display: string
  parent: string | null
  needs_force?: boolean
  tcc_protected?: boolean
  total: number
  offset?: number
  limit?: number
  entries: FsNode[]
}

export interface EvalResp {
  effect: Effect
  policy: string
  rule_id: string
  reason: string
  trace: string[]
}

// ---- network, approvals, requests ----
export interface Category {
  id: 'ai-provider' | 'package-registry' | 'source-hosting' | 'telemetry' | 'docs' | 'cloud' | 'unknown'
  label: string
  advice: string
}
export type NetMode = 'block' | 'ask'
/** What a site resolves to right now (machine-wide policy + console rules). */
export interface SiteDecision {
  effect: Effect
  policy?: string
  rule_id?: string
  reason: string
  by: 'you' | 'console' | 'agent' | 'builtin' | 'default' | 'other'
  /** An Allow from the console would make it reachable. */
  allowable: boolean
}
export interface Site {
  host: string
  display: string
  ports: string[]
  allowed: number
  blocked: number
  first_seen: string | null
  last_seen: string | null
  agents: string[]
  projects: string[]
  last: { decision: Effect | null; policy: string | null; rule_id: string | null; reason: string | null } | null
  category: Category
  policy_rule: '' | 'allow' | 'block'
  console_rule: '' | 'allow' | 'block'
  manageable: boolean
  effective: SiteDecision
}
export interface NetworkResp {
  days: number
  mode: NetMode
  sites: Site[]
  patterns: { pattern: string; effect: 'allow' | 'block' }[]
}
export interface Approval {
  id: string
  session: string
  agent: string
  agent_name: string
  project: string
  host: string
  display: string
  port: number
  created: string
  expires: string
  category: Category
}
export interface ApprovalsResp {
  approvals: Approval[]
  requests_new: number
  mode: NetMode
}
export type AnswerKind = 'once' | 'session' | 'always' | 'block' | 'block-always'
export interface RequestGroup {
  key: string
  kind: 'network' | 'file' | 'secret' | 'locked' | 'program' | 'other'
  target: string
  display: string
  actions: string[]
  samples: string[]
  /** File requests: the exact paths refused (up to 50), who asked, and whether to change them. */
  paths?: { path: string; agents: string[]; write: boolean }[]
  paths_truncated?: boolean
  count: number
  first_seen: string
  last_seen: string
  agents: string[]
  projects: string[]
  policy: string
  rule_id: string
  reason: string
  dismissed: boolean
  category?: Category
  manageable?: boolean
  effective?: SiteDecision
}
export interface RequestsResp {
  days: number
  /** This page. */
  requests: RequestGroup[]
  dismissed: number
  total: number
  page: number
  size: number
  pages: number
  /** All visible requests, every kind. */
  all: number
  counts: Partial<Record<'network' | 'file' | 'secret' | 'program' | 'other', number>>
  /** Keys of every undismissed request matching the filter (all pages). */
  keys: string[]
}
export interface StatsExtra {
  hourly: { allowed: number; blocked: number }[]
  top_blocked_sites: { host: string; count: number; category: Category }[]
  top_allowed_sites: { host: string; count: number; category: Category }[]
  blocked_by_kind: { kind: string; count: number }[]
  sites_total: number
  sites_blocked: number
}

export interface AccessRule {
  section: 'allow_read' | 'allow_write' | 'network.allow'
  pattern: string
  display: string
}
export interface AccessEntry {
  file: string
  agent: string | null
  agent_name: string | null
  project: string | null
  rules: AccessRule[]
}
export interface AccessResp {
  access: AccessEntry[]
  /** Access files left out of every session because something is wrong with them. */
  broken: { file: string; error: string }[]
  dir: string
}
export interface NotifySettings {
  quiet: boolean
  quiet_until: string | null
  wait_secs: number
  wait_choices: number[]
}

export interface AuditItem {
  name: string
  status: string
  detail: string
}
export interface AuditFinding {
  severity: 'high' | 'medium' | 'info'
  title: string
  detail: string
  fix: string
}
export interface AuditReport {
  agent: string
  project: string
  findings: AuditFinding[]
  credentials: AuditItem[]
  cloud_drives: AuditItem[]
  data_services: AuditItem[]
  mcp_servers: AuditItem[]
  keychain: AuditItem
  environment: AuditItem[]
  sockets: AuditItem[]
  grants: AuditItem[]
  network_mode: string
}
