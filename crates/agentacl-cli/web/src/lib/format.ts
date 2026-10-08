export function timeAgo(iso?: string | null): string {
  if (!iso) return '—'
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return iso
  const s = Math.max(0, Math.round((Date.now() - t) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}
export function fmtTime(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
export function sinceUs(us: number): string {
  if (!us) return '—'
  return timeAgo(new Date(us / 1000).toISOString())
}
export function tildify(p: string | null | undefined, home?: string): string {
  if (!p) return ''
  if (home && (p === home || p.startsWith(home + '/'))) return '~' + p.slice(home.length)
  return p
}
export function baseName(p: string): string {
  const s = p.replace(/\/+$/, '')
  return s.slice(s.lastIndexOf('/') + 1) || s
}

/** Plain-language names for actions in audit events. */
export function actionLabel(a: string): string {
  const m: Record<string, string> = {
    'filesystem.read': 'Read',
    'filesystem.write': 'Write / delete',
    'process.exec': 'Run program',
    'network.connect': 'Connect',
    'network.listen': 'Open a port',
    session_start: 'Agent started',
    session_end: 'Agent exited',
    backend_warning: 'Enforcement warning',
    'policy.inputs': 'Rules loaded',
    'restart.refused': 'Restart refused',
    'policy.saved': 'Rules saved',
    'session.restart_requested': 'Restart requested',
    'session.stop_requested': 'Stop requested',
    'ui.code_replay': 'Console link reused',
    'network.mode': 'Unknown-site setting changed',
    'network.allowed': 'Site allowed',
    'network.blocked': 'Site blocked',
    'network.rule_removed': 'Site rule removed',
    'network.answered': 'Answered a site request',
  }
  return m[a] ?? a
}

export const policyLabel: Record<string, string> = {
  'protect-secrets': 'Secret protection',
  'exec-persistence': 'Persistence protection',
  'agentacl-self': 'AgentACL self-protection',
  runtime: 'Agent runtime',
  'seatbelt-baseline': 'macOS sandbox baseline',
  console: 'Your decision in the console',
  default: 'Starter rules',
  user: 'Your rules',
  project: 'Project rules',
}
export const groupLabel: Record<string, string> = {
  'env-files': '.env files',
  ssh: 'SSH keys',
  aws: 'AWS credentials',
  gcp: 'Google Cloud credentials',
  azure: 'Azure credentials',
  kube: 'Kubernetes config',
  terraform: 'Terraform state & secrets',
  'git-creds': 'Git & GitHub credentials',
  'package-creds': 'Package registry tokens',
  keys: 'Private keys & certificates',
  gpg: 'GPG keys',
  browsers: 'Browser cookies & passwords',
  'cloud-drives': 'Cloud drives (Google Drive, Dropbox, OneDrive, iCloud, Box)',
  'exec-persistence': 'Persistence (git hooks, shell rc, launch agents)',
  'agentacl-self': 'AgentACL itself',
  network: 'Network',
  environment: 'Secret environment variables',
}

/** Plain-language reason for a decision. */
export function explainRule(policy?: string | null, ruleId?: string | null, effect?: string | null, fallback = ''): string {
  const deny = effect !== 'allow'
  if (policy === 'protect-secrets') return `${groupLabel[ruleId ?? ''] ?? 'Secrets'} are protected`
  if (policy === 'exec-persistence') return 'Could run code outside the sandbox later'
  if (policy === 'agentacl-self') return 'Protects AgentACL itself'
  // A provider policy only denies the agent's own settings.
  if (policy?.startsWith('provider:') && deny) return 'The agent’s own settings are read-only — changing them could grant it more access'
  if (policy?.startsWith('provider:') && !deny) return 'The agent needs this to run'
  if (policy === 'seatbelt-baseline') return 'Blocked by the base macOS sandbox'
  if (ruleId === 'default' && deny) return 'Outside the project and no rule allows it'
  return fallback
}
