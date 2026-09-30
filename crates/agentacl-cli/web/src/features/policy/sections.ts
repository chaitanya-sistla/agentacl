import type { RawDoc, RawRule } from '@/lib/api'

export type SectionKey =
  | 'filesystem.allow_read'
  | 'filesystem.allow_write'
  | 'filesystem.deny_read'
  | 'filesystem.deny_write'
  | 'process.allow'
  | 'process.deny'
  | 'process.require_approval'
  | 'network.allow'
  | 'network.deny'
  | 'network.listen'

export interface SectionDef {
  key: SectionKey
  group: 'Files & folders' | 'Programs' | 'Network'
  title: string
  help: string
  kind: RawRule['kind']
  allow: boolean
  placeholder: string
  tone: 'allow' | 'deny' | 'ask'
}

export const SECTIONS: SectionDef[] = [
  { key: 'filesystem.allow_read', group: 'Files & folders', title: 'Can read', help: 'Agents may open and read these, in addition to the project.', kind: 'path', allow: true, placeholder: '${HOME}/shared-docs/**', tone: 'allow' },
  { key: 'filesystem.allow_write', group: 'Files & folders', title: 'Can read & change', help: 'Agents may create, edit and delete files here.', kind: 'path', allow: true, placeholder: '${HOME}/scratch/**', tone: 'allow' },
  { key: 'filesystem.deny_read', group: 'Files & folders', title: 'Blocked', help: 'Agents can’t read, change, delete or rename these — even inside the project.', kind: 'path', allow: false, placeholder: '${PROJECT}/customer-data/**', tone: 'deny' },
  { key: 'filesystem.deny_write', group: 'Files & folders', title: 'Read-only', help: 'Agents can read these but not change them.', kind: 'path', allow: false, placeholder: '${PROJECT}/migrations/**', tone: 'deny' },
  { key: 'process.allow', group: 'Programs', title: 'Allowed programs', help: 'No effect today: programs run unless blocked, and a block always wins over an allow.', kind: 'command', allow: true, placeholder: 'git *', tone: 'allow' },
  { key: 'process.deny', group: 'Programs', title: 'Blocked programs', help: 'Agents can’t run these commands (kernel-enforced by program path).', kind: 'command', allow: false, placeholder: 'terraform apply *', tone: 'deny' },
  { key: 'process.require_approval', group: 'Programs', title: 'Needs approval', help: 'Blocked for now — approval prompts are not available yet.', kind: 'command', allow: false, placeholder: 'kubectl delete *', tone: 'ask' },
  { key: 'network.allow', group: 'Network', title: 'Allowed sites', help: 'Hosts agents may connect to. Everything else is blocked by default.', kind: 'host', allow: true, placeholder: 'api.github.com', tone: 'allow' },
  { key: 'network.deny', group: 'Network', title: 'Blocked sites', help: 'Always blocked, even if allowed elsewhere.', kind: 'host', allow: false, placeholder: '*.pastebin.com', tone: 'deny' },
  { key: 'network.listen', group: 'Network', title: 'Local ports agents may open', help: 'For dev servers. Only localhost is allowed.', kind: 'host', allow: true, placeholder: 'localhost:3000', tone: 'allow' },
]

export function rulesOf(doc: RawDoc, key: SectionKey): RawRule[] {
  const [a, b] = key.split('.') as [keyof RawDoc, string]
  return ((doc[a] as any)?.[b] ?? []) as RawRule[]
}
export function setRules(doc: RawDoc, key: SectionKey, rules: RawRule[]): RawDoc {
  const [a, b] = key.split('.') as [keyof RawDoc, string]
  ;(doc[a] as any)[b] = rules
  return doc
}
export function ruleCount(doc: RawDoc | null): number {
  if (!doc) return 0
  return SECTIONS.reduce((n, s) => n + rulesOf(doc, s.key).length, 0)
}
