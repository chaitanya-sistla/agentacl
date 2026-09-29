import * as React from 'react'
import { get, post, type PolicyResp, type PreviewResp, type RawDoc, type Scope } from '@/lib/api'

export function emptyDoc(scope: Scope): RawDoc {
  return {
    name: scope,
    layer: scope,
    match_: null,
    defaults: {},
    filesystem: { allow_read: [], allow_write: [], deny_read: [], deny_write: [] },
    process: { allow: [], deny: [], require_approval: [] },
    network: { allow: [], deny: [], listen: [] },
    builtin: null,
  }
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b)

/**
 * Draft of one policy file. Exactly one representation is authoritative:
 * the structured `doc` (visual editor) or the `yaml` text (YAML editor).
 */
export function usePolicyDraft(scope: Scope, project: string | null, agent: string) {
  const [loaded, setLoaded] = React.useState<PolicyResp | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [doc, setDoc] = React.useState<RawDoc | null>(null)
  const [yaml, setYaml] = React.useState('')
  const [mode, setMode] = React.useState<'doc' | 'yaml'>('doc')
  const [version, setVersion] = React.useState(0)

  const load = React.useCallback(async () => {
    try {
      const r = await get<PolicyResp>('/api/policy', { scope, project: project ?? '', agent })
      setLoaded(r)
      setDoc(r.doc ?? null)
      setYaml(r.yaml)
      setMode(r.doc ? 'doc' : 'yaml')
      setError(null)
      setVersion((v) => v + 1)
    } catch (e: any) {
      setError(e.message)
    }
  }, [scope, project, agent])

  React.useEffect(() => {
    load()
  }, [load])

  // A file that only loaded as YAML and was converted for the visual editor
  // counts as changed once it's in doc mode.
  const dirty = !!loaded && (mode === 'doc' ? !!doc && (!loaded.doc || !same(doc, loaded.doc)) : yaml !== loaded.yaml)

  /** Request body fields describing the draft (nothing when unchanged). */
  const draftBody = React.useCallback((): Record<string, unknown> => {
    const base: Record<string, unknown> = { scope, project: project ?? '', agent }
    if (!dirty) return base
    return mode === 'doc' ? { ...base, doc } : { ...base, yaml }
  }, [scope, project, agent, dirty, mode, doc, yaml])

  const updateDoc = (f: (d: RawDoc) => RawDoc) => {
    setDoc((d) => {
      const next = f(structuredClone(d ?? emptyDoc(scope)))
      return next
    })
    setMode('doc')
    setVersion((v) => v + 1)
  }
  const editYaml = (t: string) => {
    setYaml(t)
    setMode('yaml')
  }
  /** YAML → doc (for the visual editor). Returns an error if it doesn't parse. */
  const toDoc = async (): Promise<string | null> => {
    if (mode === 'doc') return null
    const r = await post<PreviewResp>('/api/policy/preview', { scope, project: project ?? '', agent, yaml })
    if (!r.ok || !r.doc) return r.error ?? 'The YAML could not be read.'
    setDoc(r.doc)
    setMode('doc')
    setVersion((v) => v + 1)
    return null
  }
  /** doc → YAML text (for the YAML tab). Returns an error if the draft is invalid. */
  const toYaml = async (): Promise<string | null> => {
    if (mode === 'yaml' || !loaded) return null
    if (!dirty) {
      setYaml(loaded.yaml)
      return null
    }
    const r = await post<PreviewResp>('/api/policy/preview', { scope, project: project ?? '', agent, doc })
    if (!r.ok) return r.error ?? 'The rules could not be converted.'
    setYaml(r.yaml)
    return null
  }
  const discard = () => {
    if (!loaded) return
    setDoc(loaded.doc ?? null)
    setYaml(loaded.yaml)
    setMode(loaded.doc ? 'doc' : 'yaml')
    setVersion((v) => v + 1)
  }
  /** Commits the YAML text edits so the map/test reflect them. */
  const applyYaml = () => setVersion((v) => v + 1)

  return { loaded, error, doc, yaml, mode, dirty, version, draftBody, updateDoc, editYaml, toDoc, toYaml, discard, reload: load, applyYaml }
}
export type PolicyDraft = ReturnType<typeof usePolicyDraft>
