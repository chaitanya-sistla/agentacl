import * as React from 'react'
import { get, type Project } from '@/lib/api'
import { useData } from '@/lib/hooks'
import { useApp } from '@/lib/app-context'
import { tildify } from '@/lib/format'
import { NativeSelect } from '@/components/ui/input'
import { PageHeader } from '@/components/app/common'
import { PolicyEditor, type EditorTab } from '@/features/policy/PolicyEditor'
import { useDiscardGuard } from '@/features/guard'

const KEY = 'af-context-project'

export default function Policies({ tab, focus }: { tab: string; focus?: string | null }) {
  const { home, agents } = useApp()
  const projects = useData(() => get<{ projects: Project[] }>('/api/projects'))
  const [project, setProject] = React.useState<string>(() => {
    try {
      return localStorage.getItem(KEY) ?? ''
    } catch {
      return ''
    }
  })
  const [agent, setAgent] = React.useState('claude-code')
  const g = useDiscardGuard()
  const list = projects.data?.projects ?? []

  // Default the preview context to the most recent project, once, and only
  // if nothing was remembered ("" is a deliberate "no project").
  const defaulted = React.useRef(false)
  React.useEffect(() => {
    if (defaulted.current || !projects.data) return
    defaulted.current = true
    let remembered: string | null = null
    try {
      remembered = localStorage.getItem(KEY)
    } catch {}
    if (remembered === null && list.length) setProject(list[0].path)
  }, [projects.data, list])
  // Remember only deliberate choices (not the initial empty state).
  const choose = (v: string) => {
    setProject(v)
    try {
      localStorage.setItem(KEY, v)
    } catch {}
  }

  // The tab is page state (not a navigation), mirrored into the URL without
  // a hashchange so it never trips the unsaved-changes guard.
  const [t, setT] = React.useState<EditorTab>(focus ? 'access' : ((['access', 'rules', 'builtins', 'yaml', 'test'].includes(tab) ? tab : 'access') as EditorTab))
  const onTab = (x: EditorTab) => {
    setT(x)
    history.replaceState(null, '', '#/policies?tab=' + x)
  }
  return (
    <>
      <PageHeader
        title="Policies"
        description="Your rules apply to every agent in every project on this Mac. Built-in protections sit on top and always win."
        actions={
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1 text-xs text-muted-foreground">
              Preview in project
              <NativeSelect className="w-64" value={project} onChange={(e) => { const v = e.target.value; g.guard(() => choose(v)) }}>
                <option value="">No project (machine-wide only)</option>
                {list.map((p) => (
                  <option key={p.path} value={p.path}>
                    {p.name} — {tildify(p.path, home)}
                  </option>
                ))}
              </NativeSelect>
            </label>
            <label className="flex flex-col gap-1 text-xs text-muted-foreground">
              As agent
              <NativeSelect className="w-44" value={agent} onChange={(e) => { const v = e.target.value; g.guard(() => setAgent(v)) }}>
                {agents.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </NativeSelect>
            </label>
          </div>
        }
      />
      <PolicyEditor scope="user" project={project || null} agent={agent} tab={t} onTab={onTab} focus={focus ?? undefined} onDirty={g.onDirty} />
    </>
  )
}
