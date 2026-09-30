import * as React from 'react'
import { Code2, FlaskConical, ListChecks, Network, ShieldCheck, AlertTriangle } from 'lucide-react'
import { post, type PreviewResp, type Scope } from '@/lib/api'
import { useApp } from '@/lib/app-context'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Textarea } from '@/components/ui/input'
import { Alert } from '@/components/ui/misc'
import { ErrorText, Loading } from '@/components/app/common'
import { usePolicyDraft, type PolicyDraft } from './draft'
import { AccessMap } from './AccessMap'
import { RulesEditor } from './RulesEditor'
import { BuiltinProtections } from './Builtins'
import { TestAccess } from './TestAccess'
import { SaveBar } from './SaveFlow'
import { ruleCount } from './sections'

export type EditorTab = 'access' | 'rules' | 'builtins' | 'yaml' | 'test'

export function PolicyEditor({ scope, project, agent = 'claude-code', tab, onTab, onDirty }: { scope: Scope; project: string | null; agent?: string; tab: EditorTab; onTab: (t: EditorTab) => void; onDirty?: (d: boolean) => void }) {
  const draft = usePolicyDraft(scope, project, agent)
  const { home } = useApp()
  const [tabErr, setTabErr] = React.useState<string | null>(null)
  const [warnings, setWarnings] = React.useState<string[]>([])

  // Live warnings (e.g. an allow a built-in protection overrides) for the
  // saved rules, or for the draft once it changes.
  React.useEffect(() => {
    if (!draft.loaded) return
    if (!draft.dirty) {
      setWarnings(draft.loaded.effective?.warnings ?? [])
      return
    }
    let live = true
    const t = setTimeout(async () => {
      try {
        const body = draft.draftBody()
        const r = await post<PreviewResp>('/api/policy/preview', body)
        if (live) setWarnings(r.ok ? r.effective?.warnings ?? [] : [])
      } catch {}
    }, 400)
    return () => {
      live = false
      clearTimeout(t)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft.version, draft.loaded, draft.dirty])

  React.useEffect(() => onDirty?.(draft.dirty), [draft.dirty, onDirty])
  React.useEffect(() => () => onDirty?.(false), [onDirty])
  React.useEffect(() => {
    const f = (e: BeforeUnloadEvent) => {
      if (draft.dirty) e.preventDefault()
    }
    window.addEventListener('beforeunload', f)
    return () => window.removeEventListener('beforeunload', f)
  }, [draft.dirty])

  const switchTab = async (t: EditorTab) => {
    setTabErr(null)
    if ((t === 'rules' || t === 'builtins') && draft.mode === 'yaml') {
      const e = await draft.toDoc()
      if (e) {
        setTabErr(`The YAML has a problem, so the visual editor can’t show it yet: ${e}`)
        return
      }
    }
    if (t === 'yaml') {
      const e = await draft.toYaml()
      if (e) {
        setTabErr(`The rules have a problem, so they can’t be shown as YAML yet: ${e}`)
        return
      }
    }
    onTab(t)
  }

  if (draft.error) return <ErrorText error={draft.error} />
  if (!draft.loaded) return <Loading label="Loading rules…" />

  return (
    <div>
      {draft.loaded.error && (
        <Alert variant="danger" className="mb-4">
          <AlertTriangle />
          <div>
            <div className="font-medium">The saved rules have a problem, so agents can’t start with them</div>
            <div className="mt-1 font-mono text-xs whitespace-pre-wrap">{draft.loaded.error}</div>
          </div>
        </Alert>
      )}
      {scope === 'project' && draft.loaded.trusted && (
        <Alert variant="info" className="mb-4">
          <ShieldCheck />
          <div>This project’s rules are trusted (you ran <code className="font-mono">agentacl policy trust</code>), so they may also allow things. To protect that trust, the console won’t overwrite this file: edit it in a text editor and run <code className="font-mono">agentacl policy trust</code> again.</div>
        </Alert>
      )}
      {warnings.length > 0 && (
        <Alert variant="warning" className="mb-4">
          <AlertTriangle />
          <div>
            <div className="font-medium">{warnings.length === 1 ? '1 thing to check' : `${warnings.length} things to check`}{draft.dirty ? ' in your unsaved changes' : ''}</div>
            <ul className="mt-1 flex list-disc flex-col gap-1 pl-4">
              {warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          </div>
        </Alert>
      )}
      <Tabs value={tab} onValueChange={(v) => switchTab(v as EditorTab)}>
        <TabsList className="h-auto flex-wrap">
          <TabsTrigger value="access">
            <Network /> Access map
          </TabsTrigger>
          <TabsTrigger value="rules">
            <ListChecks /> Rules <Badge variant="secondary">{ruleCount(draft.doc)}</Badge>
          </TabsTrigger>
          {scope === 'user' && (
            <TabsTrigger value="builtins">
              <ShieldCheck /> Built-in protections
            </TabsTrigger>
          )}
          <TabsTrigger value="test">
            <FlaskConical /> Test access
          </TabsTrigger>
          <TabsTrigger value="yaml">
            <Code2 /> YAML
          </TabsTrigger>
        </TabsList>
        <ErrorText error={tabErr} />
        <TabsContent value="access">
          <AccessMap draft={draft} scope={scope} agent={agent} onEditRules={() => switchTab('rules')} />
        </TabsContent>
        <TabsContent value="rules">{draft.doc ? <RulesEditor draft={draft} scope={scope} pickerStart={project ?? home} /> : <YamlOnly />}</TabsContent>
        {scope === 'user' && <TabsContent value="builtins">{draft.doc ? <BuiltinProtections draft={draft} /> : <YamlOnly />}</TabsContent>}
        <TabsContent value="test">
          <TestAccess draft={draft} home={home} />
        </TabsContent>
        <TabsContent value="yaml">
          <YamlTab draft={draft} />
        </TabsContent>
      </Tabs>
      <SaveBar draft={draft} />
    </div>
  )
}

function YamlOnly() {
  return <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">This file can only be edited as YAML right now. Open the YAML tab.</div>
}

function YamlTab({ draft }: { draft: PolicyDraft }) {
  const t = React.useRef<ReturnType<typeof setTimeout>>(undefined)
  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm text-muted-foreground">
        The exact file agents are held to. Edits here update the access map and tests as you type. See <code className="font-mono">docs/policy-model.md</code> for every option.
      </p>
      <Textarea
        spellCheck={false}
        className="min-h-[60vh] font-mono text-[13px] leading-6"
        value={draft.yaml}
        onChange={(e) => {
          draft.editYaml(e.target.value)
          clearTimeout(t.current)
          t.current = setTimeout(draft.applyYaml, 600)
        }}
      />
    </div>
  )
}
