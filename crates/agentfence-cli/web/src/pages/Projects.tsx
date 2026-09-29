import * as React from 'react'
import { ChevronRight, FolderKanban, Search, ShieldAlert, ShieldCheck } from 'lucide-react'
import { get, type Project } from '@/lib/api'
import { useData, useInterval, navigate } from '@/lib/hooks'
import { useApp } from '@/lib/app-context'
import { timeAgo, tildify } from '@/lib/format'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Empty, ErrorText, Loading, Mono, PageHeader, Pagination } from '@/components/app/common'
import { AddProjectButton } from '@/features/add-project'

export default function Projects() {
  const { home } = useApp()
  const d = useData(() => get<{ projects: Project[] }>('/api/projects'))
  useInterval(() => d.reload(), 15000)
  const [q, setQ] = React.useState('')
  const [page, setPage] = React.useState(1)
  const [size, setSize] = React.useState(25)
  const all = (d.data?.projects ?? []).filter((p) => !q || p.path.toLowerCase().includes(q.toLowerCase()))
  const pages = Math.max(1, Math.ceil(all.length / size))
  const rows = all.slice((page - 1) * size, page * size)

  return (
    <>
      <PageHeader
        title="Projects"
        description="Folders your agents work in. Open one to see exactly what agents can read and change there, and to add rules for it."
        actions={<AddProjectButton onAdded={(p) => navigate('/projects/' + encodeURIComponent(p))} />}
      />
      <ErrorText error={d.error} />
      <Card>
        <div className="flex items-center gap-2 border-b p-3">
          <div className="relative w-full max-w-sm">
            <Search className="absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
            <Input
              className="pl-8"
              placeholder="Filter projects…"
              value={q}
              onChange={(e) => {
                setQ(e.target.value)
                setPage(1)
              }}
            />
          </div>
        </div>
        {d.loading && !d.data ? (
          <Loading />
        ) : all.length === 0 ? (
          <div className="p-6">
            <Empty icon={FolderKanban} title={q ? 'No matching projects' : 'No projects yet'} action={!q && <AddProjectButton onAdded={(p) => navigate('/projects/' + encodeURIComponent(p))} />}>
              {!q && 'Projects appear here automatically when an agent runs in them. You can also add one now to set up its rules in advance.'}
            </Empty>
          </div>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Project</TableHead>
                  <TableHead>Agents</TableHead>
                  <TableHead>Project rules</TableHead>
                  <TableHead className="text-right">Blocked (24 h)</TableHead>
                  <TableHead>Last agent run</TableHead>
                  <TableHead className="w-8" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((p) => (
                  <TableRow key={p.path} className="cursor-pointer" onClick={() => navigate('/projects/' + encodeURIComponent(p.path))}>
                    <TableCell className="max-w-96">
                      <div className="flex items-center gap-2 font-medium">
                        {p.name || p.path}
                        {!p.exists && <Badge variant="outline">Folder missing</Badge>}
                      </div>
                      <Mono className="block truncate text-muted-foreground">{tildify(p.path, home)}</Mono>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {p.active_sessions > 0 && (
                          <Badge variant="success">
                            <ShieldCheck /> {p.active_sessions} protected
                          </Badge>
                        )}
                        {p.unprotected_agents > 0 && (
                          <Badge variant="warning">
                            <ShieldAlert /> {p.unprotected_agents} unprotected
                          </Badge>
                        )}
                        {p.active_sessions === 0 && p.unprotected_agents === 0 && <span className="text-sm text-muted-foreground">None running</span>}
                      </div>
                    </TableCell>
                    <TableCell>
                      {p.has_project_rules ? p.trusted ? <Badge variant="violet">Custom · trusted</Badge> : <Badge variant="info">Custom</Badge> : <span className="text-sm text-muted-foreground">Uses your rules</span>}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{p.blocked_24h > 0 ? <Badge variant="danger">{p.blocked_24h}</Badge> : <span className="text-muted-foreground">0</span>}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{p.last_seen ? timeAgo(p.last_seen) : 'Never'}</TableCell>
                    <TableCell>
                      <ChevronRight className="size-4 text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <Pagination page={page} pages={pages} total={all.length} size={size} onPage={setPage} onSize={(s) => { setSize(s); setPage(1) }} />
          </>
        )}
      </Card>
    </>
  )
}
