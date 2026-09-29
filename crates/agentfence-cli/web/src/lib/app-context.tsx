import * as React from 'react'
import type { Status } from '@/lib/api'

export interface AppCtx {
  status: Status | null
  home: string
  agents: { id: string; name: string }[]
  refreshStatus: () => void
  /** Editors report unsaved changes here; navigation asks before losing them. */
  setDirty: (d: boolean) => void
  /** Runs `f`, first asking to discard unsaved changes if there are any. */
  guard: (f: () => void) => void
}
export const AppContext = React.createContext<AppCtx>({ status: null, home: '', agents: [], refreshStatus: () => {}, setDirty: () => {}, guard: (f) => f() })
export const useApp = () => React.useContext(AppContext)
