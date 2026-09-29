import * as React from 'react'

/** Fetches on mount and whenever `deps` change; `reload` refetches. */
export function useData<T>(fn: () => Promise<T>, deps: React.DependencyList = []) {
  const [data, setData] = React.useState<T | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [tick, setTick] = React.useState(0)
  React.useEffect(() => {
    let live = true
    setLoading(true)
    fn()
      .then((d) => {
        if (live) {
          setData(d)
          setError(null)
        }
      })
      .catch((e) => live && setError(String(e?.message ?? e)))
      .finally(() => live && setLoading(false))
    return () => {
      live = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])
  const reload = React.useCallback(() => setTick((t) => t + 1), [])
  return { data, error, loading, reload, setData }
}

/** Re-runs `f` every `ms` while the tab is visible. */
export function useInterval(f: () => void, ms: number) {
  const ref = React.useRef(f)
  ref.current = f
  React.useEffect(() => {
    const id = setInterval(() => document.visibilityState === 'visible' && ref.current(), ms)
    return () => clearInterval(id)
  }, [ms])
}

/**
 * Set by the app while there are unsaved edits: returns false to veto a
 * hash navigation (links, Back/Forward); the app then asks and retries.
 */
let navGuard: ((to: string) => boolean) | null = null
export function setNavGuard(g: ((to: string) => boolean) | null) {
  navGuard = g
}

/** Hash router: #/path/segments?query */
export function useRoute() {
  const parse = () => {
    const h = location.hash.replace(/^#/, '') || '/'
    const [p, q] = h.split('?')
    return { path: p || '/', query: new URLSearchParams(q ?? '') }
  }
  const [r, setR] = React.useState(parse)
  const current = React.useRef(location.hash)
  React.useEffect(() => {
    const f = () => {
      const to = location.hash
      if (to !== current.current && navGuard && !navGuard(to)) {
        history.replaceState(null, '', current.current || '#/')
        return
      }
      current.current = to
      setR(parse())
    }
    window.addEventListener('hashchange', f)
    return () => window.removeEventListener('hashchange', f)
  }, [])
  return r
}
export function navigate(path: string) {
  location.hash = path
}
