// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useFleet } from './useFleet'
import type { Transport } from './transport'
import type { AgentStatus, MonitorStatus, Target } from './types'

const { transport } = vi.hoisted(() => ({
  transport: { desktop: false, setTargets: vi.fn<Transport['setTargets']>(), fetch: vi.fn<Transport['fetch']>() },
}))
vi.mock('@transport', () => ({ transport }))

const storageKey = 'fleetops.targets.v1'
const time = Date.parse('2026-01-01T12:00:00Z')
const at = (offset = 0) => new Date(time + offset).toISOString()
const originA = 'https://a.example:8443'
const originB = 'https://b.example:8443'
const originMonitor = 'https://monitor.example:8443'
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
const session = (nodeId = 'node-a', token = 'token-a') => ({ nodeId, token, expiresAt: at(3600000) })
const status = (nodeId = 'node-a'): AgentStatus => ({
  apiVersion: '1', nodeId, hostname: nodeId,
  system: { os: 'linux', platform: 'ubuntu', kernel: '6.8', arch: 'amd64' },
  agentVersion: '1.0', metricsScope: 'host', sampledAt: at(), agentStartedAt: at(-60000), uptimeSeconds: 60,
  cpu: { logicalCount: 2, usagePercent: 10 }, memory: null, disk: null,
})
const snapshot = (): MonitorStatus => ({
  apiVersion: '1', monitorId: 'monitor-b', instanceId: 'instance-b', startedAt: at(-7200000),
  // Deliberate server/client clock skew: freshness must use relative ages, not absolute timestamps.
  generatedAt: at(-3600000), heartbeatAt: at(-3625000), staleAfterSeconds: 30, storageHealthy: true,
  targets: [{
    id: 'observed-a', name: 'Agent A', url: originA, expectedNodeId: 'node-a', state: 'online',
    stale: false, failures: 0, message: '', checkedAt: at(-3600000), succeededAt: at(-3625000), status: status(),
  }],
})
const events = [{ id: 1, at: at(), targetId: 'observed-a', targetName: 'Agent A', kind: 'recovered', state: 'online', message: '' }]
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}

let stored: Map<string, string>
let storage: { getItem: ReturnType<typeof vi.fn>; setItem: ReturnType<typeof vi.fn> }
let documentStub: { hidden: boolean; addEventListener: ReturnType<typeof vi.fn>; removeEventListener: ReturnType<typeof vi.fn> }
const fleets: ReturnType<typeof useFleet>[] = []
function fleet() {
  const result = useFleet()
  fleets.push(result)
  return result
}
function add(f: ReturnType<typeof useFleet>, origin = originA, kind: Target['kind'] = 'agent', insecureAllowed = false) {
  return f.add({ name: kind === 'agent' ? 'Agent' : 'Monitor B', origin, kind, insecureAllowed })
}
function requests(method: string, path: string) {
  return transport.fetch.mock.calls.filter(([url, init]) => init?.method === method && new URL(url).pathname === path)
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date', 'setInterval', 'clearInterval'] })
  vi.setSystemTime(time)
  stored = new Map()
  storage = {
    getItem: vi.fn((key: string) => stored.get(key) ?? null),
    setItem: vi.fn((key: string, value: string) => { stored.set(key, value) }),
  }
  documentStub = { hidden: false, addEventListener: vi.fn(), removeEventListener: vi.fn() }
  vi.stubGlobal('localStorage', storage)
  vi.stubGlobal('document', documentStub)
  transport.desktop = false
  transport.setTargets.mockReset().mockResolvedValue(undefined)
  transport.fetch.mockReset().mockImplementation(async (url, init) => {
    const { hostname, pathname } = new URL(url)
    const identity = hostname === 'monitor.example' ? 'monitor-b' : hostname === 'b.example' ? 'node-b' : 'node-a'
    const token = hostname === 'monitor.example' ? 'token-monitor' : hostname === 'b.example' ? 'token-b' : 'token-a'
    if (pathname === '/api/v1/session' && init?.method === 'POST') return response(session(identity, token))
    if (pathname === '/api/v1/session' && init?.method === 'DELETE') return new Response(null, { status: 204 })
    if (pathname === '/api/v1/status' && init?.method === 'GET') return response(status(identity))
    if (pathname === '/api/v1/monitor' && init?.method === 'GET') return response(snapshot())
    if (pathname === '/api/v1/events' && init?.method === 'GET') return response({ events, nextBefore: null })
    throw new Error(`Unexpected request: ${init?.method} ${url}`)
  })
})

afterEach(() => {
  for (const f of fleets.splice(0)) f.stop()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('sessions and transport restrictions', () => {
  it('isolates tokens by origin and persists only target metadata, never credentials or sessions', async () => {
    const f = fleet()
    const a = await add(f)
    const b = await add(f, originB)
    await f.connect(a, 'credential-a')
    await f.connect(b, 'credential-b')
    await f.refreshAll(true)
    expect(f.connections[a.id]?.token).toBe('token-a')
    expect(f.connections[b.id]?.token).toBe('token-b')
    expect(f.connections[a.id]?.phase).toBe('online')
    expect(f.connections[b.id]?.phase).toBe('online')

    for (const [url, init] of requests('GET', '/api/v1/status')) {
      expect(new Headers(init?.headers).get('Authorization')).toBe(new URL(url).origin === originA ? 'Bearer token-a' : 'Bearer token-b')
    }
    expect(requests('GET', '/api/v1/status')).toHaveLength(4)
    for (const [key, value] of storage.setItem.mock.calls) {
      expect(key).toBe(storageKey)
      expect(value).not.toMatch(/credential-[ab]|token-[ab]|expiresAt/)
      for (const target of JSON.parse(value)) {
        expect(Object.keys(target).every(key => ['id', 'name', 'origin', 'kind', 'expectedNodeId', 'insecureAllowed'].includes(key))).toBe(true)
      }
    }
    const persisted = JSON.parse(stored.get(storageKey)!)
    expect(persisted.map((t: Target) => t.expectedNodeId)).toEqual(['node-a', 'node-b'])

    transport.fetch.mockClear()
    const reopened = fleet()
    await reopened.start()
    expect(reopened.targets.value).toEqual(persisted)
    expect(reopened.connections[a.id]?.token).toBeUndefined()
    expect(reopened.connections[b.id]?.token).toBeUndefined()
    await reopened.refreshAll(true)
    expect(transport.fetch).not.toHaveBeenCalled()
    expect(transport.setTargets).toHaveBeenLastCalledWith([originA, originB])
  })

  it('does not create a session or fetch metrics after rejected login', async () => {
    const f = fleet()
    const a = await add(f)
    transport.fetch.mockResolvedValueOnce(response({ error: { message: '凭据无效' } }, 401))
    await expect(f.connect(a, 'wrong')).rejects.toMatchObject({ status: 401 })
    expect(f.connections[a.id]).toMatchObject({ busy: false, phase: 'error', error: '凭据无效' })
    expect(f.connections[a.id]?.token).toBeUndefined()
    expect(a.expectedNodeId).toBeUndefined()
    expect(requests('GET', '/api/v1/status')).toHaveLength(0)
  })

  it.each([401, 403])('clears a rejected bearer session on HTTP %s even for non-JSON bodies', async code => {
    const f = fleet()
    const a = await add(f)
    await f.connect(a, 'credential-a')
    transport.fetch.mockResolvedValueOnce(new Response('<html>access denied</html>', { status: code }))
    await f.refreshAll(true)
    expect(f.connections[a.id]?.token).toBeUndefined()
    expect(f.connections[a.id]?.phase).toBe('error')
    expect(f.fresh(a)).toBe(false)
    transport.fetch.mockClear()
    await f.refreshAll(true)
    expect(transport.fetch).not.toHaveBeenCalled()
  })

  it('expires a session locally without sending its token again', async () => {
    const f = fleet()
    const a = await add(f)
    await f.connect(a, 'credential-a')
    vi.setSystemTime(time + 3600000)
    transport.fetch.mockClear()
    await f.refreshAll(true)
    expect(transport.fetch).not.toHaveBeenCalled()
    expect(f.connections[a.id]).toMatchObject({ phase: 'idle', token: undefined })
    expect(f.connections[a.id]?.error).toContain('会话已到期')
  })

  it('requires explicit HTTP confirmation on desktop and refuses HTTP entirely on Web', async () => {
    const f = fleet()
    const httpOrigin = 'http://a.example:8080'
    await expect(add(f, httpOrigin, 'agent', true)).rejects.toThrow('Web 版仅支持 HTTPS')
    transport.desktop = true
    await expect(add(f, httpOrigin)).rejects.toThrow('请先确认 HTTP 明文传输风险')
    expect(transport.setTargets).not.toHaveBeenCalled()
    expect(transport.fetch).not.toHaveBeenCalled()
    expect(f.targets.value).toEqual([])
    const a = await add(f, httpOrigin, 'agent', true)
    await f.connect(a, 'credential-a')
    expect(f.connections[a.id]?.phase).toBe('online')
    expect(transport.setTargets).toHaveBeenCalledWith([httpOrigin])
  })

  it('also blocks a restored desktop HTTP target from logging in on Web', async () => {
    stored.set(storageKey, JSON.stringify([{ id: 'restored', name: 'Agent', origin: 'http://a.example:8080', kind: 'agent', insecureAllowed: true }]))
    const f = fleet()
    await f.start()
    await expect(f.connect(f.targets.value[0]!, 'credential-a')).rejects.toThrow('Web 版仅支持 HTTPS')
    expect(transport.fetch).not.toHaveBeenCalled()
  })

  it('revokes the old token when logging in again and uses only the new token afterwards', async () => {
    const f = fleet()
    const a = await add(f)
    await f.connect(a, 'credential-a')
    const nextLogin = deferred<Response>()
    const original = transport.fetch.getMockImplementation()!
    transport.fetch.mockImplementation((url, init) => init?.method === 'POST' ? nextLogin.promise : original(url, init))
    const connecting = f.connect(a, 'new-credential')
    expect(requests('DELETE', '/api/v1/session')).toEqual([
      [originA + '/api/v1/session', expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer token-a' }) })],
    ])
    expect(f.connections[a.id]?.token).toBeUndefined()
    nextLogin.resolve(response(session('node-a', 'replacement-token')))
    await connecting
    expect(f.connections[a.id]?.token).toBe('replacement-token')
    expect(requests('GET', '/api/v1/status').at(-1)?.[1]?.headers).toMatchObject({ Authorization: 'Bearer replacement-token' })
  })
})

describe('pinned identities and monitor freshness', () => {
  it('rejects changed login nodeId, preserves the pin and revokes the rejected new session', async () => {
    const f = fleet()
    const a = await add(f)
    await f.connect(a, 'credential-a')
    const original = transport.fetch.getMockImplementation()!
    transport.fetch.mockImplementation((url, init) => init?.method === 'POST'
      ? Promise.resolve(response(session('replacement-node', 'rejected-token'))) : original(url, init))
    await expect(f.connect(a, 'credential-a')).rejects.toThrow('节点身份已改变')
    expect(a.expectedNodeId).toBe('node-a')
    expect(f.connections[a.id]?.token).toBeUndefined()
    expect(requests('GET', '/api/v1/status')).toHaveLength(1)
    expect(requests('DELETE', '/api/v1/session').map(([, init]) => new Headers(init?.headers).get('Authorization'))).toContain('Bearer rejected-token')
    expect(JSON.parse(stored.get(storageKey)!)[0].expectedNodeId).toBe('node-a')
  })

  it.each(['agent', 'monitor'] as const)('stops reading %s when its status identity changes', async kind => {
    const f = fleet()
    const target = await add(f, kind === 'agent' ? originA : originMonitor, kind)
    await f.connect(target, 'credential')
    transport.fetch.mockClear()
    transport.fetch.mockResolvedValueOnce(response(kind === 'agent' ? status('another-node') : { ...snapshot(), monitorId: 'another-monitor' }))
    await f.refreshAll(true)
    expect(f.connections[target.id]?.token).toBeUndefined()
    expect(f.connections[target.id]?.phase).toBe('error')
    expect(f.connections[target.id]?.error).toContain('身份不匹配')
    expect(f.fresh(target)).toBe(false)
    expect(requests('GET', '/api/v1/events')).toHaveLength(0)
  })

  it('ages B observations and heartbeat relative to the snapshot despite clock skew', async () => {
    const f = fleet()
    const b = await add(f, originMonitor, 'monitor')
    await f.connect(b, 'credential-b')
    const observation = f.connections[b.id]!.monitor!.targets[0]!
    expect(f.observationStale(observation)).toBe(false)
    expect(f.monitorHealthy()).toBe(true)
    f.now.value = time + 4999
    expect(f.observationStale(observation)).toBe(false)
    expect(f.monitorHealthy()).toBe(true)
    f.now.value = time + 5001
    expect(f.fresh(b)).toBe(true)
    expect(f.observationStale(observation)).toBe(true)
    expect(f.monitorHealthy()).toBe(false)
    f.now.value = time + 20000
    expect(f.fresh(b)).toBe(false)
  })

  it('never treats stale/missing observations, missing heartbeat or unhealthy storage as healthy', async () => {
    const f = fleet()
    const b = await add(f, originMonitor, 'monitor')
    await f.connect(b, 'credential-b')
    const monitor = f.connections[b.id]!.monitor!
    const observation = monitor.targets[0]!
    expect(f.observationStale({ ...observation, stale: true })).toBe(true)
    expect(f.observationStale({ ...observation, succeededAt: null })).toBe(true)
    monitor.storageHealthy = false
    expect(f.monitorHealthy()).toBe(false)
    monitor.storageHealthy = true
    monitor.heartbeatAt = null
    expect(f.monitorHealthy()).toBe(false)
    monitor.heartbeatAt = monitor.generatedAt
    f.now.value = time + 20000
    expect(f.monitorHealthy()).toBe(false)
    expect(f.observationStale({ ...observation, succeededAt: monitor.generatedAt })).toBe(true)
  })
})

describe('session cleanup and cancellation', () => {
  it.each(['agent', 'monitor'] as const)('disconnect clears cached %s data, aborts refresh and ignores a late response even if logout fails', async kind => {
    const f = fleet()
    const target = await add(f, kind === 'agent' ? originA : originMonitor, kind)
    await f.connect(target, 'credential')
    const state = f.connections[target.id]!
    expect(state.receivedAt).toBe(time)
    if (kind === 'agent') expect(state.status).toBeDefined()
    else { expect(state.monitor).toBeDefined(); expect(state.events).toHaveLength(1) }

    const pending = deferred<Response>()
    transport.fetch.mockReturnValueOnce(pending.promise)
    const refreshing = f.refreshAll(true)
    const requestSignal = transport.fetch.mock.calls.at(-1)![1]!.signal!
    transport.fetch.mockRejectedValueOnce(new Error('logout unavailable'))
    await f.disconnect(target)
    expect(requestSignal.aborted).toBe(true)
    expect(state).toMatchObject({ token: undefined, expiresAt: undefined, busy: false, phase: 'idle', error: '', receivedAt: 0, events: [] })
    expect(state.status).toBeUndefined()
    expect(state.monitor).toBeUndefined()
    expect(f.notice.value).toContain('远端注销未确认')
    expect(f.fresh(target)).toBe(false)

    // The transport deliberately ignores abort; the revision guard must still reject its late result.
    pending.resolve(response(kind === 'agent' ? status() : snapshot()))
    await refreshing
    expect(state.status).toBeUndefined()
    expect(state.monitor).toBeUndefined()
    expect(state.phase).toBe('idle')
    expect(state.events).toEqual([])
    expect(f.refreshing.value).toBe(false)
  })

  it.each(['disconnect', 'remove'] as const)('revokes a login token arriving after %s instead of restoring the cancelled session', async action => {
    const f = fleet()
    const a = await add(f)
    const pending = deferred<Response>()
    transport.fetch.mockReturnValueOnce(pending.promise)
    const connecting = f.connect(a, 'credential-a')
    const requestSignal = transport.fetch.mock.calls[0]![1]!.signal!
    await f[action](a)
    expect(requestSignal.aborted).toBe(true)
    pending.resolve(response(session('node-a', 'late-token')))
    await connecting
    expect(f.connections[a.id]?.token).toBeUndefined()
    expect(requests('GET', '/api/v1/status')).toHaveLength(0)
    expect(requests('DELETE', '/api/v1/session')).toEqual([
      [originA + '/api/v1/session', expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer late-token' }) })],
    ])
    if (action === 'remove') {
      expect(f.connections[a.id]).toBeUndefined()
      expect(f.targets.value).toEqual([])
      expect(transport.setTargets).toHaveBeenLastCalledWith([])
      expect(JSON.parse(stored.get(storageKey)!)).toEqual([])
    }
  })

  it('skips background polling while hidden and stop cancels active requests and lifecycle hooks', async () => {
    const f = fleet()
    await f.start()
    const a = await add(f)
    await f.connect(a, 'credential-a')
    transport.fetch.mockClear()
    documentStub.hidden = true
    await vi.advanceTimersByTimeAsync(5000)
    expect(transport.fetch).not.toHaveBeenCalled()

    const pending = deferred<Response>()
    transport.fetch.mockReturnValueOnce(pending.promise)
    const refreshing = f.refreshAll(true)
    const requestSignal = transport.fetch.mock.calls[0]![1]!.signal!
    f.stop()
    expect(requestSignal.aborted).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
    expect(documentStub.removeEventListener).toHaveBeenCalledWith('visibilitychange', documentStub.addEventListener.mock.calls[0]![1])
    pending.resolve(response(status('ignored-late-node')))
    await refreshing
    expect(f.connections[a.id]?.status?.nodeId).toBe('node-a')
    expect(f.connections[a.id]?.busy).toBe(false)
  })
})
