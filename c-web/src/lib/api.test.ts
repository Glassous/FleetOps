// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { agentStatus, ApiError, isAgentStatus, login, logout, monitorEvents, monitorStatus, normalizeOrigin } from './api'
import type { Transport } from './transport'
import type { AgentStatus, MonitorStatus } from './types'

const { transport } = vi.hoisted(() => ({
  transport: { desktop: false, setTargets: vi.fn<Transport['setTargets']>(), fetch: vi.fn<Transport['fetch']>() },
}))
vi.mock('@transport', () => ({ transport }))

const origin = 'https://agent.example:8443'
const at = '2026-01-01T00:00:00.000Z'
const signal = () => new AbortController().signal
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
const status = (): AgentStatus => ({
  apiVersion: '1', nodeId: 'node-a', hostname: 'agent-a',
  system: { os: 'linux', platform: 'ubuntu', kernel: '6.8', arch: 'amd64' },
  agentVersion: '1.0', metricsScope: 'host', sampledAt: at, agentStartedAt: at, uptimeSeconds: 0,
  cpu: { logicalCount: 2, usagePercent: null }, memory: null, disk: null,
})
const snapshot = (): MonitorStatus => ({
  apiVersion: '1', monitorId: 'monitor-b', instanceId: 'instance-1', startedAt: at,
  generatedAt: at, heartbeatAt: null, staleAfterSeconds: 30, storageHealthy: true,
  targets: [{
    id: 'a', name: 'Agent A', url: origin, expectedNodeId: 'node-a', state: 'unknown',
    stale: true, failures: 0, message: '', checkedAt: null, succeededAt: null, status: null,
  }],
})

beforeEach(() => { transport.fetch.mockReset() })

describe('node origin validation', () => {
  it('normalizes only an origin, including whitespace, default ports and IPv6', () => {
    expect(normalizeOrigin('  HTTPS://Agent.Example:443/  ')).toBe('https://agent.example')
    expect(normalizeOrigin('http://[::1]:8080/')).toBe('http://[::1]:8080')
  })

  it('rejects credentials, non-HTTP schemes, paths and even empty query/hash delimiters', () => {
    for (const raw of [
      'agent.example:8443', 'ftp://agent.example', 'https://user:password@agent.example',
      `${origin}/api`, `${origin}?limit=1`, `${origin}#section`, `${origin}?`, `${origin}/#`,
    ]) expect(() => normalizeOrigin(raw), raw).toThrow()
  })

  it('rejects paths that URL parsing would normalize back to the root', () => {
    for (const path of ['/a/..', '/.', '/%2e/', '/a/%2e%2e/', '/a/../', '/a\\..']) {
      expect(() => normalizeOrigin(origin + path), path).toThrow()
    }
  })
})

describe('v1 protocol validation', () => {
  it('accepts unavailable metrics and rejects invalid versions, dates and numeric ranges', () => {
    expect(isAgentStatus(status())).toBe(true)
    expect(isAgentStatus({ ...status(), memory: { totalBytes: 100, usedBytes: 50, usedPercent: 50 } })).toBe(true)
    for (const patch of [
      { apiVersion: '2' }, { nodeId: '' }, { sampledAt: 'not-a-date' }, { metricsScope: 'other' },
      { cpu: { logicalCount: 0, usagePercent: 10 } }, { cpu: { logicalCount: 2, usagePercent: 101 } },
      { memory: { totalBytes: 100, usedBytes: -1, usedPercent: 0 } },
      { disk: { totalBytes: Infinity, usedBytes: 0, usedPercent: 0 } },
    ]) expect(isAgentStatus({ ...status(), ...patch }), JSON.stringify(patch)).toBe(false)
    expect(isAgentStatus(null)).toBe(false)
    expect(isAgentStatus([])).toBe(false)
  })

  it('validates login token, identity and expiry before returning a session', async () => {
    const session = { token: 'session-a', nodeId: 'node-a', expiresAt: at }
    transport.fetch.mockResolvedValueOnce(response(session))
    await expect(login(origin, 'credential-a', signal())).resolves.toEqual(session)
    for (const patch of [{ token: '' }, { nodeId: '' }, { expiresAt: 'tomorrow' }]) {
      transport.fetch.mockResolvedValueOnce(response({ ...session, ...patch }))
      await expect(login(origin, 'credential-a', signal())).rejects.toThrow('登录响应不符合协议')
    }
  })

  it('rejects malformed status responses at the API boundary', async () => {
    transport.fetch.mockResolvedValueOnce(response({ ...status(), cpu: null }))
    await expect(agentStatus(origin, 'session-a', signal())).rejects.toThrow('节点状态不符合 v1 协议')
  })

  it('accepts unknown monitor observations but validates nested status, state and stale window', async () => {
    const valid = snapshot()
    transport.fetch.mockResolvedValueOnce(response(valid))
    await expect(monitorStatus(origin, 'session-b', signal())).resolves.toEqual(valid)
    const target = valid.targets[0]!
    for (const invalid of [
      { ...valid, staleAfterSeconds: 0 },
      { ...valid, heartbeatAt: 'invalid' },
      { ...valid, targets: [{ ...target, state: 'ok' }] },
      { ...valid, targets: [{ ...target, status: { ...status(), apiVersion: '2' } }] },
    ]) {
      transport.fetch.mockResolvedValueOnce(response(invalid))
      await expect(monitorStatus(origin, 'session-b', signal())).rejects.toThrow('监控响应不符合 v1 协议')
    }
  })

  it('validates event kinds and pagination', async () => {
    const event = { id: 1, at, targetId: 'a', targetName: 'Agent A', kind: 'recovered', state: 'online', message: '' }
    const page = { events: [event], nextBefore: null }
    transport.fetch.mockResolvedValueOnce(response(page))
    await expect(monitorEvents(origin, 'session-b', signal())).resolves.toEqual(page)
    for (const invalid of [{ ...page, nextBefore: -1 }, { ...page, events: [{ ...event, kind: 'online' }] }]) {
      transport.fetch.mockResolvedValueOnce(response(invalid))
      await expect(monitorEvents(origin, 'session-b', signal())).rejects.toThrow('事件响应不符合 v1 协议')
    }
  })
})

describe('HTTP session boundary', () => {
  it('sends credentials only to login, bearer tokens only on authenticated calls, and never cookies or redirects', async () => {
    const abort = signal()
    transport.fetch
      .mockResolvedValueOnce(response({ token: 'session-a', nodeId: 'node-a', expiresAt: at }))
      .mockResolvedValueOnce(response(status()))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
    await login(origin, 'secret-credential', abort)
    await agentStatus(origin, 'session-a', abort)
    await logout(origin, 'session-a')

    expect(transport.fetch).toHaveBeenNthCalledWith(1, `${origin}/api/v1/session`, {
      method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      signal: abort, redirect: 'error', credentials: 'omit', body: JSON.stringify({ credential: 'secret-credential' }),
    })
    expect(transport.fetch).toHaveBeenNthCalledWith(2, `${origin}/api/v1/status`, {
      method: 'GET', headers: { Accept: 'application/json', Authorization: 'Bearer session-a' },
      signal: abort, redirect: 'error', credentials: 'omit', body: undefined,
    })
    expect(transport.fetch).toHaveBeenNthCalledWith(3, `${origin}/api/v1/session`, expect.objectContaining({
      method: 'DELETE', headers: { Accept: 'application/json', Authorization: 'Bearer session-a' },
      redirect: 'error', credentials: 'omit', body: undefined,
    }))
  })

  it('preserves JSON authentication errors and bounds server-provided messages', async () => {
    transport.fetch.mockResolvedValueOnce(response({ error: { message: 'x'.repeat(300) } }, 401))
    await expect(login(origin, 'wrong', signal())).rejects.toMatchObject({
      status: 401, message: 'x'.repeat(240),
    })
  })

  it.each(['not JSON', null])('preserves HTTP 401 even when its body is %s', async body => {
    transport.fetch.mockResolvedValueOnce(new Response(body, { status: 401 }))
    await expect(agentStatus(origin, 'expired', signal())).rejects.toMatchObject({ status: 401 })
  })

  it('rejects invalid JSON on success and cancels responses above 1 MiB', async () => {
    transport.fetch.mockResolvedValueOnce(new Response('<html>proxy error</html>'))
    await expect(agentStatus(origin, 'session-a', signal())).rejects.toBeInstanceOf(ApiError)

    const cancel = vi.fn()
    const body = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(1024 * 1024 + 1)) },
      cancel,
    })
    transport.fetch.mockResolvedValueOnce(new Response(body))
    await expect(agentStatus(origin, 'session-a', signal())).rejects.toThrow('响应超过 1 MiB 限额')
    expect(cancel).toHaveBeenCalledOnce()
  })
})
