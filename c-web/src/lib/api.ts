import { transport } from '@transport'
import type { AgentStatus, EventsPage, MonitorStatus, Session, Usage } from './types'

export class ApiError extends Error {
  constructor(message: string, public status = 0) { super(message) }
}

export function normalizeOrigin(raw: string): string {
  let url: URL
  try { url = new URL(raw.trim()) } catch { throw new Error('请输入完整的 http:// 或 https:// 地址和端口') }
  if (!/^https?:\/\/[^/?#\\\s]+\/?$/i.test(raw.trim()) || !['http:', 'https:'].includes(url.protocol)
    || url.username || url.password || url.search || url.hash || url.pathname !== '/' || url.port === '0') {
    throw new Error('节点地址只能包含 HTTP/HTTPS 协议、主机和端口，不能包含凭据、路径或查询参数')
  }
  return url.origin
}

const object = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const text = (v: unknown): v is string => typeof v === 'string'
const date = (v: unknown): v is string => text(v) && Number.isFinite(Date.parse(v))
const finite = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v) && v >= 0
const percent = (v: unknown): v is number => finite(v) && v <= 100
const usage = (v: unknown): v is Usage => object(v) && finite(v.totalBytes) && finite(v.usedBytes) && percent(v.usedPercent)
const nullableDate = (v: unknown) => v === null || date(v)

export function isAgentStatus(v: unknown): v is AgentStatus {
  return object(v) && v.apiVersion === '1' && text(v.nodeId) && !!v.nodeId && text(v.hostname)
    && object(v.system) && ['os', 'platform', 'kernel', 'arch'].every(key => text(v.system && (v.system as Record<string, unknown>)[key]))
    && text(v.agentVersion) && ['host', 'container-test'].includes(String(v.metricsScope))
    && date(v.sampledAt) && date(v.agentStartedAt) && finite(v.uptimeSeconds)
    && object(v.cpu) && finite(v.cpu.logicalCount) && v.cpu.logicalCount >= 1
    && (v.cpu.usagePercent === null || percent(v.cpu.usagePercent))
    && (v.memory === null || usage(v.memory)) && (v.disk === null || usage(v.disk))
}

function isMonitor(v: unknown): v is MonitorStatus {
  return object(v) && v.apiVersion === '1' && text(v.monitorId) && !!v.monitorId && text(v.instanceId)
    && date(v.startedAt) && date(v.generatedAt) && nullableDate(v.heartbeatAt)
    && finite(v.staleAfterSeconds) && v.staleAfterSeconds > 0 && typeof v.storageHealthy === 'boolean'
    && Array.isArray(v.targets) && v.targets.every(t => object(t)
      && ['id', 'name', 'url', 'expectedNodeId', 'message'].every(k => text(t[k]))
      && ['unknown', 'online', 'unreachable', 'auth_error', 'tls_error', 'identity_mismatch', 'protocol_error'].includes(String(t.state))
      && typeof t.stale === 'boolean' && finite(t.failures) && nullableDate(t.checkedAt) && nullableDate(t.succeededAt)
      && (t.status === null || isAgentStatus(t.status)))
}

async function json(response: Response): Promise<unknown> {
  if (!response.body) throw new ApiError('服务返回空响应')
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.length
      if (size > 1024 * 1024) { await reader.cancel(); throw new ApiError('响应超过 1 MiB 限额') }
      chunks.push(value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
  try { return JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new ApiError('服务返回的不是有效 JSON') }
}

async function request(origin: string, path: string, token: string | undefined, signal: AbortSignal, body?: unknown, method = 'GET'): Promise<unknown> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const response = await transport.fetch(origin + path, {
    method, headers, signal, redirect: 'error', credentials: 'omit',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (response.status === 204) return null
  let data: unknown
  try { data = await json(response) }
  catch (error) {
    if (!response.ok) throw new ApiError(`服务请求失败 (${response.status})`, response.status)
    throw error
  }
  if (!response.ok) {
    const message = object(data) && object(data.error) && text(data.error.message)
      ? data.error.message.slice(0, 240) : `服务请求失败 (${response.status})`
    throw new ApiError(message, response.status)
  }
  return data
}

export async function login(origin: string, credential: string, signal: AbortSignal): Promise<Session> {
  const v = await request(origin, '/api/v1/session', undefined, signal, { credential }, 'POST')
  if (!object(v) || !text(v.token) || !v.token || !text(v.nodeId) || !v.nodeId || !date(v.expiresAt)) throw new ApiError('登录响应不符合协议')
  return v as unknown as Session
}
export async function logout(origin: string, token: string): Promise<void> {
  await request(origin, '/api/v1/session', token, AbortSignal.timeout(5000), undefined, 'DELETE')
}
export async function agentStatus(origin: string, token: string, signal: AbortSignal): Promise<AgentStatus> {
  const v = await request(origin, '/api/v1/status', token, signal)
  if (!isAgentStatus(v)) throw new ApiError('节点状态不符合 v1 协议')
  return v
}
export async function monitorStatus(origin: string, token: string, signal: AbortSignal): Promise<MonitorStatus> {
  const v = await request(origin, '/api/v1/monitor', token, signal)
  if (!isMonitor(v)) throw new ApiError('监控响应不符合 v1 协议')
  return v
}
export async function monitorEvents(origin: string, token: string, signal: AbortSignal): Promise<EventsPage> {
  const v = await request(origin, '/api/v1/events?limit=50', token, signal)
  if (!object(v) || !Array.isArray(v.events) || !(v.nextBefore === null || finite(v.nextBefore))
    || !v.events.every(e => object(e) && finite(e.id) && date(e.at)
      && ['targetId', 'targetName', 'state', 'message'].every(k => text(e[k]))
      && ['unreachable', 'recovered', 'error'].includes(String(e.kind)))) throw new ApiError('事件响应不符合 v1 协议')
  return v as unknown as EventsPage
}
