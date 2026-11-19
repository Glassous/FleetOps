import { computed, reactive, ref } from 'vue'
import { transport } from '@transport'
import * as api from './api'
import type { Connection, Observation, Target } from './types'

const STORAGE_KEY = 'fleetops.targets.v1'
const emptyConnection = (): Connection => ({ busy: false, phase: 'idle', error: '', receivedAt: 0, events: [] })

export function useFleet() {
  const targets = ref<Target[]>([])
  const connections = reactive<Record<string, Connection>>({})
  const notice = ref('')
  const now = ref(Date.now())
  const refreshing = ref(false)
  const revisions = new Map<string, number>()
  const controllers = new Map<string, AbortController>()
  const agents = computed(() => targets.value.filter(t => t.kind === 'agent'))
  const monitor = computed(() => targets.value.find(t => t.kind === 'monitor'))
  let timer: ReturnType<typeof setInterval> | undefined

  function persist() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(targets.value.map(t => ({
        id: t.id, name: t.name, origin: t.origin, kind: t.kind,
        expectedNodeId: t.expectedNodeId, insecureAllowed: t.insecureAllowed,
      }))))
    } catch { notice.value = '本地清单保存失败。本次连接仍可用，但重新打开后需要再次添加。' }
  }

  function restore() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY)
      if (!raw) return
      const saved: unknown = JSON.parse(raw)
      if (!Array.isArray(saved)) throw new Error()
      const ids = new Set<string>()
      const origins = new Set<string>()
      let monitors = 0
      const parsed: Target[] = saved.map(t => {
        if (!t || typeof t.id !== 'string' || ids.has(t.id) || typeof t.name !== 'string' || !t.name.trim()
          || !['agent', 'monitor'].includes(t.kind) || typeof t.origin !== 'string'
          || typeof t.insecureAllowed !== 'boolean' || (t.expectedNodeId !== undefined && typeof t.expectedNodeId !== 'string')) throw new Error()
        const origin = api.normalizeOrigin(t.origin)
        if (origins.has(origin) || (t.kind === 'monitor' && ++monitors > 1)) throw new Error()
        ids.add(t.id); origins.add(origin)
        return { id: t.id, name: t.name, origin, kind: t.kind, expectedNodeId: t.expectedNodeId, insecureAllowed: t.insecureAllowed }
      })
      targets.value = parsed
      for (const target of parsed) connections[target.id] = emptyConnection()
    } catch { notice.value = '本地节点清单无法读取，尚未覆盖原数据。请重新添加节点或检查浏览器存储。' }
  }

  function cancel(id: string) {
    revisions.set(id, (revisions.get(id) ?? 0) + 1)
    controllers.get(id)?.abort()
    controllers.delete(id)
    if (connections[id]) connections[id].busy = false
  }

  function operation(id: string) {
    const controller = new AbortController()
    controllers.set(id, controller)
    const revision = revisions.get(id) ?? 0
    return {
      signal: AbortSignal.any([controller.signal, AbortSignal.timeout(8000)]),
      current: () => connections[id] !== undefined && (revisions.get(id) ?? 0) === revision,
    }
  }

  function message(error: unknown) {
    if (error instanceof api.ApiError) return error.message
    if (error instanceof Error && error.name === 'TimeoutError') return '请求超时，请检查节点地址和网络。'
    return transport.desktop
      ? '连接失败，请检查服务、端口及 HTTPS 证书。'
      : '连接失败，请检查 HTTPS 证书、节点的 CORS 白名单与网络。'
  }

  function requireUsable(target: Target) {
    if (target.origin.startsWith('http:')) {
      if (!transport.desktop) throw new Error('Web 版仅支持 HTTPS。此 HTTP 节点请使用 Windows 客户端。')
      if (!target.insecureAllowed) throw new Error('请先确认 HTTP 明文传输风险。')
    }
  }

  async function add(input: Omit<Target, 'id' | 'expectedNodeId'>) {
    const target: Target = { ...input, id: crypto.randomUUID(), name: input.name.trim(), origin: api.normalizeOrigin(input.origin) }
    if (!target.name || target.name.length > 64) throw new Error('名称须为 1–64 个字符')
    if (targets.value.some(t => t.origin === target.origin)) throw new Error('这个地址已经在清单中')
    if (target.kind === 'monitor' && monitor.value) throw new Error('首版只连接一个持续监控服务，请先移除原连接')
    requireUsable(target)
    await transport.setTargets([...targets.value.map(t => t.origin), target.origin])
    targets.value.push(target)
    connections[target.id] = emptyConnection()
    persist()
    return target
  }

  async function connect(target: Target, credential: string) {
    const state = connections[target.id]
    if (state.busy) return
    requireUsable(target)
    cancel(target.id)
    const previousToken = state.token
    state.token = undefined
    state.expiresAt = undefined
    state.error = ''
    state.busy = true
    const op = operation(target.id)
    if (previousToken) void api.logout(target.origin, previousToken).catch(() => {})
    try {
      const session = await api.login(target.origin, credential, op.signal)
      if (!op.current()) { void api.logout(target.origin, session.token).catch(() => {}); return }
      if (target.expectedNodeId && target.expectedNodeId !== session.nodeId) {
        void api.logout(target.origin, session.token).catch(() => {})
        throw new api.ApiError('节点身份已改变。请核对服务器；如确认已重装，移除后重新添加。')
      }
      target.expectedNodeId = session.nodeId
      persist()
      state.token = session.token
      state.expiresAt = session.expiresAt
    } catch (error) {
      if (op.current()) { state.phase = 'error'; state.error = message(error) }
      throw error
    } finally {
      if (op.current()) { state.busy = false; controllers.delete(target.id) }
    }
    if (op.current() && state.token) await refreshOne(target)
  }

  async function refreshOne(target: Target) {
    const state = connections[target.id]
    if (!state?.token || state.busy) return
    if (Date.parse(state.expiresAt ?? '') <= Date.now()) {
      state.token = undefined; state.phase = 'idle'; state.error = '会话已到期，请重新登录。'; return
    }
    state.busy = true
    const op = operation(target.id)
    try {
      if (target.kind === 'agent') {
        const status = await api.agentStatus(target.origin, state.token, op.signal)
        if (!op.current()) return
        if (status.nodeId !== target.expectedNodeId) {
          state.token = undefined
          throw new api.ApiError('节点身份不匹配，已停止读取。请核对后重新添加节点。')
        }
        state.status = status
      } else {
        const snapshot = await api.monitorStatus(target.origin, state.token, op.signal)
        if (!op.current()) return
        if (snapshot.monitorId !== target.expectedNodeId) {
          state.token = undefined
          throw new api.ApiError('监控服务身份不匹配，已停止读取。')
        }
        state.monitor = snapshot
        const events = await api.monitorEvents(target.origin, state.token, op.signal)
        if (!op.current()) return
        state.events = events.events
      }
      state.receivedAt = Date.now()
      state.phase = 'online'
      state.error = ''
    } catch (error) {
      if (!op.current()) return
      if (error instanceof api.ApiError && [401, 403].includes(error.status)) state.token = undefined
      state.phase = 'error'
      state.error = message(error)
    } finally {
      if (op.current()) { state.busy = false; controllers.delete(target.id) }
    }
  }

  async function refreshAll(force = false) {
    if (refreshing.value || (!force && document.hidden)) return
    refreshing.value = true
    const queue = targets.value.filter(t => connections[t.id]?.token)
    try {
      await Promise.all(Array.from({ length: Math.min(queue.length, 4) }, async () => {
        while (queue.length) { const target = queue.shift(); if (target) await refreshOne(target) }
      }))
    } finally { refreshing.value = false; now.value = Date.now() }
  }

  async function disconnect(target: Target) {
    const state = connections[target.id]
    const token = state.token
    cancel(target.id)
    state.token = undefined; state.expiresAt = undefined; state.phase = 'idle'; state.error = ''
    state.status = undefined; state.monitor = undefined; state.events = []; state.receivedAt = 0
    if (token) {
      try { await api.logout(target.origin, token) }
      catch { notice.value = '本地会话已清除，远端注销未确认；服务端会话将在到期后失效。' }
    }
  }

  async function remove(target: Target) {
    await disconnect(target)
    const next = targets.value.filter(t => t.id !== target.id)
    await transport.setTargets(next.map(t => t.origin))
    targets.value = next
    delete connections[target.id]
    persist()
  }

  function fresh(target: Target) {
    const c = connections[target.id]
    return !!c?.token && c.phase === 'online' && now.value - c.receivedAt < 20000
  }

  function observationStale(observation: Observation) {
    const target = monitor.value
    if (!target || !fresh(target)) return true
    const c = connections[target.id]
    const snapshot = c.monitor
    if (!snapshot || !observation.succeededAt) return true
    return observation.stale || Date.parse(snapshot.generatedAt) - Date.parse(observation.succeededAt)
      + now.value - c.receivedAt > snapshot.staleAfterSeconds * 1000
  }

  function monitorHealthy() {
    const target = monitor.value
    if (!target || !fresh(target)) return false
    const c = connections[target.id]
    const snapshot = c.monitor
    return !!snapshot?.storageHealthy && !!snapshot.heartbeatAt
      && Date.parse(snapshot.generatedAt) - Date.parse(snapshot.heartbeatAt) + now.value - c.receivedAt < snapshot.staleAfterSeconds * 1000
  }

  const onVisibility = () => { now.value = Date.now(); if (!document.hidden) void refreshAll(true) }
  async function start() {
    restore()
    try { await transport.setTargets(targets.value.map(t => t.origin)) }
    catch { notice.value = '原生连接初始化失败，请确认是在 Mygo 客户端中打开桌面界面。' }
    let tick = 0
    timer = setInterval(() => { now.value = Date.now(); if (++tick % 5 === 0) void refreshAll() }, 1000)
    document.addEventListener('visibilitychange', onVisibility)
  }
  function stop() {
    clearInterval(timer)
    document.removeEventListener('visibilitychange', onVisibility)
    for (const target of targets.value) cancel(target.id)
  }

  return { targets, connections, notice, now, refreshing, agents, monitor, add, connect, disconnect, remove,
    refreshAll, fresh, observationStale, monitorHealthy, start, stop }
}
