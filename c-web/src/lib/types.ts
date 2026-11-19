export interface Usage { totalBytes: number; usedBytes: number; usedPercent: number }
export interface AgentStatus {
  apiVersion: '1'
  nodeId: string
  hostname: string
  system: { os: string; platform: string; kernel: string; arch: string }
  agentVersion: string
  metricsScope: 'host' | 'container-test'
  sampledAt: string
  agentStartedAt: string
  uptimeSeconds: number
  cpu: { logicalCount: number; usagePercent: number | null }
  memory: Usage | null
  disk: Usage | null
}
export interface Session { token: string; nodeId: string; expiresAt: string }
export type ObservationState = 'unknown' | 'online' | 'unreachable' | 'auth_error' | 'tls_error' | 'identity_mismatch' | 'protocol_error'
export interface Observation {
  id: string; name: string; url: string; expectedNodeId: string
  state: ObservationState; stale: boolean; failures: number; message: string
  checkedAt: string | null; succeededAt: string | null; status: AgentStatus | null
}
export interface MonitorStatus {
  apiVersion: '1'; monitorId: string; instanceId: string
  startedAt: string; heartbeatAt: string | null; generatedAt: string
  staleAfterSeconds: number; storageHealthy: boolean; targets: Observation[]
}
export interface MonitorEvent {
  id: number; at: string; targetId: string; targetName: string
  kind: 'unreachable' | 'recovered' | 'error'; state: string; message: string
}
export interface EventsPage { events: MonitorEvent[]; nextBefore: number | null }
export interface Target {
  id: string; name: string; origin: string; kind: 'agent' | 'monitor'
  expectedNodeId?: string; insecureAllowed: boolean
}
export interface Connection {
  token?: string; expiresAt?: string; busy: boolean
  phase: 'idle' | 'online' | 'error'; error: string; receivedAt: number
  status?: AgentStatus; monitor?: MonitorStatus; events: MonitorEvent[]
}
