import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { mkdir, writeFile } from 'node:fs/promises'
import { setTimeout as delay } from 'node:timers/promises'

const composePath = fileURLToPath(new URL('./compose.yaml', import.meta.url))
const root = fileURLToPath(new URL('../../', import.meta.url))
const artifacts = fileURLToPath(new URL('./.artifacts/', import.meta.url))
const urls = { a1: 'http://127.0.0.1:18180', a2: 'http://127.0.0.1:18181', b: 'http://127.0.0.1:18182' }
function command(program, args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(program, args, { cwd: root, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] })
    let out = '', err = ''
    child.stdout.on('data', x => { out += x }); child.stderr.on('data', x => { err += x })
    child.on('error', reject)
    child.on('exit', code => code === 0 ? resolve(out) : reject(new Error(`${program} failed (${code}): ${err.slice(-2000)}`)))
    child.stdin.end(input)
  })
}
const compose = (args, input) => command('docker', ['compose', '-f', composePath, ...args], input)
const cli = async (service, args) => JSON.parse(await compose(['exec', '-T', service, `fleetops-${service === 'b' ? 'b' : 'a'}`, ...args, '--config', '/data/config.yaml']))
const access = async service => JSON.parse(await compose(['exec', '-T', service, 'cat', '/data/bootstrap.json']))
async function request(service, path, token, options = {}) {
  return fetch(urls[service] + path, { ...options, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers }, signal: AbortSignal.timeout(5000), redirect: 'error' })
}
async function login(service, credential) {
  const res = await request(service, '/api/v1/session', undefined, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ credential }) })
  assert.equal(res.status, 200, `login ${service}`)
  return res.json()
}
async function until(description, check, timeout = 30000) {
  const deadline = Date.now() + timeout
  let lastError
  while (Date.now() < deadline) {
    try { const value = await check(); if (value) return value } catch (e) { lastError = e }
    await delay(350)
  }
  throw new Error(`${description} timed out${lastError ? `: ${lastError.message}` : ''}`)
}
const live = service => until(`${service} ready`, async () => (await request(service, '/api/v1/session')).status === 401)
await mkdir(artifacts, { recursive: true })
const checks = []
let stoppedA = false, stoppedB = false
let bToken
try {
  await Promise.all(['a1', 'a2', 'b'].map(live))
  const [a1, a2, b] = await Promise.all(['a1', 'a2', 'b'].map(access))
  assert.notEqual(a1.nodeId, a2.nodeId)
  const s1 = await login('a1', a1.credential), s2 = await login('a2', a2.credential)
  const status1 = await until('A metrics ready', async () => { const r = await request('a1', '/api/v1/status', s1.token); return r.status === 200 && r.json() })
  assert.equal(status1.nodeId, a1.nodeId)
  assert.equal(status1.metricsScope, 'container-test')
  assert.equal((await request('a2', '/api/v1/status', s1.token)).status, 401)
  assert.equal((await request('a1', '/api/v1/status')).status, 401)
  assert.equal((await request('a1', '/api/v1/session', s1.token, { method: 'DELETE', body: 'x'.repeat(32769) })).status, 413)
  assert.equal((await request('a1', '/api/v1/session', s1.token)).status, 200)
  checks.push('independent node identities', 'authenticated real metrics', 'cross-node token isolation', 'oversized DELETE has no side effect')
  const allowedOrigin = 'https://web.fixture.test'
  const preflight = await request('a1', '/api/v1/status', undefined, { method: 'OPTIONS', headers: { Origin: allowedOrigin, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization,content-type' } })
  assert.equal(preflight.status, 204)
  assert.equal(preflight.headers.get('access-control-allow-origin'), allowedOrigin)
  const unauthorized = await request('a1', '/api/v1/status', undefined, { headers: { Origin: allowedOrigin } })
  assert.equal(unauthorized.status, 401)
  assert.equal(unauthorized.headers.get('access-control-allow-origin'), allowedOrigin)
  assert.equal((await request('a1', '/api/v1/status', s1.token, { headers: { Origin: 'https://denied.fixture.test' } })).status, 403)
  checks.push('exact CORS preflight and 401 headers')
  const oldTokens = await Promise.all(['a1', 'a2'].map(service => cli(service, ['list-tokens'])))
  const t1 = await cli('a1', ['issue-token', '--name', 'simulation-monitor']), t2 = await cli('a2', ['issue-token', '--name', 'simulation-monitor'])
  assert.equal((await request('a1', '/api/v1/status', t1.token)).status, 200)
  assert.equal((await request('a1', '/api/v1/session', t1.token)).status, 403)
  const targets = { targets: [{ id: 'a1', name: '模拟节点 A1', url: 'http://a1:18080', expected_node_id: a1.nodeId, token: t1.token }, { id: 'a2', name: '模拟节点 A2', url: 'http://a2:18080', expected_node_id: a2.nodeId, token: t2.token }] }
  await compose(['exec', '-T', 'b', 'sh', '-c', 'umask 077; cat > /data/targets.yaml'], JSON.stringify(targets))
  await compose(['restart', 'b']); await live('b')
  bToken = (await login('b', b.credential)).token
  const observation = async () => { const r = await request('b', '/api/v1/monitor', bToken); assert.equal(r.status, 200); return r.json() }
  const events = async () => (await (await request('b', '/api/v1/events?limit=100', bToken)).json()).events
  await until('both targets online', async () => { const s = await observation(); return s.targets.length === 2 && s.targets.every(t => t.state === 'online') && s })
  for (const [i, service] of ['a1', 'a2'].entries()) for (const old of oldTokens[i]) if (old.name === 'simulation-monitor') await compose(['exec', '-T', service, 'fleetops-a', 'revoke-token', '--config', '/data/config.yaml', '--id', old.id])
  checks.push('machine token cannot access sessions', 'B independently polls A1 and A2', 'machine-token rotation verified before revoking old tokens')
  await compose(['stop', 'b']); stoppedB = true
  assert.equal((await request('a1', '/api/v1/status', s1.token)).status, 200)
  assert.equal((await request('a2', '/api/v1/status', s2.token)).status, 200)
  await command(process.execPath, ['c-desktop/scripts/smoke.mjs', '--simulation'])
  checks.push('real Windows EXE connects both A nodes with B stopped')
  await compose(['start', 'b']); stoppedB = false; await live('b')
  assert.equal((await request('b', '/api/v1/monitor', bToken)).status, 401)
  bToken = (await login('b', b.credential)).token
  await until('B reobserves online', async () => (await observation()).targets.every(t => t.state === 'online'))
  await command(process.execPath, ['c-desktop/scripts/smoke.mjs', '--simulation', '--monitor'])
  checks.push('real Windows EXE connects B and reads monitor targets')
  const before = await events(), lastID = before[0]?.id ?? 0
  await compose(['stop', 'a1']); stoppedA = true
  const offline = await until('A1 failure threshold', async () => { const s = await observation(); return s.targets.find(t => t.id === 'a1')?.state === 'unreachable' && s })
  assert.equal(offline.targets.find(t => t.id === 'a2').state, 'online')
  assert.equal(offline.targets.find(t => t.id === 'a1').stale, true)
  await until('repeated failure does not duplicate event', async () => (await observation()).targets.find(t => t.id === 'a1').failures >= 5)
  let recent = (await events()).filter(e => e.id > lastID)
  assert.equal(recent.filter(e => e.targetId === 'a1' && e.kind === 'unreachable').length, 1)
  await compose(['start', 'a1']); stoppedA = false; await live('a1')
  await until('A1 recovers', async () => (await observation()).targets.find(t => t.id === 'a1')?.state === 'online')
  recent = (await events()).filter(e => e.id > lastID)
  assert.equal(recent.filter(e => e.targetId === 'a1' && e.kind === 'recovered').length, 1)
  assert.equal(recent.filter(e => e.targetId === 'a2').length, 0)
  assert.equal((await request('a1', '/api/v1/status', s1.token)).status, 401)
  assert.equal((await login('a1', a1.credential)).nodeId, a1.nodeId)
  assert.equal((await request('a1', '/api/v1/status', t1.token)).status, 200)
  checks.push('B continues while both C interfaces are closed', 'A1 threshold, stale, event deduplication and recovery; A2 unaffected', 'A restart preserves identity and machine tokens, invalidates sessions')
  const persisted = recent.map(e => e.id)
  await compose(['restart', 'b']); await live('b'); bToken = (await login('b', b.credential)).token
  const restoredEvents = await events()
  assert(persisted.every(id => restoredEvents.some(e => e.id === id)))
  await until('B restart observes online', async () => (await observation()).targets.every(t => t.state === 'online'))
  assert.equal((await events()).filter(e => e.id > Math.max(...persisted, lastID)).length, 0)
  checks.push('B restart preserves events without fabricated recovery')
  const testToken = await cli('a1', ['issue-token', '--name', 'revocation-check'])
  await compose(['exec', '-T', 'a1', 'fleetops-a', 'revoke-token', '--config', '/data/config.yaml', '--id', testToken.id])
  assert.equal((await request('a1', '/api/v1/status', testToken.token)).status, 401)
  const logs = await compose(['logs', '--no-color'])
  for (const secret of [a1.credential, a2.credential, b.credential, t1.token, t2.token, s1.token, s2.token, bToken]) assert(!logs.includes(secret), 'secret found in service logs')
  checks.push('runtime machine-token revocation', 'service logs contain no test credentials or tokens')
  const report = { passed: true, checks, metricsScope: 'container-test', notValidated: ['trusted HTTPS/CORS browser connection', 'Linux systemd on a real host', '1Panel deployment'], servicesLeftRunning: ['a1', 'a2', 'b'] }
  await writeFile(`${artifacts}/verification.json`, JSON.stringify(report, null, 2))
  console.log(JSON.stringify(report, null, 2))
} finally {
  if (stoppedA) await compose(['start', 'a1'])
  if (stoppedB) await compose(['start', 'b'])
}
