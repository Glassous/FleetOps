import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { randomBytes } from 'node:crypto'
import { spawn, execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { mkdir, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

const require = createRequire(new URL('../../c-web/package.json', import.meta.url))
const { chromium } = require('playwright')
const root = fileURLToPath(new URL('../', import.meta.url))
const dev = process.argv.includes('--dev')
const simulation = process.argv.includes('--simulation')
const vm = process.argv.includes('--vm')
const vmInput = vm ? JSON.parse(await new Promise((resolve, reject) => {
  let input = ''
  process.stdin.setEncoding('utf8')
  process.stdin.on('data', chunk => { input += chunk })
  process.stdin.on('end', () => resolve(input))
  process.stdin.on('error', reject)
})) : undefined
const realBackend = simulation || vm
const withMonitor = process.argv.includes('--monitor')
const exe = resolve(process.argv.slice(2).find(v => !v.startsWith('--')) ?? `${root}/build/windows-amd64/FleetOps.exe`)
const artifacts = resolve(root, '.artifacts')
const profile = resolve(root, '.smoke-profile', randomBytes(6).toString('hex'))
await mkdir(artifacts, { recursive: true })
await mkdir(profile, { recursive: true })
const credential = randomBytes(24).toString('hex')
const token = randomBytes(24).toString('hex')
const requests = []
const server = createServer(async (req, res) => {
  requests.push({ path: req.url, method: req.method, origin: req.headers.origin ?? null })
  res.setHeader('Content-Type', 'application/json')
  res.setHeader('Cache-Control', 'no-store')
  if (req.url === '/api/v1/session' && req.method === 'POST') {
    const chunks = []
    for await (const chunk of req) chunks.push(chunk)
    if (JSON.parse(Buffer.concat(chunks)).credential !== credential) return res.writeHead(401).end('{}')
    res.end(JSON.stringify({ token, nodeId: 'smoke-node', expiresAt: new Date(Date.now() + 60000).toISOString() }))
  } else if (req.url === '/api/v1/status' && req.headers.authorization === `Bearer ${token}`) {
    res.end(JSON.stringify({ apiVersion: '1', nodeId: 'smoke-node', hostname: 'native-http-verified', metricsScope: 'container-test', system: { os: 'linux', platform: 'Debian', kernel: '6.12', arch: 'amd64' }, agentVersion: '0.1.0', sampledAt: new Date().toISOString(), agentStartedAt: new Date().toISOString(), uptimeSeconds: 86460, cpu: { logicalCount: 4, usagePercent: 17.2 }, memory: { totalBytes: 8589934592, usedBytes: 2147483648, usedPercent: 25 }, disk: null }))
  } else if (req.url === '/api/v1/session' && req.method === 'DELETE' && req.headers.authorization === `Bearer ${token}`) res.writeHead(204).end()
  else res.writeHead(403).end('{}')
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const endpoint = `http://127.0.0.1:${server.address().port}`
const compose = fileURLToPath(new URL('../../deploy/simulation/compose.yaml', import.meta.url))
const bootstrap = service => JSON.parse(execFileSync('docker', ['compose', '-f', compose, 'exec', '-T', service, 'cat', '/data/bootstrap.json'], { encoding: 'utf8', windowsHide: true }))
const targets = vm ? vmInput.targets : simulation ? [
  { name: '模拟节点 A1', origin: 'http://127.0.0.1:18180', ...bootstrap('a1') },
  { name: '模拟节点 A2', origin: 'http://127.0.0.1:18181', ...bootstrap('a2') },
] : [{ name: '验证节点', origin: endpoint, credential }]
const monitor = vm ? vmInput.monitor : withMonitor ? { name: '持续监控 B', origin: 'http://127.0.0.1:18182', ...bootstrap('b') } : undefined
const portProbe = createServer()
await new Promise(resolve => portProbe.listen(0, '127.0.0.1', resolve))
const debugPort = portProbe.address().port
await new Promise(resolve => portProbe.close(resolve))
const child = spawn(dev ? 'cmd.exe' : exe, dev ? ['/d', '/s', '/c', 'npm run dev'] : [], { cwd: root, env: { ...process.env, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${debugPort}`, WEBVIEW2_USER_DATA_FOLDER: profile }, stdio: ['ignore', 'pipe', 'pipe'] })
let logs = ''
let spawnError
child.on('error', error => { spawnError = error })
child.stdout.on('data', data => { logs += data })
child.stderr.on('data', data => { logs += data })
let browser
try {
  const deadline = Date.now() + 45000
  let ready = false
  while (Date.now() < deadline) {
    if (spawnError) throw spawnError
    if (child.exitCode !== null) throw new Error(`Desktop exited (${child.exitCode})`)
    try { if ((await fetch(`http://127.0.0.1:${debugPort}/json/version`)).ok) { ready = true; break } } catch {}
    await delay(200)
  }
  assert(ready, 'WebView2 debugging endpoint did not become ready')
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${debugPort}`)
  const context = browser.contexts()[0]
  const page = context.pages()[0] ?? await context.waitForEvent('page')
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  await page.getByRole('heading', { name: '服务器总览' }).waitFor()
  assert.match(await page.locator('header').innerText(), /Windows · 原生网络/)
  for (const target of targets) {
    await page.getByRole('button', { name: '添加服务器', exact: true }).click()
    await page.getByLabel('服务器名称').fill(target.name)
    await page.getByLabel('服务地址').fill(target.origin)
    await page.getByLabel('登录凭据').fill(target.credential)
    await page.getByRole('dialog').getByRole('button', { name: '添加服务器' }).click()
    if (!realBackend) assert.equal(requests.length, 0, 'HTTP request sent before consent')
    assert(await page.getByRole('dialog').isVisible(), 'Consent did not block submission')
    await page.getByLabel('我了解并接受明文传输风险').check()
    await page.getByRole('dialog').getByRole('button', { name: '添加服务器' }).click()
    await page.getByRole('row').filter({ hasText: target.name }).getByText('直连正常', { exact: true }).waitFor()
  }
  if (!realBackend) {
    await page.getByText('17.2%', { exact: true }).waitFor()
    assert.equal(requests.filter(r => r.path === '/api/v1/session' && r.method === 'POST').length, 1)
    assert(requests.some(r => r.path === '/api/v1/status'))
    assert(requests.every(r => r.origin === null), 'Requests unexpectedly came from browser fetch')
  }
  assert.equal(await page.getByLabel('登录凭据').inputValue(), '')
  const saved = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }))
  const storage = JSON.stringify(saved)
  assert(!storage.includes(token) && targets.every(t => !storage.includes(t.credential)))
  const nodes = JSON.parse(saved.local['fleetops.targets.v1'])
  assert(nodes.every(n => Object.keys(n).every(k => ['id', 'name', 'origin', 'kind', 'expectedNodeId', 'insecureAllowed'].includes(k))))
  if (realBackend) assert.notEqual(nodes[0].expectedNodeId, nodes[1].expectedNodeId)
  const originalURL = page.url()
  await page.evaluate(url => { location.href = url }, `${endpoint}/foreign`)
  await delay(300)
  assert.equal(page.url(), originalURL, 'Native window navigated to remote content')
  assert.match(await page.locator('header').innerText(), /Windows · 原生网络/)
  const suffix = vm ? monitor ? 'vm-monitor' : 'vm-no-b' : dev ? 'dev' : simulation ? withMonitor ? 'simulation-monitor' : 'simulation-no-b' : 'smoke'
  await page.screenshot({ path: resolve(artifacts, `desktop-${suffix}.png`), fullPage: true })
  if (monitor) {
    await page.getByRole('button', { name: '持续监控', exact: false }).click()
    await page.getByRole('button', { name: '连接监控服务' }).first().click()
    await page.getByLabel('监控服务名称').fill(monitor.name)
    await page.getByLabel('服务地址').fill(monitor.origin)
    await page.getByLabel('登录凭据').fill(monitor.credential)
    await page.getByLabel('我了解并接受明文传输风险').check()
    await page.getByRole('dialog').getByRole('button', { name: '添加监控服务' }).click()
    await page.getByText('巡检运行中', { exact: true }).waitFor()
    await page.getByRole('rowheader').filter({ hasText: targets[0].name }).waitFor()
    await page.screenshot({ path: resolve(artifacts, vm ? 'desktop-vm-monitor-detail.png' : 'desktop-monitor.png'), fullPage: true })
  }
  const finalStorage = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }))
  assert.deepEqual(Object.keys(finalStorage.local), ['fleetops.targets.v1'])
  assert.deepEqual(finalStorage.session, {})
  const finalNodes = JSON.parse(finalStorage.local['fleetops.targets.v1'])
  const expectedNodes = [...targets.map(t => ({ ...t, kind: 'agent' })), ...(monitor ? [{ ...monitor, kind: 'monitor' }] : [])]
  assert.equal(finalNodes.length, expectedNodes.length)
  finalNodes.forEach((node, i) => {
    const expected = expectedNodes[i]
    assert.match(node.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)
    assert.deepEqual(node, { id: node.id, name: expected.name, origin: expected.origin, kind: expected.kind, expectedNodeId: expected.nodeId ?? 'smoke-node', insecureAllowed: true })
  })
  assert.equal(await page.getByLabel('登录凭据').inputValue(), '')
  assert.deepEqual(errors, [])
  const result = { passed: true, kind: 'real-windows-webview2', backend: vm ? 'real CentOS 7 VMs with systemd' : simulation ? 'real Linux containers' : 'HTTP fixture without CORS', mode: dev ? 'development' : 'production', executable: dev ? null : exe, embeddedFrontend: !originalURL.includes(':5173'), agents: targets.length, monitor: !!monitor, nativeRequests: requests, pageErrors: errors }
  await writeFile(resolve(artifacts, `desktop-${suffix}.json`), JSON.stringify(result, null, 2))
  console.log(JSON.stringify(result, null, 2))
} finally {
  try {
    if (browser) await browser.close()
  } finally {
    try {
      if (child.exitCode === null && child.pid) execFileSync('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true })
    } finally {
      server.closeAllConnections()
      await new Promise(resolve => server.close(resolve))
      await writeFile(resolve(artifacts, 'desktop-smoke.log'), JSON.stringify({ capturedCharacters: logs.length, diagnosticContentOmitted: true }))
    }
  }
}
