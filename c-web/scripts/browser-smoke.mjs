import assert from 'node:assert/strict'
import { chromium } from 'playwright'
import { mkdir, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'

const base = process.argv[2] ?? 'http://127.0.0.1:5173'
const artifacts = fileURLToPath(new URL('../.artifacts/', import.meta.url))
await mkdir(artifacts, { recursive: true })
const credential = randomBytes(24).toString('hex')
const token = randomBytes(24).toString('hex')
const origin = 'https://agent.fixture.test'
const monitorOrigin = 'https://monitor.fixture.test'
const status = () => ({ apiVersion: '1', nodeId: 'web-node', hostname: 'fixture-linux', system: { os: 'linux', platform: 'Debian 13', kernel: '6.12', arch: 'amd64' }, agentVersion: '0.1.0', metricsScope: 'container-test', sampledAt: new Date().toISOString(), agentStartedAt: new Date().toISOString(), uptimeSeconds: 86500, cpu: { logicalCount: 4, usagePercent: 23.5 }, memory: { totalBytes: 8589934592, usedBytes: 2147483648, usedPercent: 25 }, disk: null })
let expired = false
let monitorStalled = false
const requests = []
const errors = []
const browser = await chromium.launch({ channel: 'msedge', headless: true })
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 960 } })
  const page = await context.newPage()
  page.on('pageerror', error => errors.push(error.message))
  await page.route(/https:\/\/(agent|monitor)\.fixture\.test\//, async route => {
    const request = route.request()
    const url = new URL(request.url())
    requests.push({ path: url.pathname, method: request.method(), host: url.host })
    const headers = { 'access-control-allow-origin': new URL(base).origin, 'access-control-allow-headers': 'authorization,content-type', 'access-control-allow-methods': 'GET,POST,DELETE,OPTIONS', 'cache-control': 'no-store' }
    if (request.method() === 'OPTIONS') return route.fulfill({ status: 204, headers })
    const isMonitor = url.origin === monitorOrigin
    const nodeId = isMonitor ? 'web-monitor' : 'web-node'
    if (url.pathname === '/api/v1/session' && request.method() === 'POST') {
      if (request.postDataJSON().credential !== credential) return route.fulfill({ status: 401, headers, json: { error: { message: '登录凭据无效' } } })
      return route.fulfill({ headers, json: { token: isMonitor ? `${token}b` : token, nodeId, expiresAt: new Date(Date.now() + 3600000).toISOString() } })
    }
    if (request.headers().authorization !== `Bearer ${isMonitor ? `${token}b` : token}` || (!isMonitor && expired)) return route.fulfill({ status: 401, headers, body: 'expired' })
    if (request.method() === 'DELETE') return route.fulfill({ status: 204, headers })
    if (url.pathname === '/api/v1/status') return route.fulfill({ headers, json: status() })
    if (url.pathname === '/api/v1/monitor') return route.fulfill({ headers, json: { apiVersion: '1', monitorId: nodeId, instanceId: 'instance-1', startedAt: new Date().toISOString(), heartbeatAt: new Date(Date.now() - (monitorStalled ? 180000 : 0)).toISOString(), generatedAt: new Date().toISOString(), staleAfterSeconds: 90, storageHealthy: true, targets: [{ id: 'a1', name: '独立监控目标', url: origin, expectedNodeId: 'web-node', state: 'online', stale: monitorStalled, failures: 0, message: '', checkedAt: new Date().toISOString(), succeededAt: new Date().toISOString(), status: status() }] } })
    return route.fulfill({ headers, json: { events: [], nextBefore: null } })
  })
  await page.goto(base)
  await page.getByRole('button', { name: '添加第一台服务器' }).click()
  await page.getByLabel('服务器名称').fill('测试节点')
  await page.getByLabel('服务地址').fill('http://127.0.0.1:18080')
  assert(await page.getByRole('dialog').getByRole('button', { name: '添加服务器' }).isDisabled())
  assert.equal(requests.length, 0)
  await page.getByText('Web 版不支持此 HTTP 地址', { exact: false }).waitFor()
  await page.getByLabel('服务地址').fill(origin)
  await page.getByLabel('登录凭据').fill(credential)
  await page.getByRole('dialog').getByRole('button', { name: '添加服务器' }).click()
  await page.getByText('23.5%', { exact: true }).waitFor()
  await page.getByText('节点详情', { exact: true }).click()
  await page.getByText('fixture-linux', { exact: true }).waitFor()
  const storage = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))
  assert(!storage.includes(token) && !storage.includes(credential))
  await page.getByLabel('搜索节点名称或地址').fill('不匹配的节点')
  await page.getByText('没有匹配', { exact: false }).waitFor()
  await page.getByLabel('搜索节点名称或地址').fill('')
  await page.screenshot({ path: `${artifacts}/web-desktop.png`, fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
  await page.screenshot({ path: `${artifacts}/web-mobile.png`, fullPage: true })
  await page.setViewportSize({ width: 1440, height: 960 })
  await page.getByRole('button', { name: '持续监控' }).click()
  await page.getByRole('button', { name: '连接监控服务' }).first().click()
  await page.getByLabel('监控服务名称').fill('独立监控')
  await page.getByLabel('服务地址').fill(monitorOrigin)
  await page.getByLabel('登录凭据').fill(credential)
  await page.getByRole('dialog').getByRole('button', { name: '添加监控服务' }).click()
  await page.getByText('巡检运行中', { exact: true }).waitFor()
  monitorStalled = true
  await page.getByRole('button', { name: '刷新状态' }).click()
  await page.getByText('监控不可用或退化', { exact: true }).waitFor()
  await page.getByText('过期 / 未观测', { exact: true }).waitFor()
  await page.getByRole('button', { name: '服务器看板' }).click()
  await page.getByText('直连正常', { exact: true }).last().waitFor()
  expired = true
  await page.getByRole('button', { name: '刷新状态' }).click()
  await page.getByRole('button', { name: '连接 测试节点', exact: true }).waitFor()
  assert.equal(await page.getByRole('button', { name: '退出 测试节点', exact: true }).count(), 0)
  expired = false
  await page.reload()
  await page.getByRole('button', { name: '连接 测试节点', exact: true }).click()
  await page.getByLabel('登录凭据').fill('invalid-test-value')
  await page.getByRole('button', { name: '登录并连接' }).click()
  await page.getByRole('alert').waitFor()
  assert.equal(await page.getByLabel('登录凭据').inputValue(), '')
  await page.getByLabel('登录凭据').fill(credential)
  await page.getByRole('button', { name: '登录并连接' }).click()
  await page.getByText('23.5%', { exact: true }).waitFor()
  await page.getByRole('button', { name: '移除 测试节点', exact: true }).click()
  await page.getByRole('button', { name: '确认移除' }).click()
  await page.getByRole('button', { name: '添加第一台服务器' }).waitFor()
  assert.deepEqual(errors, [])
  const result = { passed: true, network: 'Playwright intercepted fixtures, not trusted-HTTPS validation', checks: ['HTTP blocked in Web', 'login and metrics', 'node details', 'search', 'responsive overflow', 'memory-only sessions', 'B stalled heartbeat', 'B independent of A', 'non-JSON 401 clears token', 'reload logs out', 'invalid credentials', 'remove confirmation'], requestCount: requests.length, pageErrors: errors }
  await writeFile(`${artifacts}/browser-smoke.json`, JSON.stringify(result, null, 2))
  console.log(JSON.stringify(result, null, 2))
} finally { await browser.close() }
