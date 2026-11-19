<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { transport } from '@transport'
import { useFleet } from './lib/useFleet'
import { bytes, clock, percent, uptime } from './lib/format'
import type { ObservationState, Target } from './lib/types'

const fleet = useFleet()
const { agents, monitor, connections, notice, now, refreshing } = fleet
const page = ref<'nodes' | 'monitor'>('nodes')
const query = ref('')
const shownAgents = computed(() => agents.value.filter(t => `${t.name} ${t.origin} ${connections[t.id].status?.hostname ?? ''}`.toLowerCase().includes(query.value.toLowerCase())))
const online = computed(() => agents.value.filter(fleet.fresh).length)
const failed = computed(() => agents.value.filter(t => connections[t.id].phase === 'error').length)
const pending = computed(() => agents.value.filter(t => !connections[t.id].token && connections[t.id].phase !== 'error').length)
const monitorConnection = computed(() => monitor.value ? connections[monitor.value.id] : undefined)
const observations = computed(() => monitorConnection.value?.monitor?.targets ?? [])
const dialog = ref<HTMLDialogElement>()
const dialogMode = ref<'add' | 'login' | 'remove'>('add')
const selected = ref<Target>()
const kind = ref<Target['kind']>('agent')
const name = ref('')
const address = ref('')
const credential = ref('')
const acknowledged = ref(false)
const formError = ref('')
const submitting = ref(false)
const isHTTP = computed(() => address.value.trim().toLowerCase().startsWith('http:'))
const typeName = computed(() => kind.value === 'agent' ? '服务器' : '监控服务')
const dialogTitle = computed(() => dialogMode.value === 'add' ? `添加${typeName.value}` : dialogMode.value === 'login' ? `连接 ${selected.value?.name}` : `移除 ${selected.value?.name}`)
const labels: Record<ObservationState, string> = { unknown: '等待巡检', online: '观测正常', unreachable: 'B 侧不可达', auth_error: '凭据异常', tls_error: '证书异常', identity_mismatch: '身份不匹配', protocol_error: '协议异常' }

function stateLabel(t: Target) {
  const state = connections[t.id]
  if (state.busy && !state.token) return '正在连接'
  if (state.phase === 'error') return '连接异常'
  if (!state.token) return '待登录'
  return fleet.fresh(t) ? '直连正常' : '数据过期'
}
function tone(t: Target) {
  return fleet.fresh(t) ? 'ok' : connections[t.id].phase === 'error' ? 'bad' : 'neutral'
}
function openAdd(targetKind: Target['kind']) {
  kind.value = targetKind; dialogMode.value = 'add'; selected.value = undefined
  name.value = ''; address.value = ''; acknowledged.value = false; credential.value = ''; formError.value = ''
  dialog.value?.showModal()
}
function openLogin(target: Target) {
  kind.value = target.kind; dialogMode.value = 'login'; selected.value = target
  address.value = target.origin; acknowledged.value = target.insecureAllowed; credential.value = ''; formError.value = ''
  dialog.value?.showModal()
}
function openRemove(target: Target) {
  kind.value = target.kind; dialogMode.value = 'remove'; selected.value = target
  credential.value = ''; formError.value = ''; dialog.value?.showModal()
}
function closeDialog() { dialog.value?.close(); credential.value = ''; formError.value = '' }
async function submit() {
  if (submitting.value) return
  submitting.value = true; formError.value = ''
  const secret = credential.value
  credential.value = ''
  try {
    if (dialogMode.value === 'add') {
      const target = await fleet.add({ name: name.value, origin: address.value, kind: kind.value, insecureAllowed: acknowledged.value })
      closeDialog()
      if (secret) {
        try { await fleet.connect(target, secret) }
        catch { notice.value = `已添加 ${target.name}，但登录未成功。请检查地址和凭据后重新连接。` }
      }
    } else if (dialogMode.value === 'login' && selected.value) {
      await fleet.connect(selected.value, secret)
      closeDialog()
    } else if (selected.value) {
      await fleet.remove(selected.value)
      closeDialog()
    }
  } catch (error) {
    formError.value = error instanceof Error ? error.message : '操作失败，请重试'
    await nextTick()
    document.getElementById('credential')?.focus()
  } finally { submitting.value = false }
}
function changePage(value: 'nodes' | 'monitor') {
  page.value = value
  document.title = `${value === 'nodes' ? '服务器总览' : '持续监控'} · FleetOps`
}
onMounted(fleet.start)
onUnmounted(fleet.stop)
</script>

<template>
  <a class="skip-link" href="#main-title">跳到主要内容</a>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand"><span class="brand-mark" aria-hidden="true">F</span><div>FleetOps<small>你的服务器，尽在一处</small></div></div>
      <p class="nav-label">工作空间</p>
      <nav aria-label="主导航">
        <button :class="{ active: page === 'nodes' }" :aria-current="page === 'nodes' ? 'page' : undefined" @click="changePage('nodes')"><span class="nav-icon" aria-hidden="true">A</span>服务器看板<span class="nav-count">{{ agents.length }}</span></button>
        <button :class="{ active: page === 'monitor' }" :aria-current="page === 'monitor' ? 'page' : undefined" @click="changePage('monitor')"><span class="nav-icon" aria-hidden="true">B</span>持续监控</button>
      </nav>
      <div class="sidebar-note"><span class="mini-label">DIRECT BY DESIGN</span><p>直连每台服务器<br />不依赖中心节点</p><span class="chip" :class="transport.desktop ? 'blue' : 'neutral'">{{ transport.desktop ? 'Mygo 原生客户端' : 'Web 浏览器版' }}</span></div>
      <footer class="sidebar-footer"><span class="status-dot" aria-hidden="true"></span>FleetOps <span>v0.1.0</span></footer>
    </aside>

    <div class="workspace">
      <header class="topbar"><div class="breadcrumb">工作空间 <span>/</span> {{ page === 'nodes' ? '服务器总览' : '持续监控' }}</div><div class="runtime-info"><span class="status-dot" aria-hidden="true"></span>{{ transport.desktop ? 'Windows · 原生网络' : 'Web · HTTPS 连接' }}<span class="topbar-divider"></span><time>{{ new Date(now).toLocaleTimeString('zh-CN', { hour12: false }) }}</time></div></header>
      <main>
        <div v-if="notice" class="notice" role="status"><span>{{ notice }}</span><button class="icon-button" aria-label="关闭提示" @click="notice = ''">×</button></div>
        <div class="page-heading"><div><p class="eyebrow">{{ page === 'nodes' ? 'INFRASTRUCTURE OVERVIEW' : 'CONTINUOUS OBSERVATION' }}</p><h1 id="main-title" tabindex="-1">{{ page === 'nodes' ? '服务器总览' : '持续监控' }}</h1><p class="subtitle">{{ page === 'nodes' ? '直接连接每个节点，让服务器状态一目了然。' : '由 B 端独立运行。即使关闭客户端，观测仍然继续。' }}</p></div><div class="heading-actions"><button class="button secondary" :disabled="refreshing || !fleet.targets.value.some(t => connections[t.id].token)" @click="fleet.refreshAll(true)">{{ refreshing ? '正在刷新…' : '刷新状态' }}</button><button v-if="page === 'nodes'" class="button primary" @click="openAdd('agent')"><span aria-hidden="true">＋</span> 添加服务器</button><button v-else-if="!monitor" class="button primary" @click="openAdd('monitor')">连接监控服务</button></div></div>

        <template v-if="page === 'nodes'">
          <div class="summary-grid">
            <section class="summary-card"><span>服务器总数</span><strong>{{ agents.length }}<small>台</small></strong><p>本地保存的节点清单</p><i class="summary-decoration blue" aria-hidden="true">A</i></section>
            <section class="summary-card"><span><i class="dot ok" aria-hidden="true"></i>直连正常</span><strong>{{ online }}<small>台</small></strong><p>最近 20 秒内取得有效状态</p></section>
            <section class="summary-card"><span><i class="dot neutral" aria-hidden="true"></i>待连接</span><strong>{{ pending }}<small>台</small></strong><p>尚未建立当前登录会话</p></section>
            <section class="summary-card"><span><i class="dot bad" aria-hidden="true"></i>连接异常</span><strong>{{ failed }}<small>台</small></strong><p>需要检查网络或访问凭据</p></section>
          </div>

          <section class="panel">
            <div class="panel-toolbar"><div class="panel-title"><h2>节点列表</h2><span class="count-label">{{ agents.length }}</span></div><div class="table-tools"><span class="refresh-note"><span class="status-dot" aria-hidden="true"></span>前台每 5 秒刷新</span><label for="node-search" class="sr-only">搜索节点名称或地址</label><input id="node-search" v-model="query" class="search-input" type="search" placeholder="搜索节点名称或地址" /></div></div>
            <div v-if="!agents.length" class="empty-state"><svg aria-hidden="true" viewBox="0 0 96 80"><rect x="16" y="8" width="64" height="25" rx="6"/><rect x="16" y="42" width="64" height="25" rx="6"/><circle cx="29" cy="21" r="3"/><circle cx="29" cy="55" r="3"/><path d="M43 21h24M43 55h24M48 34v7"/></svg><h3>从第一台服务器开始</h3><p>安装 A 端后，添加节点地址和登录凭据。<br />不需要先部署 B 端。</p><button class="button primary" @click="openAdd('agent')">添加第一台服务器</button></div>
            <div v-else class="table-wrap" role="region" aria-labelledby="nodes-caption" tabindex="0">
              <table class="node-table"><caption id="nodes-caption" class="sr-only">服务器节点与资源状态</caption><thead><tr><th scope="col">服务器</th><th scope="col">连接状态</th><th scope="col">CPU</th><th scope="col">内存</th><th scope="col">根分区</th><th scope="col">运行时间</th><th scope="col">操作</th></tr></thead><tbody>
                <tr v-for="target in shownAgents" :key="target.id">
                  <th scope="row"><div class="node-name"><span class="server-icon" aria-hidden="true">A</span><span>{{ target.name }}<small>{{ target.origin }}</small></span></div><div v-if="connections[target.id].status" class="node-meta">{{ connections[target.id].status?.system.platform }} · {{ connections[target.id].status?.system.arch }}<span v-if="connections[target.id].status?.metricsScope === 'container-test'" class="test-label">容器测试</span></div><div v-if="connections[target.id].error" class="row-error">{{ connections[target.id].error }}</div><details v-if="connections[target.id].status" class="node-details"><summary>节点详情</summary><dl><dt>节点 ID</dt><dd>{{ connections[target.id].status!.nodeId }}</dd><dt>主机名</dt><dd>{{ connections[target.id].status!.hostname }}</dd><dt>系统 / 内核</dt><dd>{{ connections[target.id].status!.system.os }} / {{ connections[target.id].status!.system.kernel }}</dd><dt>Agent 版本</dt><dd>{{ connections[target.id].status!.agentVersion }}</dd><dt>Agent 启动</dt><dd>{{ clock(connections[target.id].status!.agentStartedAt) }}</dd></dl></details></th>
                  <td data-label="连接状态"><span class="chip" :class="tone(target)"><i class="dot" aria-hidden="true"></i>{{ stateLabel(target) }}</span><small class="cell-secondary">{{ target.origin.startsWith('http:') ? 'HTTP · 未加密' : 'HTTPS · 加密' }}</small></td>
                  <td data-label="CPU"><template v-if="connections[target.id].status"><span class="metric-value">{{ percent(connections[target.id].status?.cpu.usagePercent) }}</span><progress v-if="connections[target.id].status?.cpu.usagePercent != null" :value="connections[target.id].status!.cpu.usagePercent!" max="100" :aria-label="`${target.name} CPU 使用率`"></progress><small v-else class="cell-secondary">采集中</small></template><span v-else class="missing">—</span></td>
                  <td data-label="内存"><template v-if="connections[target.id].status?.memory"><span class="metric-value">{{ percent(connections[target.id].status?.memory?.usedPercent) }}</span><small class="cell-secondary">{{ bytes(connections[target.id].status!.memory!.usedBytes) }} / {{ bytes(connections[target.id].status!.memory!.totalBytes) }}</small></template><span v-else class="missing">—</span></td>
                  <td data-label="根分区"><template v-if="connections[target.id].status?.disk"><span class="metric-value">{{ percent(connections[target.id].status?.disk?.usedPercent) }}</span><small class="cell-secondary">{{ bytes(connections[target.id].status!.disk!.usedBytes) }} / {{ bytes(connections[target.id].status!.disk!.totalBytes) }}</small></template><span v-else class="missing">—</span></td>
                  <td data-label="运行时间"><span v-if="connections[target.id].status">{{ uptime(connections[target.id].status!.uptimeSeconds) }}</span><span v-else class="missing">—</span><small v-if="connections[target.id].status" class="cell-secondary">采样 {{ new Date(connections[target.id].status!.sampledAt).toLocaleTimeString('zh-CN', { hour12: false }) }}</small></td>
                  <td data-label="操作"><div class="row-actions"><button v-if="!connections[target.id].token || connections[target.id].phase === 'error'" class="text-button" :disabled="connections[target.id].busy" :aria-label="`连接 ${target.name}`" @click="openLogin(target)">连接</button><button v-if="connections[target.id].token" class="text-button muted" :aria-label="`退出 ${target.name}`" @click="fleet.disconnect(target)">退出</button><button class="text-button muted" :aria-label="`移除 ${target.name}`" @click="openRemove(target)">移除</button></div></td>
                </tr>
                <tr v-if="!shownAgents.length"><td colspan="7" class="no-results">没有匹配“{{ query }}”的节点</td></tr>
              </tbody></table>
            </div>
            <div v-if="agents.length" class="panel-footer"><span>共 {{ agents.length }} 台服务器 · 数据来自 A 端直接连接</span><span>会话仅保存在内存中</span></div>
          </section>
          <details class="help-block"><summary>如何连接我的服务器？</summary><div><p><strong>客户端：</strong>输入 A 端的 HTTP IP:端口，或反代后的 HTTPS 地址；HTTP 会明文传输凭据。</p><p><strong>Web：</strong>使用 HTTPS 节点，并将此网站的完整 Origin 加入 A 端 CORS 白名单。</p><p>凭据通过服务器上的 A 端 CLI 初始化获取。刷新页面或重启客户端后，需要重新登录。</p></div></details>
        </template>

        <template v-else>
          <section v-if="!monitor" class="panel empty-state monitor-empty"><div class="monitor-glyph" aria-hidden="true">24<span>/ 7</span></div><h2>让监控一直在线</h2><p>在一台服务器上独立运行 B 端，配置需要巡检的 A 节点。<br />连接 B 后，在这里查看观测结果和状态事件。</p><button class="button primary" @click="openAdd('monitor')">连接监控服务</button><small>B 不代理日常操作，停止 B 不影响服务器直连。</small></section>
          <template v-else>
            <section class="panel monitor-connection"><div><span class="eyebrow">MONITOR / B</span><h2>{{ monitor.name }}<span class="chip" :class="fleet.monitorHealthy() ? 'ok' : 'neutral'">{{ fleet.monitorHealthy() ? '巡检运行中' : monitorConnection?.token ? '监控不可用或退化' : '待登录' }}</span></h2><p class="mono">{{ monitor.origin }}<span v-if="monitor.origin.startsWith('http:')" class="http-note">HTTP 未加密</span></p><p v-if="monitorConnection?.error" class="row-error">{{ monitorConnection.error }}</p></div><div class="heading-actions"><button v-if="!monitorConnection?.token || monitorConnection.phase === 'error'" class="button primary" :disabled="monitorConnection?.busy" @click="openLogin(monitor)">登录监控服务</button><button v-if="monitorConnection?.token" class="button secondary" @click="fleet.disconnect(monitor)">退出</button><button class="text-button muted" @click="openRemove(monitor)">移除</button></div></section>
            <div class="monitor-note">以下是 B 端的独立观测，并非本机直连结果。监控不可用时，服务器看板仍可正常使用。</div>
            <section class="panel"><div class="panel-toolbar"><div class="panel-title"><h2>监控目标</h2><span class="count-label">{{ observations.length }}</span></div><span class="refresh-note">巡检心跳：{{ clock(monitorConnection?.monitor?.heartbeatAt) }}</span></div><div v-if="!observations.length" class="compact-empty">{{ monitorConnection?.token ? '暂无监控目标，请在 B 端目标配置中添加节点。' : '登录 B 端后读取监控目标。' }}</div><div v-else class="table-wrap" role="region" aria-labelledby="observations-caption" tabindex="0"><table><caption id="observations-caption" class="sr-only">B 端观测结果</caption><thead><tr><th scope="col">节点</th><th scope="col">B 端观测</th><th scope="col">数据新鲜度</th><th scope="col">最近成功</th><th scope="col">诊断</th></tr></thead><tbody><tr v-for="observation in observations" :key="observation.id"><th scope="row">{{ observation.name }}<small class="cell-secondary mono">{{ observation.url }}</small></th><td data-label="B 端观测"><span class="chip" :class="observation.state === 'online' && !observation.failures ? 'ok' : observation.state === 'unknown' ? 'neutral' : 'warn'">{{ observation.failures && observation.state === 'online' ? '探测重试' : labels[observation.state] }}</span></td><td data-label="数据新鲜度"><span class="chip" :class="fleet.observationStale(observation) ? 'neutral' : 'blue'">{{ fleet.observationStale(observation) ? '过期 / 未观测' : '最新观测' }}</span></td><td data-label="最近成功">{{ clock(observation.succeededAt) }}</td><td data-label="诊断"><span>{{ observation.message || '—' }}</span><small v-if="observation.failures" class="cell-secondary">连续失败 {{ observation.failures }} 次</small></td></tr></tbody></table></div></section>
            <section class="panel events-panel"><div class="panel-toolbar"><h2>状态事件</h2><span class="refresh-note">最近 50 条 · 仅状态变化时记录</span></div><div v-if="!monitorConnection?.events.length" class="compact-empty">尚无状态事件。首次正常连接不会生成恢复告警。</div><ol v-else class="event-list"><li v-for="event in monitorConnection.events" :key="event.id"><span class="event-dot" :class="event.kind === 'recovered' ? 'ok' : 'warn'" aria-hidden="true"></span><div><strong>{{ event.targetName }}</strong><span class="event-kind">{{ event.kind === 'recovered' ? '恢复可达' : event.kind === 'unreachable' ? 'B 侧不可达' : '观测异常' }}</span><p>{{ event.message }}</p></div><time>{{ clock(event.at) }}</time></li></ol></section>
          </template>
        </template>
        <footer class="content-footer"><span>FleetOps / Independent infrastructure</span><span>无中转 · 凭据不持久化 · 只读看板</span></footer>
      </main>
    </div>
  </div>

  <dialog ref="dialog" class="connection-dialog" aria-labelledby="dialog-title" @close="credential = ''" @cancel="credential = ''">
    <div class="dialog-header"><div><p class="eyebrow">{{ dialogMode === 'remove' ? 'LOCAL CONNECTION' : 'DIRECT CONNECTION' }}</p><h2 id="dialog-title">{{ dialogTitle }}</h2></div><button class="icon-button" type="button" aria-label="关闭对话框" @click="closeDialog">×</button></div>
    <form @submit.prevent="submit">
      <template v-if="dialogMode === 'remove'"><p class="remove-description">仅从此设备移除连接及本地记录，不会卸载服务器上的服务，也不会删除 B 端的监控配置。</p><p class="mono dialog-address">{{ selected?.origin }}</p></template>
      <template v-else>
        <template v-if="dialogMode === 'add'"><label for="target-name">{{ typeName }}名称</label><input id="target-name" v-model="name" required maxlength="64" placeholder="例如：生产节点 01" autofocus /><label for="target-address">服务地址</label><p id="address-hint" class="field-hint">只填写协议、IP / 域名及端口，不包含 API 路径。</p><input id="target-address" v-model="address" type="url" required :placeholder="transport.desktop ? 'http://IP:18080' : 'https://节点域名'" aria-describedby="address-hint" /></template>
        <p v-else class="mono dialog-address">{{ selected?.origin }}</p>
        <label for="credential">登录凭据 <span v-if="dialogMode === 'add'" class="optional">可稍后填写</span></label><input id="credential" v-model="credential" type="password" autocomplete="off" :required="dialogMode === 'login'" maxlength="512" aria-describedby="credential-hint" /><p id="credential-hint" class="field-hint">由该服务的本机 CLI 初始化生成，仅用于本次登录，不会保存到本地。</p>
        <div v-if="isHTTP" class="insecure-warning"><strong>HTTP 连接未加密</strong><p>登录凭据和服务器数据将以明文传输，公网使用推荐 HTTPS。</p><label v-if="transport.desktop && (dialogMode === 'add' || !selected?.insecureAllowed)" class="checkbox-label" for="http-confirm"><input id="http-confirm" v-model="acknowledged" type="checkbox" required />我了解并接受明文传输风险</label><p v-if="!transport.desktop" class="web-limit">Web 版不支持此 HTTP 地址，请改用 HTTPS 或 Windows 客户端。</p></div>
      </template>
      <p v-if="formError" class="form-error" role="alert">{{ formError }}</p>
      <div class="dialog-footer"><button class="button secondary" type="button" @click="closeDialog">取消</button><button class="button" :class="dialogMode === 'remove' ? 'danger' : 'primary'" type="submit" :disabled="submitting || (dialogMode !== 'remove' && !transport.desktop && isHTTP)">{{ submitting ? '处理中…' : dialogMode === 'remove' ? '确认移除' : dialogMode === 'add' ? `添加${typeName}` : '登录并连接' }}</button></div>
    </form>
  </dialog>
</template>
