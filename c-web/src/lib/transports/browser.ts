import type { Transport } from '../transport'

export const transport: Transport = {
  desktop: false,
  async setTargets() {},
  fetch(url, init) {
    if (new URL(url).protocol !== 'https:') {
      return Promise.reject(new Error('Web 版仅支持 HTTPS 节点。HTTP IP:端口请使用 Windows 客户端。'))
    }
    return globalThis.fetch(url, { ...init, credentials: 'omit', redirect: 'error' })
  },
}
