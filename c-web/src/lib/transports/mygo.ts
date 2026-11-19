import { fetch as nativeFetch } from '@mygo-plugins/fetch'
import { Connections } from '../../generated/mygo'
import type { Transport } from '../transport'

export const transport: Transport = {
  desktop: true,
  setTargets(origins) {
    return Connections.setTargets(origins)
  },
  fetch(url, init) {
    return nativeFetch(url, { ...init, credentials: 'omit', redirect: 'error' })
  },
}
