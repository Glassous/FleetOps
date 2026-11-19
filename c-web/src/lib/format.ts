export function bytes(value: number): string {
  if (value === 0) return '0 B'
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), 4)
  return `${(value / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][index]}`
}
export function uptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor(seconds % 86400 / 3600)
  return days ? `${days} 天 ${hours} 小时` : `${hours} 小时 ${Math.floor(seconds % 3600 / 60)} 分`
}
export function clock(value?: string | null): string {
  return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '尚无记录'
}
export function percent(value: number | null | undefined): string { return value == null ? '—' : `${value.toFixed(1)}%` }
