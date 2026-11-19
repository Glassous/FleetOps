export interface Transport {
  desktop: boolean
  setTargets(origins: string[]): Promise<void>
  fetch(url: string, init?: RequestInit): Promise<Response>
}
