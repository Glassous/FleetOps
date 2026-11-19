import { defineConfig } from 'mygo-cli'

export default defineConfig({
  name: 'FleetOps',
  identifier: 'app.fleetops.desktop',
  version: '0.1.0',
  devUrl: 'http://127.0.0.1:5173',
  devCommand: 'npm --prefix ../c-web run dev:desktop',
  buildCommand: 'npm --prefix ../c-web run build:desktop',
  frontendDist: '../c-web/dist-desktop',
  bindings: '../c-web/src/generated/mygo.ts',
  out: 'build',
  resources: ['MYGO-LICENSE.txt'],
})
