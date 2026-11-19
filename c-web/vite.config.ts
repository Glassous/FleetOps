import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig(({ mode }) => ({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      '@transport': fileURLToPath(new URL(`./src/lib/transports/${mode === 'desktop' ? 'mygo' : 'browser'}.ts`, import.meta.url)),
    },
  },
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
  build: { outDir: mode === 'desktop' ? 'dist-desktop' : 'dist', target: 'es2022' },
}))
