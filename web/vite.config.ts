import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Development: Vite serves the UI with hot reload and proxies API calls to
// the local Go server, so the browser sees one origin and session cookies
// behave exactly as in production.
// Production: `pnpm build` emits dist/, which the Go binary embeds.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8080',
    },
  },
  build: {
    outDir: 'dist',
  },
})
