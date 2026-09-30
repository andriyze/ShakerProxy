import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"

// `npm run dev` serves the UI with hot reload on http://127.0.0.1:5173 and
// forwards /api to the local dev edge started by `make dev` (Caddy on :8443).
//
// control-api only accepts requests whose Host header is one of
// SHAKERPROXY_ALLOWED_HOSTS (localhost:8443,127.0.0.1:8443 in development) and,
// when an Origin header is present, only that same origin
// (apps/control-api/internal/server/server.go validateHost). The proxy
// therefore presents itself as the edge: changeOrigin rewrites Host, and the
// browser's Origin (http://127.0.0.1:5173) is rewritten to the edge origin.
// This is a development convenience only; production serves the UI and the
// API from the same origin.
const edge = process.env.SHAKERPROXY_DEV_EDGE ?? "http://127.0.0.1:8443"

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: edge,
        changeOrigin: true,
        configure(proxy) {
          proxy.on("proxyReq", (proxyReq) => {
            if (proxyReq.getHeader("origin")) proxyReq.setHeader("origin", edge)
          })
        },
      },
    },
  },
})
