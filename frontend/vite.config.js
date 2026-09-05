import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    allowedHosts: true,
    // The preview proxy provides its own refresh channel. Disabling Vite's
    // client websocket prevents it from constructing an invalid proxy URL.
    hmr: false,
  },
})
