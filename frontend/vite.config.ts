import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        secure: false,
      },
      '/ws': {
        target: 'http://localhost:8080',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    chunkSizeWarningLimit: 700,
    rollupOptions: {
      output: {
        manualChunks(id) {
          // Three.js and its addons into a dedicated chunk
          if (id.includes('node_modules/three')) {
            return 'vendor-three';
          }
          // STOMP / SockJS into a dedicated chunk
          if (
            id.includes('node_modules/@stomp') ||
            id.includes('node_modules/sockjs-client')
          ) {
            return 'vendor-stomp';
          }
          // React ecosystem into its own chunk
          if (
            id.includes('node_modules/react') ||
            id.includes('node_modules/react-dom') ||
            id.includes('node_modules/react-router')
          ) {
            return 'vendor-react';
          }
        },
      },
    },
  },
})

