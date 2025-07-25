// frontend/vite.config.ts
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { inspectorServer } from '@react-dev-inspector/vite-plugin';
// import OpenIde from 'vite-inspector';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  define: {
    global: 'window'
  },
  plugins: [react(), tsconfigPaths(), inspectorServer()],
  // server: {
  //   port: 3000,
  //   host: true,
  //   strictPort: true,
  //   watch: {
  //     usePolling: true,
  //     interval: 1000
  //   },
  //   hmr: {
  //     clientPort: 80
  //   }
  // },
  server: {
    port: 5173, // Vite’s default port :contentReference[oaicite:9]{index=9}
    host: '0.0.0.0', // bind to all interfaces :contentReference[oaicite:10]{index=10}
    strictPort: true, // fail if 5173 is taken :contentReference[oaicite:11]{index=11}
    watch: {
      // polling for Docker mounts :contentReference[oaicite:12]{index=12}
      usePolling: true,
      interval: 1000
    },
    hmr: {
      // HMR over WebSocket on host port 5173 :contentReference[oaicite:13]{index=13}
      host: 'localhost',
      clientPort: 5173
    }
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/setupTests.ts'
  }
});
