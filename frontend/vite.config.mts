// frontend/vite.config.ts
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import OpenIde from 'vite-inspector';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  define: {
    global: 'window'
  },
  plugins: [
    react(),
    tsconfigPaths(),
    OpenIde({
      framework: 'react'
    })
  ],
  server: {
    port: 3000,
    host: true,
    strictPort: true,
    watch: {
      usePolling: true,
      interval: 1000
    },
    hmr: {
      clientPort: 80
    }
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/setupTests.ts'
  }
});
