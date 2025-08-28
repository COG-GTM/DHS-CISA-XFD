// frontend/vite.config.mts
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tsconfigPaths from 'vite-tsconfig-paths';
import { visualizer } from 'rollup-plugin-visualizer';
import type { PluginOption } from 'vite';

export default defineConfig(({ mode }) => ({
  define: { global: 'window' },
  plugins: [
    react(),
    tsconfigPaths(),
    ...(mode === 'analyze'
      ? [
          visualizer({
            filename: './dist/stats.html',
            open: true,
            gzipSize: true,
            brotliSize: true,
            template: 'treemap'
          }) as PluginOption
        ]
      : [])
  ],
  server: {
    port: 5173,
    host: '0.0.0.0',
    strictPort: true,
    watch: { usePolling: true, interval: 1000 },
    hmr: { host: 'localhost', clientPort: 5173 }
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/setupTests.ts'
  }
}));
