// frontend/vite.config.mts
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tsconfigPaths from 'vite-tsconfig-paths';
import { visualizer } from 'rollup-plugin-visualizer';
import type { PluginOption } from 'vite';
// ✅ add the Vite inspector plugin (this injects source info into JSX)
// import Inspector from 'react-dev-inspector/plugins/vite';
import { inspectorServer } from '@react-dev-inspector/vite-plugin';

export default defineConfig(({ mode, command }) => {
  const enableInspector =
    command === 'serve' &&
    (process.env.VITE_ENABLE_INSPECTOR ?? 'true') !== 'false';

  return {
    define: { global: 'window' },
    plugins: [
      react(),
      tsconfigPaths(),
      ...(enableInspector ? [inspectorServer() as PluginOption] : []),
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
      port: 3000,
      host: '0.0.0.0',
      strictPort: true,
      watch: { usePolling: true, interval: 1000 },
      hmr: { host: 'localhost', clientPort: 3000 }
    },
    test: {
      globals: true,
      environment: 'jsdom',
      setupFiles: './src/setupTests.ts'
    }
  };
});
