import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: fileURLToPath(new URL('../frontend', import.meta.url)),
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 4173,
    proxy: {
      '/api': 'http://127.0.0.1:8000',
    },
  },
});
