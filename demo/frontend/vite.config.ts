import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5175,
    proxy: {
      '/demo': process.env.DEMO_API_ORIGIN || 'http://localhost:8018',
      '/api': process.env.DEMO_API_ORIGIN || 'http://localhost:8018',
    },
  },
  build: { target: 'es2020', chunkSizeWarningLimit: 900 },
});
