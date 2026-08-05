import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5180,
    host: '0.0.0.0',
    proxy: {
      '/publisher-admin': { target: 'http://127.0.0.1:8100', rewrite: (path) => path.replace(/^\/publisher-admin/, '') },
      '/publisher-ingest': { target: 'http://127.0.0.1:8102', rewrite: (path) => path.replace(/^\/publisher-ingest/, '') },
      '/publisher-review': { target: 'http://127.0.0.1:8103', rewrite: (path) => path.replace(/^\/publisher-review/, '') },
      '/publisher-feed': { target: 'http://127.0.0.1:8101', rewrite: (path) => path.replace(/^\/publisher-feed/, '') },
    },
  },
  test: { environment: 'jsdom', setupFiles: './src/test/setup.ts', css: true },
});
