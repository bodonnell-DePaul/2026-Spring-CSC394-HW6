import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const backendUrl = process.env.VITE_BACKEND_URL || 'http://localhost:5000';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: backendUrl,
        changeOrigin: true,
      },
      '/login': {
        target: backendUrl,
        changeOrigin: true,
      },
      '/logout': {
        target: backendUrl,
        changeOrigin: true,
      },
    },
  },
});
