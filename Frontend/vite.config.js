import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // '/api'로 시작하는 모든 요청을 http://localhost:8000으로 전달
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''), // 백엔드로 보낼 때 '/api' 제거
      },
      // '/analysis'로 시작하는 요청 (업로드 및 단일 조회)
      '/analysis': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      // '/analyses' 요청 (목록 조회)
      '/analyses': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
});