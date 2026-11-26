// SPDX-License-Identifier: Apache-2.0

/// <reference types="vitest" />
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// VITE_API=mock (기본): 브라우저 안 목업 계층으로 동작한다.
// VITE_API=real (--mode real): /api 를 mydc-web 데몬(기본 127.0.0.1:8080)으로 넘긴다.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  const target = env.MYDC_WEB_DAEMON ?? 'http://127.0.0.1:8080';
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: { '/api': { target, changeOrigin: false } },
    },
    build: { outDir: 'dist', emptyOutDir: true, sourcemap: false },
    test: { environment: 'node', include: ['src/**/*.test.ts'] },
  };
});
