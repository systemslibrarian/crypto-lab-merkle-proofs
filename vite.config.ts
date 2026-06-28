/// <reference types="vitest/config" />
import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-merkle-proofs/',
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  test: {
    globals: true,
    environment: 'node',
  },
});
