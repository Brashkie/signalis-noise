import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
    include: ['__tests__/**/*.test.ts'],

    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary', 'html', 'lcov'],
      reportsDirectory: './coverage',
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts', '**/*.d.ts'],
      thresholds: {
        statements: 90,
        branches: 78,
        functions: 95,
        lines: 92,
      },
    },
  },
});
