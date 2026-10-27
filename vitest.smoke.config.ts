import { defineConfig } from 'vitest/config';

// Smoke tests drive the built artifact in dist/. `npm run smoke` builds first.
export default defineConfig({
  test: {
    include: ['test/smoke/**/*.test.ts'],
    testTimeout: 30_000,
  },
});
