import { defineConfig } from 'vitest/config';

// Adversarial-input timing suite. It is NOT run directly by `npm test`: test/htmlDos.test.ts spawns it
// in a child process with a hard kill timeout, so a regression to super-linear parsing fails the
// parent test instead of hanging the whole test process.
export default defineConfig({
  test: {
    include: ['test/adversarial/**/*.adversarial.ts'],
    testTimeout: 30_000,
  },
});
