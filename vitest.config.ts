import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // Each test file boots its own server on a random port and its own temp DATA_DIR,
    // so files can run in parallel safely.
    fileParallelism: true,
  },
});
