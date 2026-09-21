import { defineConfig } from 'vitest/config';

// The S3 backend only executes when the suite runs against MinIO (TEST_S3=1).
// Counting it in a local run would report a permanent, misleading gap, so it is
// measured in the S3 run instead — CI does both.
const s3Exclusions = process.env.TEST_S3 === '1' ? [] : ['src/storage/s3.ts'];

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // Each test file boots its own server on a random port and its own temp DATA_DIR,
    // so files can run in parallel safely.
    fileParallelism: true,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // server.ts and cli.ts are process entry points: exercised by running the app, not by the suite.
      exclude: ['src/server.ts', 'src/cli.ts', ...s3Exclusions],
      reporter: ['text', 'lcov'],
      thresholds: { statements: 90, branches: 85, functions: 90, lines: 93 },
    },
  },
});
