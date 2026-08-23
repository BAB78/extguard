module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/*.test.ts'],
  // backend/ is a separate service with its own vitest suite and its own tsconfig. Left in,
  // Jest picks up backend/tests/app.test.ts, fails to resolve its vitest imports, and exits
  // non-zero even when all extension tests pass. The release workflow runs `npm test` at the
  // root, so this silently broke publishing the moment the backend tests were added.
  testPathIgnorePatterns: ['/node_modules/', '/out/', '/backend/'],
};
