const { defineConfig } = require('vitest/config');

module.exports = defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['**/*.test.js', '**/*.test.ts'],
    exclude: ['node_modules/**', '**/node_modules/**'],
    testTimeout: 15000,
    reporters: ['verbose'],
  },
});
