import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['**/*.test.ts'],
    // Exclude git worktrees under .claude/ — they have their own (uninstalled)
    // deps and would otherwise fail to resolve, polluting the root test run.
    exclude: ['**/node_modules/**', '**/dist/**', '**/.next/**', '**/.claude/**'],
    environment: 'node',
  },
});
