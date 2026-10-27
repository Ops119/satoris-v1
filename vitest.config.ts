import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    // Resolve workspace packages to their TypeScript sources, so tests need no build step.
    conditions: ["satoris-source"],
  },
  test: {
    include: ["packages/*/test/**/*.test.ts"],
  },
});
