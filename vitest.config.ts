import { defineConfig } from "vitest/config";

// Resolve workspace packages to their TypeScript sources, so tests need no build step.
// Node-environment tests resolve through Vite's SSR resolver, so set both.
const conditions = ["satoris-source", "import", "node", "default"];

export default defineConfig({
  resolve: { conditions },
  ssr: { resolve: { conditions, externalConditions: ["satoris-source"] } },
  test: {
    include: ["packages/*/test/**/*.test.ts"],
    server: { deps: { inline: [/@satoris\//] } },
  },
});
