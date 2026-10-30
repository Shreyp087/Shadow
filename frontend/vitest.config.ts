import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

const rootDir = fileURLToPath(new URL("./", import.meta.url));

export default defineConfig({
  envDir: false,
  resolve: {
    alias: {
      "@": path.resolve(rootDir)
    }
  },
  test: {
    environment: "node",
    include: ["lib/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["lib/**/*.ts"],
      exclude: ["lib/**/*.test.ts"],
      reporter: ["text", "lcov"],
      thresholds: {
        lines: 60,
        functions: 60,
        statements: 60,
        branches: 60
      }
    }
  }
});
