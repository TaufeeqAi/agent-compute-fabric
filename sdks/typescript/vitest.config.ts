import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    setupFiles: ["tests/support/setup.ts"],
    // A test that waits has stopped using the virtual clock. Fail it fast instead of letting it sleep.
    testTimeout: 5000,
    restoreMocks: true,
    unstubGlobals: true,
    unstubEnvs: true,
  },
});
