/**
 * Runs around every test of the suite.
 *
 * After each test:
 *
 * - every scripted transport the test made is checked: no request unexpected, none left over;
 * - every object the test got back from the SDK, returned or thrown, is searched for the canary
 *   credential in every text form it has;
 * - everything written to the console during the test is searched for it too. The SDK has no
 *   logger, so a line on the console is itself a finding.
 */

import { afterEach, beforeEach, expect, vi } from "vitest";

import { CANARY_KEY, expectNoSecret, produced, scripts, secrets } from "./harness.js";

const CONSOLE_METHODS = ["debug", "error", "info", "log", "trace", "warn"] as const;

let written: unknown[][] = [];

beforeEach(() => {
  scripts.length = 0;
  produced.length = 0;
  secrets.clear();
  secrets.add(CANARY_KEY);
  written = [];
  for (const method of CONSOLE_METHODS) {
    vi.spyOn(console, method).mockImplementation((...parts: unknown[]) => {
      written.push(parts);
    });
  }
});

afterEach(() => {
  for (const script of scripts) {
    script.check();
  }
  for (const subject of produced) {
    expectNoSecret(subject);
  }
  for (const parts of written) {
    expectNoSecret(parts);
  }
  expect(written, "the SDK writes nothing to the console").toEqual([]);
});
