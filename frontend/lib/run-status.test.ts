import { describe, expect, it } from "vitest";
import { isActiveRun } from "./run-status";

describe("scan polling lifecycle", () => {
  it("keeps polling from queueing through execution and stops on terminal states", () => {
    const states = ["PENDING", "PENDING", "RUNNING", "COMPLETED"] as const;
    expect(states.map(isActiveRun)).toEqual([true, true, true, false]);
    expect(isActiveRun("FAILED")).toBe(false);
    expect(isActiveRun(undefined)).toBe(false);
  });
});
