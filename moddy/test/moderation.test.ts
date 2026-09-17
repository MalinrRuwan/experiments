import { describe, expect, test } from "bun:test";

import {
  buildReport,
  DEFAULT_POLICY,
  decodePolicy,
  Finding,
  SEVERITY_LEVELS,
  severityLabel,
  statusFor,
  verdictFor,
} from "../src/moderation.ts";
import type { Assessment, Policy } from "../src/moderation.ts";

const POLICY: Policy = {
  actionThreshold: 0.7,
  reviewThreshold: 0.35,
  severityBlock: 2,
};

const findingWith = (probability: number): Finding =>
  new Finding({
    id: "hate_speech",
    label: "hate speech",
    probability,
    status: statusFor(probability, POLICY),
  });

const ASSESSMENT: Assessment = {
  model: "jev-latest",
  probabilities: {
    disturbing_content: 0.4,
    hate_speech: 0.02,
    sexual_content: 0.91,
  },
  severity: { confidence: 0.8, score: 1.1 },
  usage: { inputTokens: 300, outputTokens: 40 },
};

describe("statusFor", () => {
  test("is clear below the review threshold", () => {
    expect(statusFor(0.34, POLICY)).toBe("clear");
  });

  test("reviews at the review threshold", () => {
    expect(statusFor(0.35, POLICY)).toBe("review");
  });

  test("flags at the action threshold", () => {
    expect(statusFor(0.7, POLICY)).toBe("flagged");
  });
});

describe("verdictFor", () => {
  test("allows when nothing fires", () => {
    expect(verdictFor([findingWith(0.1)], 0.2, POLICY)).toBe("allow");
  });

  test("reviews when a category reaches the review threshold", () => {
    expect(verdictFor([findingWith(0.4)], 0.2, POLICY)).toBe("review");
  });

  test("blocks when a category reaches the action threshold", () => {
    expect(verdictFor([findingWith(0.9)], 0.2, POLICY)).toBe("block");
  });

  test("severity at the block line promotes review to block", () => {
    expect(verdictFor([findingWith(0.4)], 2, POLICY)).toBe("block");
  });

  test("severity below the block line does not block on its own", () => {
    expect(verdictFor([], 1.9, POLICY)).toBe("allow");
  });
});

describe("severityLabel", () => {
  test("rounds to the nearest rubric level", () => {
    expect(severityLabel(1.4)).toBe(SEVERITY_LEVELS[1]);
    expect(severityLabel(2.6)).toBe(SEVERITY_LEVELS[3]);
  });

  test("clamps out-of-range scores", () => {
    expect(severityLabel(-1)).toBe(SEVERITY_LEVELS[0]);
    expect(severityLabel(99)).toBe(SEVERITY_LEVELS[3]);
  });
});

describe("decodePolicy", () => {
  test("accepts the defaults", () => {
    expect(decodePolicy(DEFAULT_POLICY)).toEqual(DEFAULT_POLICY);
  });

  test("rejects probabilities above one", () => {
    expect(() =>
      decodePolicy({ ...DEFAULT_POLICY, actionThreshold: 1.5 })
    ).toThrow();
  });

  test("rejects a severity block above the scale", () => {
    expect(() =>
      decodePolicy({ ...DEFAULT_POLICY, severityBlock: 4 })
    ).toThrow();
  });
});

describe("buildReport", () => {
  const report = buildReport({
    assessment: ASSESSMENT,
    createdAt: "2026-01-01T00:00:00.000Z",
    policy: POLICY,
    text: "some text",
  });

  test("marks each category with its status", () => {
    const byId = Object.fromEntries(
      report.findings.map((finding) => [finding.id, finding.status])
    );
    expect(byId).toEqual({
      disturbing_content: "review",
      hate_speech: "clear",
      sexual_content: "flagged",
    });
  });

  test("blocks when a category is flagged", () => {
    expect(report.verdict).toBe("block");
  });

  test("explains the verdict with the firing categories", () => {
    expect(report.rationale).toContain("sexual content 0.91");
  });
});
