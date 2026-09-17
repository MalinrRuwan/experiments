import { Schema } from "effect";

/**
 * The content categories moddy checks. Each maps to one Noul question in
 * `src/type-safe.ts`.
 */
export const CATEGORY_IDS = [
  "hate_speech",
  "sexual_content",
  "disturbing_content",
] as const;

export const CategoryId = Schema.Literals(CATEGORY_IDS);
export type CategoryId = typeof CategoryId.Type;

export const CATEGORY_LABELS: Readonly<Record<CategoryId, string>> = {
  disturbing_content: "disturbing content",
  hate_speech: "hate speech",
  sexual_content: "sexual content",
};

/** The severity rubric, low to high. Index is the level number. */
export const SEVERITY_LEVELS = [
  "safe: ordinary content with nothing concerning",
  "mild: crude, rude, or suggestive, but not a policy violation",
  "moderate: a clear content-policy violation, but not extreme",
  "severe: extreme hate, explicit sexual content, or graphic disturbing material",
] as const;

/** What a category probability means once the policy is applied. */
export const CategoryStatus = Schema.Literals(["clear", "review", "flagged"]);
export type CategoryStatus = typeof CategoryStatus.Type;

export class Finding extends Schema.Class<Finding>("moddy/Finding")({
  id: CategoryId,
  label: Schema.String,
  probability: Schema.Number,
  status: CategoryStatus,
}) {}

const Probability = Schema.Number.pipe(
  Schema.check(Schema.isBetween({ maximum: 1, minimum: 0 }))
);
const SeverityScore = Schema.Number.pipe(
  Schema.check(Schema.isBetween({ maximum: 3, minimum: 0 }))
);

/** Application-owned thresholds. TypeSafe answers; this decides. */
export const Policy = Schema.Struct({
  actionThreshold: Probability,
  reviewThreshold: Probability,
  severityBlock: SeverityScore,
});

export type Policy = typeof Policy.Type;

export const DEFAULT_POLICY: Policy = {
  actionThreshold: 0.7,
  reviewThreshold: 0.35,
  severityBlock: 2,
};

export const decodePolicy = Schema.decodeUnknownSync(Policy);

export const Verdict = Schema.Literals(["allow", "review", "block"]);
export type Verdict = typeof Verdict.Type;

export const EXIT_CODES: Readonly<Record<Verdict, number>> = {
  allow: 0,
  block: 3,
  review: 2,
};

export class Severity extends Schema.Class<Severity>("moddy/Severity")({
  confidence: Schema.Number,
  label: Schema.String,
  score: Schema.Number,
}) {}

export class Usage extends Schema.Class<Usage>("moddy/Usage")({
  inputTokens: Schema.Number,
  outputTokens: Schema.Number,
}) {}

export class Report extends Schema.Class<Report>("moddy/Report")({
  createdAt: Schema.String,
  findings: Schema.Array(Finding),
  model: Schema.String,
  rationale: Schema.String,
  severity: Severity,
  text: Schema.String,
  usage: Usage,
  verdict: Verdict,
}) {}

export const statusFor = (
  probability: number,
  policy: Policy
): CategoryStatus => {
  if (probability >= policy.actionThreshold) {
    return "flagged";
  }
  if (probability >= policy.reviewThreshold) {
    return "review";
  }
  return "clear";
};

/** The strictest result wins: block beats review beats allow. */
export const verdictFor = (
  findings: readonly Finding[],
  severityScore: number,
  policy: Policy
): Verdict => {
  if (
    findings.some((finding) => finding.status === "flagged") ||
    severityScore >= policy.severityBlock
  ) {
    return "block";
  }
  return findings.some((finding) => finding.status === "review")
    ? "review"
    : "allow";
};

export const severityLabel = (score: number): string => {
  const level = Math.min(
    SEVERITY_LEVELS.length - 1,
    Math.max(0, Math.round(score))
  );
  return SEVERITY_LEVELS[level];
};

const rationaleFor = (
  findings: readonly Finding[],
  severity: Severity,
  policy: Policy,
  verdict: Verdict
): string => {
  if (verdict === "allow") {
    return `no category reached the review threshold (${policy.reviewThreshold}); severity ${severity.score.toFixed(1)}`;
  }

  const reasons = findings
    .filter((finding) => finding.status !== "clear")
    .map(
      (finding) =>
        `${finding.label} ${finding.probability.toFixed(2)} (${finding.status})`
    );

  if (severity.score >= policy.severityBlock) {
    reasons.push(
      `severity ${severity.score.toFixed(1)} >= ${policy.severityBlock}`
    );
  }

  return reasons.join(", ");
};

export interface Assessment {
  readonly model: string;
  readonly probabilities: Readonly<Record<CategoryId, number>>;
  readonly severity: {
    readonly score: number;
    readonly confidence: number;
  };
  readonly usage: {
    readonly inputTokens: number;
    readonly outputTokens: number;
  };
}

/** Combine one TypeSafe assessment and one policy into a report. Pure. */
export const buildReport = (input: {
  readonly text: string;
  readonly assessment: Assessment;
  readonly policy: Policy;
  readonly createdAt: string;
}): Report => {
  const findings = CATEGORY_IDS.map(
    (id) =>
      new Finding({
        id,
        label: CATEGORY_LABELS[id],
        probability: input.assessment.probabilities[id],
        status: statusFor(input.assessment.probabilities[id], input.policy),
      })
  );

  const severity = new Severity({
    confidence: input.assessment.severity.confidence,
    label: severityLabel(input.assessment.severity.score),
    score: input.assessment.severity.score,
  });

  const verdict = verdictFor(findings, severity.score, input.policy);

  return new Report({
    createdAt: input.createdAt,
    findings,
    model: input.assessment.model,
    rationale: rationaleFor(findings, severity, input.policy, verdict),
    severity,
    text: input.text,
    usage: new Usage({
      inputTokens: input.assessment.usage.inputTokens,
      outputTokens: input.assessment.usage.outputTokens,
    }),
    verdict,
  });
};
