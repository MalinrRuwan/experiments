import { Schema } from "effect";

import { Report } from "./moderation.ts";
import type { CategoryStatus, Verdict } from "./moderation.ts";

/** The JSON representation written by `--json` and `--output`. */
export const encodeReportJson = Schema.encodeSync(
  Schema.fromJsonString(Report, { space: 2 })
);

const ANSI = {
  bold: "\u001B[1m",
  dim: "\u001B[2m",
  green: "\u001B[32m",
  red: "\u001B[31m",
  reset: "\u001B[0m",
  yellow: "\u001B[33m",
} as const;

const VERDICT_COLORS: Readonly<Record<Verdict, string>> = {
  allow: ANSI.green,
  block: ANSI.red,
  review: ANSI.yellow,
};

const STATUS_COLORS: Readonly<Record<CategoryStatus, string>> = {
  clear: ANSI.dim,
  flagged: ANSI.red,
  review: ANSI.yellow,
};

const BAR_WIDTH = 20;
const TEXT_PREVIEW_LENGTH = 72;

const paint = (code: string, text: string, enabled: boolean): string =>
  enabled ? `${code}${text}${ANSI.reset}` : text;

const bar = (probability: number): string => {
  const filled = Math.round(probability * BAR_WIDTH);
  return "█".repeat(filled) + "·".repeat(BAR_WIDTH - filled);
};

/** Collapse whitespace and truncate so a report always fits on one line per field. */
const preview = (text: string, maxLength = TEXT_PREVIEW_LENGTH): string => {
  const collapsed = text.replaceAll(/\s+/gu, " ").trim();
  return collapsed.length > maxLength
    ? `${collapsed.slice(0, maxLength - 1)}…`
    : collapsed;
};

export const renderReport = (
  report: Report,
  options: { readonly color: boolean }
): string => {
  const { color } = options;
  const lines = [
    paint(ANSI.bold, "moddy · content moderation", color),
    "",
    `  ${paint(ANSI.dim, "text", color)}       ${preview(report.text)}`,
    `  ${paint(ANSI.dim, "model", color)}      ${report.model}`,
    "",
  ];

  for (const finding of report.findings) {
    lines.push(
      `  ${finding.label.padEnd(20)} ${finding.probability.toFixed(2)}  ${bar(finding.probability)}  ${paint(
        STATUS_COLORS[finding.status],
        finding.status.toUpperCase(),
        color
      )}`
    );
  }

  lines.push(
    "",
    `  ${paint(ANSI.dim, "severity", color)}   ${report.severity.score.toFixed(1)}/3  ${report.severity.label} ${paint(
      ANSI.dim,
      `(confidence ${report.severity.confidence.toFixed(2)})`,
      color
    )}`,
    `  ${paint(ANSI.dim, "verdict", color)}    ${paint(
      `${ANSI.bold}${VERDICT_COLORS[report.verdict]}`,
      report.verdict.toUpperCase(),
      color
    )}  ${paint(ANSI.dim, report.rationale, color)}`,
    `  ${paint(ANSI.dim, "tokens", color)}     ${report.usage.inputTokens} in / ${report.usage.outputTokens} out`
  );

  return lines.join("\n");
};

/** One line for scripts: `BLOCK  hate speech 0.98 (flagged)`. */
export const renderQuiet = (report: Report): string =>
  `${report.verdict.toUpperCase()}  ${report.rationale}`;
