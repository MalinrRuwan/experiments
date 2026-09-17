#!/usr/bin/env bun
import { BunRuntime, BunServices } from "@effect/platform-bun";
import {
  Console,
  DateTime,
  Effect,
  FileSystem,
  Option,
  Schema,
  Stdio,
  Stream,
} from "effect";
import { Argument, Command, Flag } from "effect/unstable/cli";

import {
  buildReport,
  DEFAULT_POLICY,
  EXIT_CODES,
  Policy,
} from "./moderation.ts";
import { encodeReportJson, renderQuiet, renderReport } from "./render.ts";
import { TypeSafe } from "./type-safe.ts";

class CliInputError extends Schema.TaggedError<CliInputError>()(
  "CliInputError",
  {
    message: Schema.String,
  }
) {}

const readStdin = Effect.fnUntraced(function* readStdin() {
  const stdio = yield* Stdio.Stdio;
  const chunks = yield* Stream.runCollect(stdio.stdin);
  return Buffer.concat(
    Array.from(chunks, (chunk) => Buffer.from(chunk))
  ).toString("utf-8");
});

const resolveText = Effect.fnUntraced(function* resolveText(config: {
  readonly text: Option.Option<string>;
  readonly file: Option.Option<string>;
}) {
  if (Option.isSome(config.file)) {
    if (config.file.value === "-") {
      return yield* readStdin();
    }
    const fs = yield* FileSystem.FileSystem;
    return yield* fs.readFileString(config.file.value);
  }

  if (Option.isSome(config.text)) {
    return config.text.value;
  }

  const stdio = yield* Stdio.Stdio;
  const stdinIsTerminal = yield* stdio.stdinIsTerminal;
  if (stdinIsTerminal) {
    return yield* new CliInputError({
      message:
        'no input: pass text as an argument, use --file, or pipe text into stdin (see "moddy --help")',
    });
  }

  return yield* readStdin();
});

const program = Command.make(
  "moddy",
  {
    actionThreshold: Flag.Finite("action-threshold").pipe(
      Flag.withDescription(
        "Probability at or above which a category is flagged"
      ),
      Flag.withDefault(DEFAULT_POLICY.actionThreshold)
    ),
    color: Flag.Boolean("color").pipe(
      Flag.withDescription(
        "Colorize the terminal report (defaults to on in a terminal)"
      ),
      Flag.optional
    ),
    file: Flag.String("file").pipe(
      Flag.withAlias("f"),
      Flag.withDescription("Read text from a file ('-' reads stdin)"),
      Flag.optional
    ),
    json: Flag.Boolean("json").pipe(
      Flag.withDescription(
        "Print the JSON report instead of the terminal report"
      ),
      Flag.withDefault(false)
    ),
    model: Flag.String("model").pipe(
      Flag.withDescription("TypeSafe model to use"),
      Flag.withDefault("jev-latest")
    ),
    output: Flag.String("output").pipe(
      Flag.withAlias("o"),
      Flag.withDescription("Write the JSON report to a file"),
      Flag.optional
    ),
    quiet: Flag.Boolean("quiet").pipe(
      Flag.withAlias("q"),
      Flag.withDescription("Print only the verdict line"),
      Flag.withDefault(false)
    ),
    reviewThreshold: Flag.Finite("review-threshold").pipe(
      Flag.withDescription(
        "Probability at or above which a category is sent to review"
      ),
      Flag.withDefault(DEFAULT_POLICY.reviewThreshold)
    ),
    severityBlock: Flag.Finite("severity-block").pipe(
      Flag.withDescription("Severity score (0-3) that forces a block"),
      Flag.withDefault(DEFAULT_POLICY.severityBlock)
    ),
    text: Argument.String("text").pipe(
      Argument.withDescription("Text to moderate; omit to read from stdin"),
      Argument.optional
    ),
  },
  (config) =>
    Effect.gen(function* runModerate() {
      const policy = yield* Schema.decodeUnknownEffect(Policy)({
        actionThreshold: config.actionThreshold,
        reviewThreshold: config.reviewThreshold,
        severityBlock: config.severityBlock,
      }).pipe(
        Effect.mapError(
          (error) =>
            new CliInputError({
              message: `invalid thresholds: ${error.message}`,
            })
        )
      );

      const text = (yield* resolveText(config)).trim();
      if (text.length === 0) {
        return yield* new CliInputError({
          message: "no input: the text is empty",
        });
      }

      const typeSafe = yield* TypeSafe;
      const assessment = yield* typeSafe.moderate(text, {
        model: config.model,
      });
      const report = buildReport({
        assessment,
        createdAt: DateTime.formatIso(yield* DateTime.now),
        policy,
        text,
      });

      if (Option.isSome(config.output)) {
        const fs = yield* FileSystem.FileSystem;
        yield* fs.writeFileString(
          config.output.value,
          encodeReportJson(report)
        );
        yield* Console.error(`moddy: wrote ${config.output.value}`);
      }

      if (config.json) {
        yield* Console.log(encodeReportJson(report));
      } else if (config.quiet) {
        yield* Console.log(renderQuiet(report));
      } else {
        const stdio = yield* Stdio.Stdio;
        const stdoutIsTerminal = yield* stdio.stdoutIsTerminal;
        yield* Console.log(
          renderReport(report, {
            color: Option.getOrElse(config.color, () => stdoutIsTerminal),
          })
        );
      }

      yield* Effect.sync(() => {
        process.exitCode = EXIT_CODES[report.verdict];
      });
    }).pipe(
      Effect.catchTag(["CliInputError", "TypeSafeError"], (error) =>
        Effect.gen(function* reportError() {
          yield* Console.error(`moddy: ${error.message}`);
          yield* Effect.sync(() => {
            process.exitCode = 1;
          });
        })
      )
    )
).pipe(
  Command.withDescription(
    "Moderate text with TypeSafe AI: hate speech, sexual content, and disturbing content"
  ),
  Command.withExamples([
    {
      command: 'moddy "Thanks for the help, this looks great"',
      description: "Moderate a string argument",
    },
    {
      command: "pbpaste | moddy",
      description: "Moderate text from stdin",
    },
    {
      command: "moddy --file comment.txt --output report.json",
      description: "Read a file and write the JSON report",
    },
    {
      command: "moddy --quiet --review-threshold 0.2 < comment.txt",
      description: "Script against the verdict and exit code",
    },
  ]),
  Command.run({ version: "0.1.0" }),
  Effect.provide(TypeSafe.layer),
  Effect.provide(BunServices.layer)
);

BunRuntime.runMain(program);
