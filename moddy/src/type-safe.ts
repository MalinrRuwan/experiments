import { noul, score, TypeSafeClient } from "@typesafe-ai/sdk";
import { Config, Context, Effect, Layer, Redacted, Schema } from "effect";

import type { Assessment } from "./moderation.ts";
import { SEVERITY_LEVELS } from "./moderation.ts";

/**
 * The question battery. Every question is answered in one request; code turns
 * the probabilities into a decision. Keep known policy out of these prompts.
 */
const QUESTIONS = {
  disturbing_content: noul(
    "Would this text make a typical reader uncomfortable or distressed?",
    {
      false:
        "It is ordinary conversation, criticism, or a disagreement that a typical reader would not find distressing.",
      true: "It depicts graphic violence, gore, cruelty, abuse, harassment, self-harm, or suicide in a way a typical reader would find distressing.",
    }
  ),
  hate_speech: noul(
    "Does this text contain hate speech or an attack on people because of who they are?",
    {
      false:
        "It contains no attack on a person or group based on a protected characteristic.",
      true: "It attacks, dehumanises, or calls for harm against people based on race, ethnicity, religion, nationality, immigration status, gender, gender identity, sexual orientation, disability, age, or another protected characteristic.",
    }
  ),
  severity: score(
    "How severe is the content problem in this text?",
    SEVERITY_LEVELS
  ),
  sexual_content: noul("Does this text contain sexual content?", {
    false:
      "It contains no sexual content. Romance, affection, and clinical health discussion are not sexual content.",
    true: "It depicts, describes, or explicitly requests sexual activity, sexual anatomy, or sexual acts.",
  }),
};

const NoulAnswer = Schema.Struct({
  noul: Schema.Number,
  type: Schema.Literal("noul"),
});

const ScoreAnswer = Schema.Struct({
  confidence: Schema.Number,
  score: Schema.Number,
  type: Schema.Literal("score"),
});

/** Runtime validation of the raw API response before it enters the domain. */
const SystemOneResponse = Schema.Struct({
  answers: Schema.Struct({
    disturbing_content: NoulAnswer,
    hate_speech: NoulAnswer,
    severity: ScoreAnswer,
    sexual_content: NoulAnswer,
  }),
  model: Schema.String,
  usage: Schema.Struct({
    input_tokens: Schema.Number,
    output_tokens: Schema.Number,
  }),
});

export class TypeSafeError extends Schema.TaggedError<TypeSafeError>()(
  "TypeSafeError",
  {
    message: Schema.String,
    reason: Schema.Literals([
      "missing_api_key",
      "request_failed",
      "invalid_response",
    ]),
  }
) {}

const clientFromEnv = Effect.fnUntraced(function* clientFromEnv() {
  const apiKey = yield* Config.Redacted("TYPESAFE_API_KEY").pipe(
    Effect.catchTag("ConfigError", () =>
      Effect.fail(
        new TypeSafeError({
          message:
            "TYPESAFE_API_KEY is not set. Put it in .env or export it before running moddy.",
          reason: "missing_api_key",
        })
      )
    )
  );

  return new TypeSafeClient({
    apiKey: Redacted.value(apiKey),
    timeout: 60_000,
  });
});

const moderate = Effect.fn("TypeSafe.moderate")(function* moderate(
  text: string,
  options?: { readonly model?: string }
): Effect.fn.Return<Assessment, TypeSafeError> {
  const client = yield* clientFromEnv();

  const raw = yield* Effect.tryPromise({
    catch: (cause) =>
      new TypeSafeError({
        message: cause instanceof Error ? cause.message : String(cause),
        reason: "request_failed",
      }),
    try: () =>
      client.systemOne({
        questions: QUESTIONS,
        state: text,
        ...(options?.model === undefined ? {} : { model: options.model }),
      }),
  });

  const response = yield* Schema.decodeUnknownEffect(SystemOneResponse)(
    raw
  ).pipe(
    Effect.mapError(
      (error) =>
        new TypeSafeError({
          message: `Unexpected response from TypeSafe: ${error.message}`,
          reason: "invalid_response",
        })
    )
  );

  return {
    model: response.model,
    probabilities: {
      disturbing_content: response.answers.disturbing_content.noul,
      hate_speech: response.answers.hate_speech.noul,
      sexual_content: response.answers.sexual_content.noul,
    },
    severity: {
      confidence: response.answers.severity.confidence,
      score: response.answers.severity.score,
    },
    usage: {
      inputTokens: response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    },
  };
});

/** Assessment of one piece of text. No verdict yet; the policy decides. */
export class TypeSafe extends Context.Service<
  TypeSafe,
  {
    readonly moderate: (
      text: string,
      options?: { readonly model?: string }
    ) => Effect.Effect<Assessment, TypeSafeError>;
  }
>()("moddy/TypeSafe") {
  static readonly layer: Layer.Layer<TypeSafe> = Layer.succeed(
    TypeSafe,
    TypeSafe.of({ moderate })
  );
}
