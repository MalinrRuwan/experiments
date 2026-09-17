# moddy

Content moderation CLI powered by [TypeSafe AI](https://typesafe.ai) (Jev) and [Effect](https://effect.website). It reads text from an argument, a file, or stdin, asks Jev a battery of content questions, and turns the probabilities into one of three verdicts:

- **allow** — nothing reached the review threshold
- **review** — something is borderline; a human should look
- **block** — a category or the severity score crossed the action line

The categories are hate speech, sexual content, and disturbing content (graphic violence, cruelty, abuse, harassment, self-harm, suicide).

## Setup

Requires [Bun](https://bun.sh).

```sh
bun install
cp .env.example .env   # then add TYPESAFE_API_KEY from console.typesafe.ai
```

Bun loads `.env` automatically. You can also export `TYPESAFE_API_KEY` in your shell instead.

## Usage

```sh
# Text as an argument
moddy "Thanks for the help yesterday, the new dashboard looks great."

# From stdin
pbpaste | moddy
cat comment.txt | bun run src/cli.ts

# From a file, writing a JSON report next to the terminal report
moddy --file comment.txt --output report.json

# Machine-readable output only
moddy --json --file comment.txt > report.json

# Quiet mode for scripts (exit code carries the verdict)
if moddy --quiet --file comment.txt; then echo "ok"; fi
```

Without a global install, run it with `bun run src/cli.ts …`.

### Options

| Option | Description |
| --- | --- |
| `[text]` | Text to moderate; omit to read stdin |
| `-f, --file <path>` | Read text from a file (`-` reads stdin) |
| `-o, --output <path>` | Also write the JSON report to a file |
| `--json` | Print the JSON report instead of the terminal report |
| `-q, --quiet` | Print only the verdict line |
| `--model <name>` | TypeSafe model (default `jev-latest`) |
| `--review-threshold <n>` | Probability for a review (default `0.35`) |
| `--action-threshold <n>` | Probability for a flag (default `0.70`) |
| `--severity-block <n>` | Severity score that forces a block (default `2`) |
| `--color` / `--no-color` | Force or disable ANSI colors (default: on in a terminal) |

### Exit codes

| Code | Meaning                                |
| ---- | -------------------------------------- |
| `0`  | allow                                  |
| `1`  | error, missing input, or invalid flags |
| `2`  | review                                 |
| `3`  | block                                  |

## Example

```text
moddy · content moderation

  text       "I will find you and make you pay for this."
  model      jev-latest

  hate speech          0.05  ····················  CLEAR
  sexual content       0.02  ····················  CLEAR
  disturbing content   0.96  ████████████████████  FLAGGED

  severity   2.3/3  moderate: a clear content-policy violation, but not extreme (confidence 0.81)
  verdict    BLOCK  disturbing content 0.96 (flagged), severity 2.3 >= 2
  tokens     389 in / 41 out
```

## How it works

1. `src/type-safe.ts` sends one request with four questions: a `Noul` per category and a `Score` for severity. The raw response is validated with `Schema` before it enters the domain.
2. `src/moderation.ts` holds the policy: thresholds, precedence, and the `Report` model. This is pure code, so changing a threshold does not change what the model was asked.
3. `src/cli.ts` handles input resolution, output, and exit codes.

The model supplies calibrated probabilities; the decision stays in your code and in the flags you pass. See `AGENTS.md` for conventions.

## Development

```sh
bun test              # policy tests, no API calls
bun run typecheck     # tsc --noEmit
bun run check         # Ultracite (Oxlint) read-only
bun run fix           # Ultracite auto-fix (Oxlint + Oxfmt)
```

## Notes

- Text is sent to the TypeSafe API for evaluation. Do not feed it anything you cannot share with your provider.
- TypeSafe returns probabilities, not text generations, so moddy never rewrites or paraphrases your content.
