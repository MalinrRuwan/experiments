# moddy

Content moderation CLI built with TypeSafe AI (Jev) and Effect.

moddy takes text from an argument, a file, or stdin, asks TypeSafe's Jev model a battery of questions about it, and turns the probabilities into a verdict: `allow`, `review`, or `block`.

## Stack

- **Bun only.** Use `bun` / `bunx` for everything. Never `npm`, `npx`, `pnpm`, `yarn`, or `node`. `bun.lock` is the only lockfile; do not commit or create `package-lock.json` or `yarn.lock`.
- **Effect v4 RC** (`effect@rc`) for services, layers, CLI parsing, errors, logging, and file/stdin IO. See the Effect section below before writing code.
- **TypeSafe AI** via `@typesafe-ai/sdk`. The model returns calibrated probabilities, not text.
- **Effect CLI** from `effect/unstable/cli` for flags, arguments, help, and version.
- **Ultracite** with **Oxlint** (linting) and **Oxfmt** (formatting). Config lives in `oxlint.config.ts` and `oxfmt.config.ts`.

## Commands

| Task | Command |
| --- | --- |
| Install | `bun install` |
| Run (dev) | `bun run src/cli.ts "text"` / `echo "text" \| bun run src/cli.ts` |
| Typecheck | `bun run typecheck` |
| Test | `bun test` |
| Lint (read-only) | `bun run check` |
| Lint + format (fix) | `bun run fix` |
| Build a binary | `bun build --compile src/cli.ts --outfile moddy` |

Bun loads `.env` automatically. Copy `.env.example` to `.env` and set `TYPESAFE_API_KEY` (also available as `TYPESAFE_DEFAULT_MODEL` and `TYPESAFE_BASE_URL` via the SDK).

## Architecture

```
src/cli.ts        Command definition, input resolution, output routing, exit codes
src/type-safe.ts  TypeSafe service: question battery, Effect-wrapped SDK call,
                  Schema-validated responses
src/moderation.ts Domain model and policy: categories, thresholds, routing, Report
src/render.ts     Terminal report and JSON encoding
test/             Bun tests for the policy logic (no API calls)
```

- `Moderation` is pure. Thresholds and precedence live in code, not in prompts, so policy changes do not require new inference.
- `TypeSafe` wraps the SDK's promise API with `Effect.tryPromise` and decodes the raw response with `Schema` before it enters the domain.
- `cli.ts` owns IO and exit codes only.

## Conventions

- Model domain values with `Schema` (`Schema.Class`, `Schema.Struct`, `Schema.Literals`) and decode untrusted data at the boundary with `Schema.decodeUnknownEffect` / `Schema.decodeUnknownSync`.
- Define errors with `Schema.TaggedError` and handle them with `Effect.catchTag`.
- Prefer `Effect.fn("Service.method")` for reusable effectful functions and `Effect.fnUntraced` for small helpers.
- Use `Context.Service` + `Layer` for anything touching the outside world.
- Exit codes: `0` allow, `1` error/missing input, `2` review, `3` block.

## Content categories

| id | What it catches |
| --- | --- |
| `hate_speech` | Attacks or calls for harm against people based on a protected characteristic |
| `sexual_content` | Sexual activity, anatomy, or explicit requests |
| `disturbing_content` | Graphic violence, cruelty, abuse, harassment, self-harm, suicide |

Each category is one `Noul` (yes/no probability). A `Score` rates severity 0-3. The routing rule: a category at or above `--action-threshold` flags, at or above `--review-threshold` reviews, and severity at or above `--severity-block` forces a block. The strictest outcome wins.

## Linting and formatting

This project uses [Ultracite](https://ultracite.ai) with Oxlint and Oxfmt.

- `bun run check` lints without writing changes.
- `bun run fix` applies lint fixes and Oxfmt formatting.
- Run `bun run check` and `bun run typecheck` before considering a change done.

Follow the Ultracite code standards: `const` by default, `for...of` over `.forEach`, early returns, no `any`, no `console.log` in production code (use Effect's `Console` or logging services), and `as const` for immutable values.

## Learning more about Effect

This repository uses the Effect Typescript library.

Before writing any Effect code, first read `node_modules/effect/AGENTS.md` **completely**, and follow the links in the file when required.

If you need to learn more about particular Effect apis and concepts that the guide doesn't cover, search through the source code in `node_modules/effect/src`.
