import { defineConfig } from "oxlint";
import core from "ultracite/oxlint/core";

export default defineConfig({
  extends: [core],
  ignorePatterns: core.ignorePatterns,
  rules: {
    // Domain modeling with Effect Schema puts several Schema.Class
    // declarations in one module on purpose; this is not OOP sprawl.
    "max-classes-per-file": "off",
    // `export const Policy = Schema.Struct(...)` plus
    // `export type Policy = typeof Policy.Type` shares a name between the
    // value and type namespaces, which `no-redeclare` misreads as a clash.
    "no-redeclare": "off",
    // This codebase is built on Effect, whose combinators take callbacks by
    // design. The rule targets promise chains and fires on Effect.catchTag.
    "promise/prefer-await-to-callbacks": "off",
    // `class X extends Schema.TaggedError<X>()(...)` is the Effect schema
    // pattern. The rule mistakes the base-class call for a `throw` target and
    // its autofix inserts a `new` that breaks the class expression.
    "unicorn/throw-new-error": "off",
  },
});
