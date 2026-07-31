# Contributing

Thanks for your interest in improving these skills. The bar is simple: changes
must make the security analysis **more accurate**, **more reproducible**, or
**clearer to act on** — never noisier.

## Ground rules

- **One skill, one purpose.** Do not merge responsibilities across skills.
- **No fabricated examples.** Every code sample, finding, or trace in a skill or
  reference file must reflect a real, reproducible case. Placeholder findings are
  not acceptable.
- **Scripts stay deterministic.** Helper scripts under `scripts/` must produce
  the same output for the same input. No network calls in the enumeration path,
  no time-dependent behavior.
- **No secrets.** Never commit API keys, private keys, RPC URLs with tokens, or
  client data.
- **POSIX-portable shell.** Shell scripts must run on GNU (Linux) and BSD
  (macOS) tooling. Use POSIX ERE and POSIX character classes — no PCRE-only
  escapes.

## Making a change

1. Fork and branch from `main`.
2. Keep the change scoped to a single skill unless you are editing shared docs.
3. If you change a skill's behavior, bump its `VERSION` file (semantic
   versioning) and add a line to [CHANGELOG.md](CHANGELOG.md).
4. Run the skill's scripts against the fixtures in that skill's `scripts/`
   directory (where present) and confirm they still pass.
5. Open a pull request describing *what* changed and *why the analysis is better*.

## Adding a new skill

A new skill must include, at minimum:

- `SKILL.md` with valid YAML frontmatter (`name`, `description` with triggers).
- A `VERSION` file starting at `1.0.0`.
- Deterministic helper scripts under `scripts/` if the skill enumerates code.
- Reference material under `references/` — taxonomies and templates, not prose.

Open an issue first to discuss scope so the suite stays focused.
