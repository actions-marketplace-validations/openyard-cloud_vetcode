# Contributing

Thanks for helping. The most useful contributions:

1. **A rule for something real.** Point to the advisory, write-up or sample it comes from.
2. **Fewer false positives.** A snippet of legitimate code that vetcode reports, and the change that stops it.
3. **Better reference checklists** (`skills/vetcode/references/`), which guide Claude's manual review.

## Layout

- `skills/vetcode/SKILL.md`: what Claude does with the scanner's output.
- `skills/vetcode/scripts/vet.mjs`: the CLI. Rules live in `scripts/lib/` by area: `malware.mjs`, `supply.mjs`, `agent.mjs`, `secrets.mjs`, `web.mjs`, `config.mjs`.
- `mcp/server.mjs`: the same scanner and checklists as an MCP server (stdio, no dependencies), for agents that do not load skills.
- `tests/vet.test.mjs`: run with `npm test` (Node 18+, no dependencies).

## Writing a rule

A rule is plain data: `id`, `category`, `severity`, `title`, a regex `re` (or a `test(text)` function for whole-file checks), `files` to limit which files it reads, `why` (what an attacker gets, in one sentence) and `fix`.

- Add a test that fires and, where it matters, one that stays quiet on legitimate code.
- **Never commit a real secret or working malware.** Build fixtures from pieces at test time (see how `tests/vet.test.mjs` does it), so GitHub push protection, antivirus and vetcode itself stay quiet on this repository.
- Keep the scanner dependency-free. Large rule sets that already exist elsewhere (semgrep, gitleaks) are better used as external tools than copied.
- Before opening a pull request: `npm test` and `node skills/vetcode/scripts/vet.mjs . --fail-on high`.

Changes go through pull requests; `main` is protected.

## Releasing

Raise the version in all five places (`package.json`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `skills/vetcode/SKILL.md`, `skills/vetcode/scripts/lib/index.mjs`) and the `#vX.Y.Z` pins in the README, then merge to main. The Release workflow tags the version, publishes the GitHub release with `vetcode-skill.zip`, and publishes `@openyard/vetcode` to npm. Pushes that keep the same version do nothing.
