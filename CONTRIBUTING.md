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
- A new rule about malware, the supply chain or agent files is a **sign**: it is reported, and it does not give a verdict alone until it has a record (`bench/README.md`, "Signs and verdicts"). After changing such rules, run the Benchmark workflow on seed 7 with `skills` and regenerate `skills/vetcode/scripts/lib/data/rule-trust.json` with `bench/calibrate.mjs`; check on seed 31 and `skills-heldout`. Do not edit the table by hand.
- Before opening a pull request: `npm test` and `node skills/vetcode/scripts/vet.mjs . --fail-on high`.

Changes go through pull requests; `main` is protected.

## Releasing

Raise the version in all five places (`package.json`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `skills/vetcode/SKILL.md`, `skills/vetcode/scripts/lib/index.mjs`) and the `#vX.Y.Z` pins in the README, then merge to main. The Release workflow tags the version and publishes the GitHub release with `vetcode-skill.zip`. vetcode is not on npm yet: the workflow also tries to publish there and only warns when the registry refuses, so a release never depends on it. Pushes that keep the same version do nothing.
