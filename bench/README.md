# Benchmark

Measures how many real malicious packages the vetcode scanner flags, and how many clean
packages it flags by mistake. Scanner only: the agent's verification step is not part of
these numbers.

| Dataset | Malicious | Benign |
|---|---|---|
| npm | [NPMAnalysis](https://github.com/lxyeternal/NPMAnalysis) (its paper scores GuardDog and 12 other tools on the same data) | NPMAnalysis |
| PyPI | [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) | source distributions of popular packages from pypi.org |
| AI skills | Datadog dataset | skills from Anthropic, Trail of Bits and obra/superpowers |

A package is flagged when vetcode reports a high or critical finding in the malware,
supply-chain or agent categories, ignoring low-confidence findings (tests, docs).

## Run it online (recommended)

Actions → **Benchmark** → Run workflow. Samples are downloaded and scanned on a throwaway
GitHub runner; the results are attached to the run and summarised on its page. No
malicious sample touches your machine.

## Run it locally

Only if you need to: the samples are real malware. Nothing is installed or executed (archives
are unpacked into empty folders, read, and deleted), but antivirus may react.

```bash
node bench/fetch.mjs --cache /tmp/vetcode-bench --npm 1000 --pypi 300 --seed 7
node bench/run.mjs --cache /tmp/vetcode-bench --out bench/results
node bench/summary.mjs bench/results
rm -rf /tmp/vetcode-bench
```

`fetch.mjs` refuses to start with less than 5 GB free. Score in parallel with
`--shard i/n` (one process per shard) and combine with `node bench/merge.mjs <out>`.

## Head to head with other tools

`rivals.mjs` runs another scanner on exactly the samples in a cache, so both are scored on the
same data. GuardDog is scored with each of its four verdicts (any issue, any threat rule, risk
score ≥ 5, ≥ 7) and its best F1 is reported; Cisco skill-scanner runs its static and behavioural
analysers (no LLM) and is scored at max severity high, medium+ and any finding.

```bash
pip install guarddog cisco-ai-skill-scanner      # in a virtualenv
node bench/rivals.mjs --tool guarddog --bin "$(which guarddog)" --cache /tmp/vetcode-bench --out bench/results-guarddog --only npm,pypi
node bench/rivals.mjs --tool skill-scanner --bin "$(which skill-scanner)" --cache /tmp/vetcode-bench --out bench/results-cisco --only skills
```

Latest results on fresh samples (never used for tuning):

| Data | vetcode F1 · precision · recall · false alarms | Other tool (same data) |
|---|---|---|
| npm, 500 + 500 (seed 16) | 94.4 · 97.6 · 91.4 · 2.2% | GuardDog 93.3 · 95.4 · 91.2 · 4.4% |
| PyPI, 300 + 216 (seed 17) | 86.4 · 93.4 · 80.3 · 7.9% | GuardDog 78.3 · 78.5 · 78.0 · 29.6% |
| AI skills, 204 + 132, severity high | caught 29.9%, false alarms 3.0% | Cisco skill-scanner 23.5%, 15.9% |

Each rule change is tuned on one seed and confirmed on a new one; differences of one or two
points between seeds are normal.

## Evasion: does it still catch the sample once it is disguised?

`mutate.mjs` rewrites malicious samples the way attackers do to get past scanners, without
running anything: string literals split and glued with `+`, written as `\xNN` escapes, the
whole file packed into base64 and passed to `eval`/`exec`, JavaScript pushed 400 spaces off
screen, code moved under `dist/`. The same clean packages go into every set, so tools with
several verdicts are judged on their best one. `robustness.mjs` reports, of the samples a tool
caught as they were, how many it still catches after each rewrite.

```bash
node bench/mutate.mjs --cache /tmp/vetcode-bench --out /tmp/vetcode-mutated --n 150
for m in none split hex pack offscreen dist; do node bench/run.mjs --cache /tmp/vetcode-mutated/$m --out /tmp/mv-$m; done
node bench/robustness.mjs --mut /tmp/vetcode-mutated --tool vetcode=/tmp/mv
```

For other tools, score the untouched set first, then pass its best verdict to every rewritten
set with `rivals.mjs --verdict <name>` so the comparison uses one verdict throughout.

Latest (npm seed 18 and PyPI seed 19, 150 malicious + 150 clean each; share of caught samples
still caught):

| | dist/ | hex | off screen | packed | split |
|---|---|---|---|---|---|
| vetcode, npm | 99.2%¹ | 100% | 100% | 100% | 100% |
| GuardDog, npm | 100% | 99.2% | 100% | 92.2% | 99.2% |
| vetcode, PyPI | 100% | 100% | – | 100% | 100% |
| GuardDog, PyPI | 99.2% | 93.4% | – | 100% | 95.9% |

¹ The one sample was moved outside its package by an earlier version of `mutate.mjs` (its
install script no longer pointed at the moved file); fixed since.

## Advanced techniques (red team)

```bash
node bench/redteam.mjs            # this build
node bench/redteam.mjs --lib <path to another build>/skills/vetcode/scripts/lib/index.mjs
```

Fifteen techniques from 2021–2026 campaigns that the public datasets barely contain (code
pushed off-screen in dist/, GlassWorm Unicode payloads, payloads in images, protestware,
time bombs, sandbox evasion, homoglyphs, disguised executables, purpose mismatch, recon
beacons, ClawHavoc-style skills, skills that hide actions, a Visual Studio project with an encoded
PowerShell build event, a Rust build script that steals SSH keys, a Go init() reverse shell),
each next to a clean look-alike.
Samples are generated at run time and carry no working payload. The set was built
alongside the rules, so it measures coverage, not an independent detection rate.
