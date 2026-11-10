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

Every head-to-head run on fresh samples (never used for tuning), oldest first, including the
ones vetcode lost. F1 · precision · recall · false alarms:

| Data | vetcode | GuardDog (best verdict) |
|---|---|---|
| npm seed 14, 500 + 500 | 93.3 · 96.4 · 90.4 · 3.4% | 92.8 · 95.7 · 90.0 · 4.0% |
| npm seed 16, 500 + 500 | 94.4 · 97.6 · 91.4 · 2.2% | 93.3 · 95.4 · 91.2 · 4.4% |
| npm seed 18, 150 + 150 | 92.6 · 97.8 · 88.0 · 2.0% | **93.2** · 94.5 · 92.0 · 5.3% |
| npm seed 20, 500 + 499 | 95.1 · 98.3 · 92.2 · 1.6% | 93.0 · 96.0 · 90.2 · 3.8% |
| npm seed 21, 500 + 498 | 94.1 · 97.2 · 91.2 · 2.6% | **94.2** · 97.4 · 91.2 · 2.4% |
| npm seed 23, 150 + 150 | 93.5 · 96.5 · 90.7 · 3.3% | **94.6** · 96.5 · 92.7 · 3.3% |
| npm seed 26, 500 + 499 | 96.1 · 98.3 · 94.0 · 1.6% | 93.0 · 93.5 · 92.4 · 6.4% |
| npm seed 27, 150 + 150 | 95.5 · 98.6 · 92.7 · 1.3% | 93.9 · 95.2 · 92.7 · 4.7% |
| PyPI seed 12, 300 + 216 | 87.4 · 93.5 · 82.0 · 7.9% | 81.3 · 83.0 · 79.7 · 22.7% |
| PyPI seed 15, 300 + 216 | 84.1 · 93.1 · 76.7 · 7.9% | 81.1 · 82.9 · 79.3 · 22.7% |
| PyPI seed 17, 300 + 216 | 86.4 · 93.4 · 80.3 · 7.9% | 78.3 · 78.5 · 78.0 · 29.6% |
| PyPI seed 19, 150 + 150 | 89.0 · 95.4 · 83.3 · 4.0% | 80.0 · 80.0 · 80.0 · 20.0% |
| PyPI seed 22, 300 + 152 | 89.2 · 96.5 · 83.0 · 5.9% | 85.0 · 87.9 · 82.3 · 22.4% |
| PyPI seed 24, 150 + 150 | 89.0 · 95.4 · 83.3 · 4.0% | 80.0 · 80.0 · 80.0 · 20.0% |
| PyPI seed 28, 150 + 150 | 88.6 · 95.4 · 82.7 · 4.0% | 79.6 · 79.9 · 79.3 · 20.0% |
| AI skills, 204 + 132, severity high | caught 29.9%, false alarms 3.0% | Cisco skill-scanner 23.5%, 15.9% |

Each rule change is tuned on one seed and confirmed on a new one; differences of one or two
points between seeds are normal.

## Evasion: does it still catch the sample once it is disguised?

`mutate.mjs` rewrites malicious samples the way attackers do to get past scanners, without
running anything: string literals split and glued with `+`, written as `\xNN` escapes, built
from character codes or written backwards, the whole file packed into base64 (or gzip, then
base64) and passed to `eval`/`exec`, JavaScript pushed 400 spaces off
screen, code moved under `dist/`. The same clean packages go into every set, so tools with
several verdicts are judged on their best one. `robustness.mjs` reports, of the samples a tool
caught as they were, how many it still catches after each rewrite.

```bash
node bench/mutate.mjs --cache /tmp/vetcode-bench --out /tmp/vetcode-mutated --n 150
for m in none split hex charcode reverse pack zpack offscreen dist; do node bench/run.mjs --cache /tmp/vetcode-mutated/$m --out /tmp/mv-$m; done
node bench/robustness.mjs --mut /tmp/vetcode-mutated --tool vetcode=/tmp/mv
```

For other tools, score the untouched set first, then pass its best verdict to every rewritten
set with `rivals.mjs --verdict <name>` so the comparison uses one verdict throughout.

Latest (share of caught samples still caught; 150 malicious + 150 clean per ecosystem; the
first five columns on npm seed 18 / PyPI seed 19, gzip on seeds 23 / 24, the last two on
seeds 27 / 28):

| | dist/ | hex | off screen | packed | split | gzip | char codes | reversed |
|---|---|---|---|---|---|---|---|---|
| vetcode, npm | 99.2%¹ | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| GuardDog, npm | 100% | 99.2% | 100% | 92.2% | 99.2% | 95.0% | 98.4% | 97.6% |
| vetcode, PyPI | 100% | 100% | – | 100% | 100% | 99.2% | 100% | 100% |
| GuardDog, PyPI | 99.2% | 93.4% | – | 100% | 95.9% | 98.3% | 90.1% | 90.9% |

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

## The agent step: authorization and business logic

```bash
node bench/agent.mjs --scanner-only               # free: the scanner alone
node bench/agent.mjs --runs 2 --jobs 4 --out bench/results/<date>-agent.json   # + Claude Code
node bench/agent.mjs --rescore bench/results/<date>-agent.json                   # score saved runs again
```

Ten small Express and Flask apps, each with one planted bug that patterns cannot see:

- IDOR on an invoice;
- an admin route without the admin check;
- mass assignment of `role`;
- a price taken from the client;
- a negative transfer amount;
- a single-use coupon that can be redeemed again;
- a reset token that is not tied to its account;
- a tenant chosen by a header;
- IDOR in Flask;
- a refund on an order in any state.

Each app sits next to a fixed look-alike that differs only in the fix.

The agent gets a neutral temp folder and is told only to do a vetcode review of its own app. It never learns which bug class to look for. A finding counts when it meets all of these:
- it is in the right file;
- it has a matching class;
- its title names the planted bug;
- it is reported at medium or above.

Results from 2026-11-10, Claude Code with its default model, 2 runs per app:

| | Caught (vulnerable apps) | Same bug reported on the fix |
|---|---|---|
| Scanner alone | 1/10 | 0/10 |
| Scanner + agent | **20/20** | **0/20** |

The agent also reported one further real weakness on a fixed app: a password reset that leaves existing sessions valid. In the first run, it showed that the first "fixed" checkout still let a negative quantity lower the total. The case was corrected so that each app has exactly one bug, and that case was run again. The cost was about $0.33 per review.

**Read this as a check that the review step works, not as a detection rate.** We wrote these apps ourselves. Each holds one bug in about 20 lines, which is far easier than a real codebase, and the model may have seen similar textbook examples. The independent measure is real advisories with their fix commits, published after the model's training cutoff. That is the next step.
