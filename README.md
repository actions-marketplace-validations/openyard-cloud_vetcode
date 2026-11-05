# vetcode

**A security check you can run before you trust code: your own app before it ships, or someone else's repo, package, extension or MCP server before you install it.**

vetcode is an [Agent Skill](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview) for Claude (Claude Code, claude.ai, and other agents that load skills). A zero-dependency scanner finds candidates in seconds; then Claude reads the code around each one, traces where the data comes from, throws out false positives, and looks for what patterns cannot see (missing authorization, IDOR, broken business logic). You get a short report with real findings, concrete attack scenarios and fixes.

Free and open source (MIT), from the [OpenYard](https://openyard.cloud) community.

[Tiếng Việt ở cuối trang ↓](#tiếng-việt)

## What it checks

| Area | Examples |
|---|---|
| **Malware** | decode-then-`eval`, download-and-run, reverse shells, credential and wallet theft (`~/.ssh`, `~/.aws`, browser profiles), env-var exfiltration to webhooks, `_0x` obfuscation, hidden Unicode payloads (GlassWorm), Trojan Source bidi characters, AI CLIs started with permission prompts off, self-spreading `npm publish` worms, `.pth` autoruns, miners |
| **Supply chain** | suspicious `preinstall`/`postinstall`, typosquats (`expresss`, `@angullar/core`, `reqeusts`), git/URL dependencies, lockfile packages from foreign hosts, `--extra-index-url` dependency confusion, `setup.py` that runs code, VS Code tasks that run on folder open, git hooks, known vulnerable and **known malicious** packages via [OSV.dev](https://osv.dev) |
| **AI agents** | project `.claude/settings.json` with hooks, API base-URL redirects or auto-approved MCP servers; prompt injection and hidden comments in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, skills; poisoned MCP tool descriptions; unpinned or plain-HTTP MCP servers |
| **Secrets** | 40+ providers (cloud, AI, payment, SaaS, registries), private keys, database URLs, Supabase `service_role` keys (and not the public anon key), committed `.env`, secrets in git history, secrets behind `NEXT_PUBLIC_`/`VITE_` prefixes |
| **Web / API** | SQL/NoSQL/command injection, XSS, SSTI, path traversal, SSRF, open redirects, unsafe deserialisation, weak JWT handling, TLS checks off, permissive CORS, mass assignment, weak password hashing, insecure randomness, zip slip, XXE, prototype pollution, model output passed to `eval` |
| **Server & cloud** | root containers, secrets in image layers, privileged/socket-mounted containers, databases published on all interfaces, nginx alias traversal, public buckets, open SSH/RDP, Cloudflare secrets in `vars`, Supabase tables without RLS or with `using (true)` policies, Firebase rules open to everyone |
| **CI/CD** | `pull_request_target` / `workflow_run` running PR code, script injection from PR titles, `GITHUB_ENV` injection, `secrets: inherit`, spoofable bot checks, actions pinned to movable tags |

## Install

**Claude Code** (plugin):

```
/plugin marketplace add openyard-cloud/vetcode
/plugin install vetcode@openyard
```

or copy the skill folder by hand: `git clone https://github.com/openyard-cloud/vetcode && cp -r vetcode/skills/vetcode ~/.claude/skills/`

**claude.ai:** download `vetcode-skill.zip` from [Releases](https://github.com/openyard-cloud/vetcode/releases) and upload it under Settings → Capabilities → Skills.

Requires Node.js 18+ for the scanner. Without Node, Claude still reviews by hand using the checklists in `references/`.

## Use

Just ask:

- "Check this repo for malware before I run it"
- "Security review before I deploy"
- "Is this MCP server safe to install?"
- "Review my changes for security issues"

or run `/vetcode` (Claude Code; `/vetcode:vetcode` when installed as a plugin).

### The scanner on its own

```bash
node skills/vetcode/scripts/vet.mjs [path] [options]
```

| Option | |
|---|---|
| `--online` | look up dependencies on OSV.dev (known vulnerabilities and malware); also runs semgrep, osv-scanner and trivy if installed |
| `--deps` | read installed `node_modules`: install scripts, and the full code of packages that have them |
| `--history` | search git history for secrets that were committed and later removed |
| `--diff [base]` | only files changed against `base` (default: uncommitted changes) |
| `--no-ignore` | ignore `.vetcodeignore` and inline suppressions (always use this on code you did not write) |
| `--json file` / `--sarif file` | full results as JSON, or SARIF 2.1.0 for GitHub code scanning |
| `--fail-on <severity>` | exit 1 if a finding at that level or worse exists |
| `--no-tools` | do not run external tools (gitleaks runs automatically if installed) |

### In CI

```yaml
name: vetcode
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@v4
        with: { repository: openyard-cloud/vetcode, path: .vetcode }
      - run: node .vetcode/skills/vetcode/scripts/vet.mjs . --sarif vetcode.sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: vetcode.sarif }
```

### Suppressing a false positive

```js
const id = Math.random(); // vetcode-ignore[insecure-random] used for a UI animation, not a secret
```

Name the rule. Folders can go in `.vetcodeignore` (gitignore syntax). Every report shows how much was suppressed, and `--no-ignore` turns all of it off.

## How it works, and its limits

The scanner is regex and heuristics: fast, offline, explainable, and noisy on purpose. It produces candidates, not verdicts. The skill tells Claude to confirm each one with a concrete exploit scenario, drop what it cannot justify, and review what patterns cannot see. [Cisco's measurements on malicious agent skills](https://github.com/cisco-ai-defense/skill-scanner) found that rules alone catch a small share of them, while adding a model's judgement catches far more; vetcode is built around that combination.

It is not a guarantee. New malware, logic bugs and infrastructure outside the repository can still slip through. Treat a clean report as "nothing obvious found".

**Privacy:** everything runs locally. Only with `--online` are package names and versions sent to OSV.dev. Secrets are redacted in every report.

## Learning from others

vetcode borrows ideas (not code) from projects that do parts of this very well, and works alongside them: [GuardDog](https://github.com/DataDog/guarddog), [zizmor](https://github.com/zizmorcore/zizmor), [gitleaks](https://github.com/gitleaks/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog), [Snyk agent-scan (mcp-scan)](https://github.com/invariantlabs-ai/mcp-scan), [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages), [semgrep](https://github.com/semgrep/semgrep), [claude-code-security-review](https://github.com/anthropics/claude-code-security-review) and [Trail of Bits' skills](https://github.com/trailofbits/skills). If you need deep coverage in one area, use them too; vetcode will pick up gitleaks, semgrep, osv-scanner and trivy when they are installed.

## Contributing

New rules, fewer false positives and real-world samples are all welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Found a way to make vetcode miss malware? Please report it privately: [SECURITY.md](SECURITY.md).

---

## Tiếng Việt

**vetcode** là một skill kiểm tra bảo mật cho Claude. Dùng nó để soát app, web, server của bạn trước khi deploy, hoặc soát repo, package, extension, MCP server của người khác trước khi cài.

- **Cách hoạt động:** bộ quét (không cần cài gì thêm) tìm các điểm đáng ngờ trong vài giây. Sau đó Claude đọc code quanh từng điểm, lần theo dữ liệu, loại báo động giả, và tìm thêm lỗi mà regex không thấy được như thiếu phân quyền, IDOR hay sai logic nghiệp vụ.
- **Kiểm tra:** mã độc, tấn công chuỗi cung ứng (package giả tên, script cài đặt độc), lỗ hổng nhắm vào AI agent (hooks, chỉ dẫn ẩn trong `CLAUDE.md`, MCP độc), lộ key và secret, lỗ hổng web/API, cấu hình server và cloud (Docker, nginx, Supabase RLS, Firebase, Cloudflare), CI/CD.
- **Cài cho Claude Code:** `/plugin marketplace add openyard-cloud/vetcode` rồi `/plugin install vetcode@openyard`.
- **Dùng:** hỏi bằng tiếng Việt, ví dụ "kiểm tra bảo mật repo này", "quét mã độc trước khi cài", "soát lỗ hổng trước khi deploy". Báo cáo sẽ trả lời bằng tiếng Việt.
- **Riêng tư:** mọi thứ chạy trên máy bạn. Chỉ khi bật `--online` thì tên và phiên bản package mới được gửi tới OSV.dev. Secret luôn được che trong báo cáo.

Miễn phí, mã nguồn mở (MIT), thuộc cộng đồng [OpenYard](https://openyard.cloud).
