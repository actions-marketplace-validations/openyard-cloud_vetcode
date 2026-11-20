// Everything vetcode reads in one file, on its own: the per-file part of a scan. It touches no
// state outside the file, so files can be scanned in any order or on other threads
// (scan-pool.mjs) and give the same findings.
import { scanLines, scanFile, rank, finding, TEST, VENDORED, LOCALE, DEVTOOL, DEVSTACK, TOOLCHAIN } from "./engine.mjs";
import { scanSecrets } from "./secrets.mjs";
import { MALWARE_RULES, MALWARE_FILE_RULES } from "./malware.mjs";
import { WEB_RULES } from "./web.mjs";
import { LANG_RULES } from "./langs.mjs";
import { ECOSYSTEM_FILE_RULES } from "./ecosystems.mjs";
import { CONFIG_RULES, CONFIG_FILE_RULES } from "./config.mjs";
import { scanSupplyChain } from "./supply.mjs";
import { scanAgentFiles } from "./agent.mjs";
import { scanSinks } from "./sinks.mjs";
import { ANOMALY_FILE_RULES } from "./anomaly.mjs";
import { decoded, payloads, stashed } from "./normalize.mjs";

export const YARN_COPY = { id: "committed-package-manager", category: "supply-chain", severity: "low", confidence: "high", title: "The project runs a committed copy of Yarn",
  why: "With yarnPath set, every yarn command runs this file, on each developer's machine and in CI. It is far too large to review by eye, so a changed copy would go unnoticed.",
  fix: "Compare it with the official release: run vetcode with --online, or run `yarn set version <the same version>` and confirm git shows no change." };

// Code hidden from patterns: run the malware rules again on the file with split strings
// joined and escapes decoded, and on base64 payloads it hands to eval/exec. Only what the
// plain text did not already show is added, at the line where the hiding happens.
function scanHidden(file, findings) {
  const views = [];
  const alt = decoded(file.text);
  if (alt) views.push({ text: alt, how: "once its split strings are joined and escapes decoded" });
  // Payloads inside payloads (packed, then packed again): unwrap up to three layers.
  const unwrapFrom = (text, line, depth) => {
    for (const p of [...payloads(text).map(x => ({ ...x, how: "inside a base64 payload it runs" })), ...stashed(text).map(x => ({ ...x, how: "inside an encoded string that decodes to code" }))]) {
      if (views.length > 20) return;
      views.push({ text: p.text, line: line ?? p.line, how: p.how });
      if (depth < 3) unwrapFrom(p.text, line ?? p.line, depth + 1);
    }
  };
  unwrapFrom(file.text, undefined, 1);
  if (!views.length) return;
  const seen = new Set(findings.filter(f => f.file === file.rel).map(f => f.rule));
  for (const v of views) {
    const found = [];
    scanLines(file, v.text, MALWARE_RULES, found);
    scanFile(file, v.text, MALWARE_FILE_RULES, found);
    for (const f of found) {
      if (seen.has(f.rule)) continue;
      seen.add(f.rule);
      findings.push({ ...f, line: v.line || f.line, title: `${f.title} (hidden)`, evidence: `${v.how}: ${f.evidence}`.slice(0, 160) });
    }
  }
}

/** One file: { findings, sinks, partial (bytes, when only its ends were read), yarn (a committed Yarn release) }. */
export function scanOne(file, root) {
  const findings = [], sinks = [], out = { findings, sinks, partial: null, yarn: null };
  // Only a file as big as the real thing: a small script under .yarn/ is read like any other.
  const committedTool = (file, from) => {
    if (!TOOLCHAIN.test(file.rel) || !(file.partial || file.text.length > 200_000)) return false;
    for (let i = from; i < findings.length; i++) findings[i].confidence = "low";
    const yarn = /(^|\/)\.yarn\/releases\/yarn-(\d+\.\d+\.\d+)\.cjs$/.exec(file.rel);
    if (yarn) { findings.push(finding(YARN_COPY, file.rel, 1, `yarn ${yarn[2]}`)); out.yarn = { rel: file.rel, abs: file.abs, version: yarn[2] }; }
    return true;
  };
  if (file.partial) {
    // Too big to read whole: secrets and malware checks on its first and last 256 KB.
    const from = findings.length;
    scanSecrets(file, file.text, findings);
    scanLines(file, file.text, MALWARE_RULES, findings);
    scanFile(file, file.text, MALWARE_FILE_RULES, findings);
    // A committed package manager is expected to be this big; it is checked by comparison below, not by reading.
    if (committedTool(file, from)) return out;
    // More than a megabyte of JavaScript in one file is build output: its matches stay visible and decide nothing.
    if (/\.(c|m)?js$/.test(file.rel)) for (let i = from; i < findings.length; i++) if (findings[i].confidence === "medium") findings[i].confidence = "low";
    out.partial = file.partial;
    return out;
  }
  const mark = findings.length;
  scanAgentFiles(file, file.text, findings);
  scanSecrets(file, file.text, findings);
  scanLines(file, file.text, MALWARE_RULES, findings);
  scanFile(file, file.text, MALWARE_FILE_RULES, findings);
  scanHidden(file, findings);
  scanLines(file, file.text, WEB_RULES, findings);
  scanLines(file, file.text, LANG_RULES, findings);
  scanFile(file, file.text, ECOSYSTEM_FILE_RULES, findings);
  scanLines(file, file.text, CONFIG_RULES, findings);
  scanFile(file, file.text, CONFIG_FILE_RULES, findings);
  scanSupplyChain(file, file.text, findings, root);
  scanFile(file, file.text, ANOMALY_FILE_RULES, findings);
  scanSinks(file, file.text, sinks);
  // A vulnerability pattern in a test, a fixture or a vendored library is not in the app's own
  // request path. Malware, secrets and supply-chain findings there still count.
  if (TEST.test(file.rel) || VENDORED.test(file.rel) || LOCALE.test(file.rel)) for (let k = findings.length - 1; k >= mark; k--) if (findings[k].category === "web") findings.splice(k, 1);
  // Maintainer scripts and development containers: kept, but as low. Secrets and malware there keep their severity.
  const dev = DEVTOOL.test(file.rel), stack = DEVSTACK.test(file.rel);
  if (dev || stack) for (let k = mark; k < findings.length; k++) {
    const f = findings[k];
    if (((dev && f.category === "web") || (stack && f.category === "config")) && rank(f.severity) < rank("low")) findings[k] = { ...f, severity: "low" };
  }
  // Bundled or minified output is full of patterns that mean nothing there; keep its findings
  // visible but let only high-confidence ones decide.
  // Only JavaScript ships that way on purpose: a one-line Python file or setup.py is itself
  // suspicious (that is how obfuscated payloads look), so those keep their confidence.
  if (/\.(c|m)?js$/.test(file.rel) && (/\.min\.|[-.]bundle\.|\.dart\.js$|(^|\/)(dist|out)\//.test(file.rel) || file.text.length / (file.text.split("\n").length || 1) > 300))
    for (let i = mark; i < findings.length; i++) if (findings[i].confidence === "medium") findings[i].confidence = "low";
  // A committed package manager matches every pattern and none of it means anything; its
  // findings stay visible but decide nothing. What matters is whether the file is the
  // official one, and that is a comparison (--online), not a pattern.
  committedTool(file, mark);
  return out;
}
