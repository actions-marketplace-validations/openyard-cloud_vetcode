// Places to read. A dangerous call whose argument is not a fixed text is not a finding: on real
// applications most of them are fine, and on real advisories the bug is usually that the value
// reaching such a call was not checked somewhere else. What a scanner can honestly say is where
// those calls are, so that a reader traces each value back instead of searching for the calls.
//
// A place is reported apart from the findings (result.places): it has no severity, does not fail
// a build, and costs one line per file in the report. bench/injection.mjs measures how often a
// place stands where a real bug was fixed; bench/noise.mjs how many there are in code that is fine.
import { TEST, DOC, VENDORED, LOCALE, DEVTOOL, TOOLCHAIN } from "./engine.mjs";
import fs from "node:fs";

// Entries of the catalogue that were measured to fire often on applications that are fine and never
// where a real bug was fixed (bench/calibrate-web.mjs): they would only add lines to read.
let DROPPED = new Set();
try { DROPPED = new Set(JSON.parse(fs.readFileSync(new URL("./data/web-places.json", import.meta.url), "utf8")).dropped || []); } catch {}

export const KINDS = {
  command: { title: "Runs a program with an argument that is not fixed", ask: "Can any part of the command or its arguments come from a request, a file name, a setting or another system? An argument that starts with a dash is an option, and a string that passes through a shell is a command." },
  code: { title: "Runs text as code", ask: "Where does the text come from? A value from a request, a stored record, a tool definition or a model's answer must never reach it." },
  deserialize: { title: "Rebuilds objects from data", ask: "Who can write the data that is loaded here? These loaders run code or build any type the data names." },
  sql: { title: "SQL text built from parts", ask: "Is every part that is not fixed text a bound parameter or taken from an allow-list? Column and table names count too." },
  html: { title: "Writes HTML without escaping", ask: "Can the value hold text a user, a file or another site supplied? Sanitised or generated HTML is fine; anything else is cross-site scripting." },
};

// A first argument that is fixed text: a plain string with nothing interpolated, or a list of such.
const STR = String.raw`[rRbBuUfF]{0,2}(?:"(?:[^"\\\n$#{}%]|\\.)*"|'(?:[^'\\\n$#{}%]|\\.)*'|\x60(?:[^\x60\\\n$]|\\.)*\x60)`;
const FIXED = String.raw`(?:${STR}|\[\s*(?:${STR}\s*,?\s*)*\])\s*[,)]`;
// A program started with a list of arguments: fixed only when the program and every argument are.
const ONE = String.raw`(?:${STR}|\[\s*(?:${STR}\s*,?\s*)*\])`;
const ALL_FIXED = String.raw`${ONE}(?:\s*,\s*${ONE})*\s*(?:,\s*\{[^{}]*\}\s*)?\)`;
const argv = names => new RegExp(String.raw`(?:${names})\s*\(\s*(?!${ALL_FIXED})(?!\s*\))`);
const call = (names, { empty = false } = {}) => new RegExp(String.raw`(?:${names})\s*\(\s*(?!${FIXED})${empty ? "" : String.raw`(?!\s*\))`}`);

const JS = /\.(?:c|m)?[jt]sx?$|\.vue$|\.svelte$/i, PY = /\.pyw?$/i, PHP = /\.(?:php|phtml)$/i, RB = /\.(?:rb|rake)$/i, GO = /\.go$/i, JVM = /\.(?:java|kt|scala|groovy)$/i, CS = /\.cs$/i, RS = /\.rs$/i;
const bare = String.raw`(?<![\w.$])`, phpFn = String.raw`(?<![\w>:$\\])`;

const SINKS = [
  // ---- runs a program
  { id: "sink-command-py", kind: "command", files: PY, re: call(String.raw`${bare}(?:os\.system|os\.popen|os\.exec[lv]p?e?|os\.spawn[lv]p?e?|subprocess\.(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)|asyncio\.create_subprocess_(?:shell|exec)|pexpect\.(?:spawn|run)|Popen)`) },
  { id: "sink-command-js", kind: "command", files: JS, requires: /child_process|\bexeca\b|shelljs/, re: call(String.raw`(?:${bare}|(?<=child_process\.)|(?<=\bcp\.)|(?<=childProcess\.))(?:exec|execSync)|\bshell\.exec`) },
  { id: "sink-command-js-2", kind: "command", files: JS, requires: /child_process|\bexeca\b/, re: argv(String.raw`(?:${bare}|(?<=child_process\.)|(?<=\bcp\.)|(?<=childProcess\.))(?:spawn|spawnSync|execFile|execFileSync|fork)|${bare}execa(?:\.\w+)?`) },
  { id: "sink-command-php", kind: "command", files: PHP, re: call(String.raw`${phpFn}(?:exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec)`) },
  { id: "sink-command-php-2", kind: "command", files: PHP, re: /\x60[^\x60\n]*\$[\w{]/ },
  { id: "sink-command-go", kind: "command", files: GO, re: argv(String.raw`exec\.Command`) },
  { id: "sink-command-go-2", kind: "command", files: GO, re: new RegExp(String.raw`exec\.CommandContext\s*\(\s*[\w.()]+\s*,\s*(?!${FIXED})`) },
  { id: "sink-command-jvm", kind: "command", files: JVM, re: call(String.raw`Runtime\.getRuntime\(\)\.exec|\bProcessBuilder`) },
  { id: "sink-command-rb", kind: "command", files: RB, re: call(String.raw`(?<![\w.:])(?:system|exec|spawn)|\bIO\.popen|\bOpen3\.(?:capture[23]e?|popen[23]e?|pipeline\w*)|\bKernel\.(?:system|exec|spawn)`) },
  { id: "sink-command-rb-2", kind: "command", files: RB, re: /(?:\x60|%x[({\[])[^\x60\n]*#\{/ },
  { id: "sink-command-cs", kind: "command", files: CS, re: call(String.raw`\bProcess\.Start|new\s+ProcessStartInfo`) },
  { id: "sink-command-rs", kind: "command", files: RS, re: call(String.raw`\bCommand::new`) },
  { id: "sink-command-rs-2", kind: "command", files: RS, requires: /Command::new/, re: call(String.raw`\.args?`) },
  // ---- runs text as code
  { id: "sink-code-py", kind: "code", files: PY, re: call(String.raw`${bare}(?:eval|exec|__import__)|\bimportlib\.import_module|${bare}render_template_string|\.from_string`) },
  { id: "sink-code-js", kind: "code", files: JS, re: call(String.raw`${bare}eval|new\s+Function|\bvm\.(?:runInNewContext|runInThisContext|runInContext|compileFunction)|new\s+vm\.Script`) },
  { id: "sink-code-php", kind: "code", files: PHP, re: call(String.raw`${phpFn}(?:eval|create_function|call_user_func(?:_array)?)`) },
  { id: "sink-code-php-2", kind: "code", files: PHP, re: /^\s*(?:include|require)(?:_once)?\s*\(?\s*(?![\s("']|__DIR__\s*\.\s*["']|dirname\(__FILE__\)\s*\.\s*["'])/ },
  { id: "sink-code-rb", kind: "code", files: RB, re: call(String.raw`(?<![\w.:])eval|\.(?:instance_eval|class_eval|module_eval)|\bERB\.new`) },
  { id: "sink-code-rb-2", kind: "code", files: RB, re: /\.constantize\b/ },
  { id: "sink-code-jvm", kind: "code", files: JVM, re: call(String.raw`\.parseExpression|\bClass\.forName|new\s+GroovyShell\(\)\.evaluate|\.getEngineByName\([^)]*\)\.eval`) },
  // ---- rebuilds objects from data
  { id: "sink-deserialize-py", kind: "deserialize", files: PY, unless: /Loader\s*=\s*(?:yaml\.)?C?SafeLoader|weights_only\s*=\s*True|allow_pickle\s*=\s*False/, re: call(String.raw`${bare}(?:pickle|cPickle|_pickle|dill|cloudpickle)\.(?:loads?|Unpickler)|\bjoblib\.load|\btorch\.load|\bmarshal\.loads?|\bshelve\.open|\bjsonpickle\.decode|\byaml\.(?:load|unsafe_load|full_load|load_all)|\b(?:numpy|np)\.load|\b(?:pandas|pd)\.read_pickle`) },
  { id: "sink-deserialize-py-2", kind: "deserialize", files: PY, re: /\.recv_pyobj\s*\(/ },
  { id: "sink-deserialize-php", kind: "deserialize", files: PHP, re: call(String.raw`${phpFn}unserialize`) },
  { id: "sink-deserialize-jvm", kind: "deserialize", files: JVM, re: /new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|new\s+XMLDecoder\s*\(|new\s+XStream\s*\(|\.enableDefaultTyping\s*\(|\.activateDefaultTyping\s*\(|new\s+Yaml\s*\(\s*\)/ },
  { id: "sink-deserialize-rb", kind: "deserialize", files: RB, re: call(String.raw`\bMarshal\.load|\bYAML\.(?:load|unsafe_load)|\bOj\.load`) },
  { id: "sink-deserialize-js", kind: "deserialize", files: JS, re: call(String.raw`${bare}unserialize|\bv8\.deserialize|\bserialize\.unserialize`) },
  { id: "sink-deserialize-cs", kind: "deserialize", files: CS, re: /new\s+(?:BinaryFormatter|NetDataContractSerializer|LosFormatter|SoapFormatter)\s*\(|TypeNameHandling\.(?:All|Auto|Objects|Arrays)/ },
];

const COMMENT = /^\s*(?:\/\/|#(?!\{)|\*|\/\*|<!--|--\s)/;

/** Dangerous calls with an argument that is not fixed text, as { kind, file, line, call }. */
export function scanSinks(file, text, places) {
  const rel = file.rel;
  if (TEST.test(rel) || DOC.test(rel) || VENDORED.test(rel) || LOCALE.test(rel) || DEVTOOL.test(rel) || TOOLCHAIN.test(rel)) return;
  const rules = SINKS.filter(r => !DROPPED.has(r.id) && r.files.test(rel) && (!r.requires || r.requires.test(text)));
  if (!rules.length) return;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 2000 || COMMENT.test(line)) continue;
    for (const r of rules) {
      const m = r.re.exec(line);
      if (!m || (r.unless && r.unless.test(line))) continue;
      places.push({ kind: r.kind, file: rel, line: i + 1, call: line.trim().slice(0, 120), sink: r.id });
      break;
    }
  }
}

// Rules that match a dangerous call without seeing where its value comes from report places too.
// Which ones is measured, not chosen: bench/calibrate-web.mjs writes data/web-places.json from
// how often each rule pointed at a real bug and how often it fires on applications that are fine.
export const kindOfRule = id => /^xss-|^postmessage/.test(id) ? "html" : /^sql-/.test(id) ? "sql" : /^cmd-/.test(id) ? "command" : /^code-eval/.test(id) ? "code" : /^deserialize/.test(id) ? "deserialize" : null;
