// Scans files on several threads when there are enough of them to pay for starting the threads.
// Each file is scanned by scanOne (perfile.mjs), which depends on nothing but the file, so the
// results, put back in the files' order, are the ones a single thread gives.
import os from "node:os";
import { Worker } from "node:worker_threads";
import { scanOne } from "./perfile.mjs";
import { options } from "./engine.mjs";

const BATCH = 48;
// Below this many files a scan takes well under a second, less than starting the threads costs.
const MIN_FILES = 400;

export function threadsFor(count) {
  const env = Number(process.env.VETCODE_THREADS);
  const cores = typeof os.availableParallelism === "function" ? os.availableParallelism() : os.cpus().length;
  if (Number.isInteger(env) && env >= 1) return Math.min(env, 16);
  if (count < MIN_FILES) return 1;
  return Math.max(1, Math.min(cores - 1, 8, Math.ceil(count / 800)));
}

/** [{ findings, sinks, partial, yarn }] in the order of `files`; suppressed lines go into options.suppressed. */
export async function scanAll(files, root) {
  const n = threadsFor(files.length);
  if (n > 1) {
    try { return await parallel(files, root, n); }
    catch { /* a thread could not start or failed: scan here instead */ }
  }
  return files.map(f => scanOne(f, root));
}

function parallel(files, root, n) {
  return new Promise((resolve, reject) => {
    const results = new Array(files.length), suppressed = [];
    let next = 0, done = 0, failed = false;
    const workers = [];
    const finish = err => {
      for (const w of workers) w.terminate();
      if (err) { failed = true; reject(err); return; }
      for (const s of suppressed) options.suppressed.add(s);
      resolve(results);
    };
    const feed = w => {
      if (next >= files.length) return;
      const from = next; next = Math.min(files.length, next + BATCH);
      w.postMessage({ from, files: files.slice(from, next).map(({ abs, rel, text, partial }) => ({ abs, rel, text, partial })) });
    };
    for (let i = 0; i < n; i++) {
      const w = new Worker(new URL("./scan-worker.mjs", import.meta.url), { workerData: { root, inline: options.inline } });
      workers.push(w);
      w.on("message", m => {
        if (failed) return;
        m.results.forEach((r, k) => { results[m.from + k] = r; });
        suppressed.push(...m.suppressed);
        done += m.results.length;
        if (done === files.length) finish(); else feed(w);
      });
      w.on("error", e => { if (!failed) finish(e); });
      w.on("exit", code => { if (code !== 0 && !failed && done < files.length) finish(new Error(`scan thread exited with ${code}`)); });
      feed(w);
    }
    if (!files.length) finish();
  });
}
