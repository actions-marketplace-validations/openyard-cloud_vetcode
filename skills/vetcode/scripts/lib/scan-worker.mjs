// One scan thread (scan-pool.mjs): scans the files it is sent and returns what scanOne found.
import { parentPort, workerData } from "node:worker_threads";
import { scanOne } from "./perfile.mjs";
import { options } from "./engine.mjs";

options.inline = workerData.inline;
parentPort.on("message", ({ from, files }) => {
  options.suppressed = new Set();
  const results = files.map(f => scanOne(f, workerData.root));
  parentPort.postMessage({ from, results, suppressed: [...options.suppressed] });
});
