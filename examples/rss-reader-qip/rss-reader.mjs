#!/usr/bin/env node
// rss-reader polls the feeds listed in a featherd bucket's
// config/subscriptions.opml, stores each post once under const/, keeps each
// feed's state under mut/, and writes the newest posts to view/index.html.
// It talks to featherd only over its S3 API, so featherd enforces every
// conditional write. It's the Node and QIP version of ../rss-reader.

import { parseArgs } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";
import { S3 } from "./s3.mjs";
import { Reader, loadComponents } from "./reader.mjs";

const usage = `usage: rss-reader.mjs [--once] [--interval 15m] [--view 25] [--parallel 4]

Environment:
  FEATHERD               featherd's URL (default http://127.0.0.1:8333)
  BUCKET                 the bucket (default rss)
  AWS_ACCESS_KEY_ID      with AWS_SECRET_ACCESS_KEY, sign requests with SigV4
  AWS_SECRET_ACCESS_KEY  for FEATHERD_AUTH=sigv4; unset for FEATHERD_AUTH=none
`;

function log(msg) {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  const stamp = `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  console.error(`rss-reader: ${stamp} ${msg}`);
}

// duration parses Go-style durations such as 15m, 1h30m or 90s, in ms.
function duration(s) {
  const units = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 };
  const parts = [...s.matchAll(/(\d+(?:\.\d+)?)(ms|s|m|h)/g)];
  if (parts.length === 0 || parts.map((m) => m[0]).join("") !== s) return NaN;
  return parts.reduce((ms, [, n, unit]) => ms + Number(n) * units[unit], 0);
}

async function main() {
  let values;
  try {
    ({ values } = parseArgs({
      options: {
        once: { type: "boolean", default: false },
        interval: { type: "string", default: "15m" },
        view: { type: "string", default: "25" },
        parallel: { type: "string", default: "4" },
        help: { type: "boolean", short: "h", default: false },
      },
    }));
  } catch (err) {
    process.stderr.write(`${err.message}\n${usage}`);
    return 2;
  }
  const interval = duration(values.interval);
  const viewSize = Number(values.view);
  const parallel = Number(values.parallel);
  if (values.help || !(interval > 0) || !(Number.isInteger(viewSize) && viewSize >= 1) || !(Number.isInteger(parallel) && parallel >= 1)) {
    process.stderr.write(usage);
    return 2;
  }

  const env = process.env;
  const endpoint = env.FEATHERD || "http://127.0.0.1:8333";
  if (!/^https?:\/\/[^/]+/.test(endpoint)) throw new Error(`FEATHERD=${JSON.stringify(endpoint)} is not an http(s) URL`);
  const accessKeyId = env.AWS_ACCESS_KEY_ID ?? "";
  const secretAccessKey = env.AWS_SECRET_ACCESS_KEY ?? "";
  if (!accessKeyId !== !secretAccessKey) throw new Error("set both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or neither");

  const reader = new Reader({
    s3: new S3({
      endpoint, bucket: env.BUCKET || "rss", accessKeyId, secretAccessKey,
      region: env.AWS_REGION || "us-east-1", // featherd has no regions and accepts any
    }),
    components: await loadComponents(),
    log, viewSize, parallel,
  });

  const stop = new AbortController();
  for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => stop.abort());
  for (;;) {
    try {
      const r = await reader.poll();
      log(`polled ${r.feeds} feeds: ${r.fetched} fetched, ${r.notModified} not modified, ${r.failed} failed, ${r.skipped} waiting; ${r.added} new posts, ${r.retired} feeds retired`);
    } catch (err) {
      if (values.once || stop.signal.aborted) throw err;
      log(`poll: ${err.message}`);
    }
    if (values.once) return 0;
    try {
      await sleep(interval, undefined, { signal: stop.signal });
    } catch {
      return 0;
    }
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error("rss-reader:", err.message);
    process.exit(1);
  },
);
