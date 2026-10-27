// The tests build featherd from the repository root and run it with SigV4
// on, so the reader's signing and conditional writes are checked against
// what featherd actually enforces. The reader doesn't use featherd's code.
// Run `make test`, which builds the components first.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import { S3, awsEscape, canonicalQuery, sha256Hex } from "./s3.mjs";
import { Reader, loadComponents, feedKey, decodeState, warcRecord, parseMultipart, subscriptionsKey, itemsPrefix, indexKey } from "./reader.mjs";
import { Rejection } from "./qip.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const testKeyID = "rss-reader";
const testSecret = "0123456789abcdef0123456789abcdef";
let dir, featherdBin, components;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "rss-reader-qip-test-"));
  featherdBin = join(dir, "featherd");
  execFileSync("go", ["build", "-o", featherdBin, "."], { cwd: join(here, "..", ".."), stdio: "inherit" });
  components = await loadComponents();
});

after(() => rmSync(dir, { recursive: true, force: true }));

async function freePort() {
  const srv = createServer();
  await new Promise((resolve) => srv.listen(0, "127.0.0.1", resolve));
  const { port } = srv.address();
  await new Promise((resolve) => srv.close(resolve));
  return port;
}

// startFeatherd runs featherd on a free port and returns its URL.
async function startFeatherd(t) {
  const addr = `127.0.0.1:${await freePort()}`;
  const data = mkdtempSync(join(dir, "data-"));
  const proc = spawn(featherdBin, ["--addr", addr, "--dir", data], {
    env: { ...process.env, FEATHERD_AUTH: "sigv4", FEATHERD_ACCESS_KEY_ID: testKeyID, FEATHERD_SECRET_ACCESS_KEY: testSecret },
    stdio: ["ignore", "ignore", "inherit"],
  });
  t.after(() => proc.kill());
  for (let i = 0; i < 100; i++) {
    try {
      await fetch(`http://${addr}/`);
      return `http://${addr}`;
    } catch {
      await sleep(50);
    }
  }
  throw new Error("featherd didn't start");
}

// startOrigins serves fake feeds whose bodies the test changes, with
// ETags, as the real sites do.
async function startOrigins(t) {
  const origins = { feeds: new Map(), broken: new Set() };
  const srv = createServer((req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    if (origins.broken.has(path)) return res.writeHead(502).end("down");
    const body = origins.feeds.get(path);
    if (body === undefined) return res.writeHead(404).end();
    const etag = `"${sha256Hex(body).slice(0, 8)}"`;
    if (req.headers["if-none-match"] === etag) return res.writeHead(304).end();
    res.writeHead(200, { ETag: etag }).end(body);
  });
  await new Promise((resolve) => srv.listen(0, "127.0.0.1", resolve));
  t.after(() => srv.close());
  origins.base = `http://127.0.0.1:${srv.address().port}`;
  return origins;
}

const rss = (...items) => `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>
<title>MacRumors</title><link>https://www.macrumors.com</link>
<atom:link href="https://feeds.macrumors.com/MacRumors-All" rel="self"/>
${items.join("\n")}</channel></rss>`;

const post = (guid, title, date) => `<item><title>${title}</title><link>https://www.macrumors.com/${guid}</link>
<guid isPermaLink="false">${guid}</guid><pubDate>${date}</pubDate>
<description><![CDATA[<p>About <b>${title}</b>.</p>]]></description></item>`;

const atomFeed = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<title>Daring Fireball</title>
<entry><title>Linked: Something</title><link rel="alternate" href="/linked/2026/10/25/something"/>
<id>tag:daringfireball.net,2026:/linked//6.1</id><published>2026-10-25T20:00:00Z</published>
<updated>2026-10-25T20:00:00Z</updated><content type="html">&lt;p&gt;A link.&lt;/p&gt;</content></entry>
<entry><title type="html">&lt;script&gt;alert(1)&lt;/script&gt; Escaped</title><link href="javascript:alert(1)"/>
<id>tag:daringfireball.net,2026:/2</id><published>2026-10-24T09:00:00Z</published>
<updated>2026-10-24T09:00:00Z</updated><summary>Plain &amp; simple.</summary></entry>
</feed>`;

async function newEnv(t) {
  const origins = await startOrigins(t);
  const endpoint = await startFeatherd(t);
  const env = { origins, now: new Date("2026-10-26T09:00:00Z") };
  const s3 = new S3({ endpoint, bucket: "rss", accessKeyId: testKeyID, secretAccessKey: testSecret });
  env.s3 = s3;
  env.reader = new Reader({
    s3, components, now: () => env.now,
    log: process.env.VERBOSE ? (m) => console.error("rss-reader:", m) : () => {},
  });
  env.subscribe = async (...paths) => {
    const outlines = paths.map((p) => `<outline type="rss" text="${p}" xmlUrl="${origins.base}${p}"/>`).join("");
    await s3.createBucket();
    await s3.put(subscriptionsKey, "text/x-opml",
      `<?xml version="1.0"?><opml version="2.0"><head><title>${Date.now()}-${Math.random()}</title></head><body>${outlines}</body></opml>`);
  };
  env.keys = (prefix) => s3.list(prefix);
  env.get = async (key) => {
    const res = await s3.get(key);
    return { body: res.body.toString(), status: res.status };
  };
  env.state = async (path) => {
    const { body, status } = await env.get(feedKey(origins.base + path));
    assert.equal(status, 200, `no state for ${path}`);
    return decodeState(body);
  };
  env.advance = (ms) => (env.now = new Date(env.now.getTime() + ms));
  return env;
}

const minute = 60_000, hour = 60 * minute, day = 24 * hour;

// The README's walkthrough: a first poll of two feeds, then a refresh
// where MacRumors changed, Daring Fireball didn't and a third feed is down.
test("refresh", async (t) => {
  const env = await newEnv(t);
  const mrItems = [
    post("mr-1", "iPhone 18 rumor", "Sun, 25 Oct 2026 18:00:00 +0000"),
    post("mr-2", "macOS 27.1 beta", "Sun, 25 Oct 2026 12:00:00 GMT"),
    post("mr-3", "Future dated", "Fri, 01 Jan 2027 00:00:00 +0000"),
  ];
  env.origins.feeds.set("/mr", rss(...mrItems));
  env.origins.feeds.set("/df", atomFeed);
  await env.subscribe("/mr", "/df");

  // First poll: every post is new, and each feed goes from New to Idle.
  let res = await env.reader.poll();
  assert.equal(res.fetched, 2);
  assert.equal(res.added, 5);
  assert.equal((await env.keys(itemsPrefix)).length, 5);
  let mr = await env.state("/mr");
  assert.equal(mr.state, "idle");
  assert.ok(mr.etag);
  assert.equal(mr.url, env.origins.base + "/mr");

  let { body: page } = await env.get(indexKey);
  // The future-dated post is capped at the poll's time, so it's first; the
  // rest follow by date across both feeds.
  let last = -1;
  for (const title of ["Future dated", "Linked: Something", "iPhone 18 rumor", "macOS 27.1 beta", "Escaped"]) {
    const i = page.indexOf(title);
    assert.ok(i > last, `${title} out of order in view:\n${page}`);
    last = i;
  }
  assert.ok(page.includes("<p>About iPhone 18 rumor.</p>"), "snippet not plain text");
  assert.ok(!page.includes("<script>") && !page.includes("javascript:"), "view isn't escaped");
  assert.ok(page.includes(env.origins.base + "/linked/2026/10/25/something"), "relative Atom link not resolved");

  // Refresh: MacRumors adds two posts and re-dates an old one, Daring
  // Fireball answers 304 and a third feed is down.
  env.advance(hour);
  env.origins.feeds.set("/mr", rss(
    post("mr-5", "New post two", "Mon, 26 Oct 2026 09:30:00 +0000"),
    post("mr-4", "New post one", "Mon, 26 Oct 2026 09:10:00 +0000"),
    post("mr-1", "iPhone 18 rumor (updated)", "Mon, 26 Oct 2026 09:20:00 +0000"),
    ...mrItems.slice(1),
  ));
  env.origins.broken.add("/down");
  await env.subscribe("/mr", "/df", "/down");
  const dfBefore = await env.state("/df");
  res = await env.reader.poll();
  assert.deepEqual([res.fetched, res.notModified, res.failed, res.added], [1, 1, 1, 2]);
  // The re-dated post keeps the key it was first stored under.
  assert.equal((await env.keys(itemsPrefix)).length, 7);
  assert.deepEqual(await env.state("/df"), dfBefore, "Daring Fireball's state changed on 304");
  let down = await env.state("/down");
  assert.equal(down.state, "failed");
  assert.equal(down.n, "1");
  assert.equal(down.first_failed_at, "2026-10-26T10:00:00Z");
  assert.equal(down.retry_at, "2026-10-26T10:15:00Z");
  assert.match(down.error, /502/);
  ({ body: page } = await env.get(indexKey));
  const two = page.indexOf("New post two"), one = page.indexOf("New post one");
  assert.ok(two >= 0 && one > two, "new posts missing or out of order");

  // Before retry_at the failed feed isn't fetched; after it, it backs off
  // further; a week after it first failed it's Dead.
  env.advance(minute);
  res = await env.reader.poll();
  assert.deepEqual([res.skipped, res.failed], [1, 0]);
  env.advance(15 * minute);
  await env.reader.poll();
  down = await env.state("/down");
  assert.equal(down.n, "2");
  assert.equal(down.retry_at, new Date(env.now.getTime() + 30 * minute).toISOString().replace(".000", ""));
  env.advance(8 * day);
  await env.reader.poll();
  down = await env.state("/down");
  assert.equal(down.state, "dead");
  assert.ok(down.config);
  env.advance(2 * day);
  res = await env.reader.poll();
  assert.equal(res.skipped, 1, "dead feed polled");

  // Editing the config retries it once; it recovers and is Idle again.
  env.origins.broken.delete("/down");
  env.origins.feeds.set("/down", rss(post("d-1", "Back up", "Mon, 02 Nov 2026 00:00:00 +0000")));
  await env.subscribe("/mr", "/df", "/down");
  res = await env.reader.poll();
  assert.deepEqual([res.fetched, res.added], [1, 1]);
  down = await env.state("/down");
  assert.equal(down.state, "idle");
  assert.equal(down.n, undefined);
  assert.equal(down.error, undefined);

  // Unsubscribing deletes the feed's state but keeps its posts.
  const items = (await env.keys(itemsPrefix)).length;
  await env.subscribe("/mr", "/down");
  res = await env.reader.poll();
  assert.equal(res.retired, 1);
  assert.equal((await env.get(feedKey(env.origins.base + "/df"))).status, 404);
  assert.equal((await env.keys(itemsPrefix)).length, items);
});

// A post whose const/seen/ object was written, but not its item, is stored
// at the seen object's key the next time the feed changes.
test("crash between seen and item", async (t) => {
  const env = await newEnv(t);
  env.origins.feeds.set("/mr", rss(post("mr-1", "Lost", "Sun, 25 Oct 2026 18:00:00 +0000")));
  await env.subscribe("/mr");
  await env.reader.poll();
  const keys = await env.keys(itemsPrefix);
  assert.equal(keys.length, 1);
  // featherd doesn't stop this DELETE yet; it stands in for the crash.
  await env.s3.delete(keys[0]);
  // The post comes back re-dated, which mustn't move it.
  env.origins.feeds.set("/mr", rss(post("mr-1", "Lost", "Mon, 26 Oct 2026 08:00:00 +0000")));
  const res = await env.reader.poll();
  assert.equal(res.added, 1);
  assert.deepEqual(await env.keys(itemsPrefix), keys);
});

test("missing subscriptions", async (t) => {
  const env = await newEnv(t);
  await assert.rejects(env.reader.poll(), new RegExp(subscriptionsKey));
});

// The components, without featherd.

function convert(url, body, now = new Date("2026-10-26T00:00:00Z")) {
  const res = { status: 200, statusText: "OK", headers: new Headers() };
  const out = components.feed.render(warcRecord(url, res, Buffer.from(body, "latin1"), now), { now_unix_seconds: BigInt(now / 1000) });
  return parseMultipart(out.body, out.contentType);
}

test("feed formats", () => {
  const rdf = `<?xml version="1.0" encoding="ISO-8859-1"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel><title>Caf\xe9</title></channel>
<item><title>One</title><link>https://example.com/1</link><dc:date>2026-10-20T10:00:00Z</dc:date></item>
<item><title>No ID</title></item>
</rdf:RDF>`;
  const entries = convert("https://example.com/feed", rdf);
  assert.equal(entries.length, 1);
  const [e] = entries;
  assert.match(e.body, /<title>Café<\/title>/);
  assert.match(e.body, /<id>https:\/\/example.com\/1<\/id>/);
  assert.match(e.body, /<published>2026-10-20T10:00:00Z<\/published>/);
  // The key is the one the Go reader uses for the same post.
  const ts = String(9999999999 - Date.parse("2026-10-20T10:00:00Z") / 1000);
  assert.equal(e.name, `${ts}/${sha256Hex("https://example.com/feed\nhttps://example.com/1").slice(0, 32)}`);

  assert.throws(() => convert("https://example.com/", "<html><body>not a feed</body></html>"),
    (err) => err instanceof Rejection && err.mode === "neither RSS nor Atom");
  assert.throws(() => convert("https://example.com/", "<rss><channel><item><title>cut"),
    (err) => err instanceof Rejection && err.mode === "malformed XML");
});

test("multipart boundary is fresh on each render", () => {
  const a = components.feed.render(warcRecord("https://x/f", { status: 200, headers: new Headers() }, Buffer.from(rss(post("a", "A", ""))), new Date()));
  const b = components.feed.render(warcRecord("https://x/f", { status: 200, headers: new Headers() }, Buffer.from(rss(post("a", "A", ""))), new Date()));
  assert.notEqual(a.contentType, b.contentType);
  assert.doesNotMatch(a.contentType, /uuid-00000000/);
  assert.equal(parseMultipart(a.body, a.contentType).length, 1);
});

test("state transitions", () => {
  const nowUnixSeconds = BigInt(Date.parse("2026-10-26T09:00:00Z") / 1000);
  const step = (state, event) => components.state.render(state + "\n" + event, { now_unix_seconds: nowUnixSeconds }).body.toString();
  const idle = 'state=idle\nurl=https://example.com/feed\netag="mr-v1"\nlast_ok=2026-10-25T21:00:00Z\n';

  // A newline in the error would start another field, so the host joins
  // the lines, as the Go reader's encoder does.
  const failed = step(idle, "event=failed\nurl=https://example.com/feed\nerror=timeout after 30s\n");
  assert.equal(failed, [
    "state=failed", "url=https://example.com/feed", 'etag="mr-v1"', "last_ok=2026-10-25T21:00:00Z", "n=1",
    "first_failed_at=2026-10-26T09:00:00Z", "last_failed_at=2026-10-26T09:00:00Z",
    "error=timeout after 30s", "retry_at=2026-10-26T09:15:00Z", "",
  ].join("\n"));
  // A 304 for an Idle feed writes nothing; for a Failed one it's Idle
  // again, with the old validators and the failure cleared.
  assert.equal(step(idle, "event=not_modified\nurl=https://example.com/feed\n"), "");
  assert.equal(step(failed, "event=not_modified\nurl=https://example.com/feed\n"),
    'state=idle\nurl=https://example.com/feed\netag="mr-v1"\nlast_ok=2026-10-26T09:00:00Z\n');
  // A New feed has no state lines.
  assert.equal(step("", 'event=fetched\nurl=https://example.com/feed\netag="v2"\n'),
    'state=idle\nurl=https://example.com/feed\netag="v2"\nlast_ok=2026-10-26T09:00:00Z\n');
  assert.throws(() => step(idle, "event=exploded\n"), Rejection);
});

test("opml", () => {
  const opml = `<opml><body><outline xmlUrl="https://a/?x=1&amp;y=2"/>
<outline text="folder"><outline xmlUrl="https://a/?x=1&amp;y=2"/><outline xmlUrl="ftp://no"/><outline xmlUrl=" http://b/ "/></outline></body></opml>`;
  assert.equal(components.opml.render(opml).body.toString(), "https://a/?x=1&y=2\r\nhttp://b/\r\n");
});

test("SigV4 escaping", () => {
  assert.equal(canonicalQuery({ prefix: "const/items/", "list-type": "2" }), "list-type=2&prefix=const%2Fitems%2F");
  assert.equal(awsEscape("a b/c~", true), "a%20b/c~");
});
