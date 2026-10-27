// The reader: everything that touches the network, featherd or the clock.
// Parsing OPML and feeds, the feed statechart and rendering the page are
// QIP components, which see only the bytes passed to them.

import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { load } from "./qip.mjs";
import { sha256Hex } from "./s3.mjs";

// The bucket's prefixes, each with its own write rule:
//
//   config/  your input, edited by hand; the reader only reads it
//   mut/     per-feed state: created with If-None-Match: *, then replaced
//            and deleted only with If-Match
//   const/   write-once: created with If-None-Match: *, never replaced or
//            deleted
//   view/    projections, rebuilt from const/ by the one reader
export const subscriptionsKey = "config/subscriptions.opml";
export const feedsPrefix = "mut/feeds/";
export const seenPrefix = "const/seen/";
export const itemsPrefix = "const/items/";
export const indexKey = "view/index.html";

// loadComponents loads the four components built by `make`.
export async function loadComponents(dir = new URL("./build/", import.meta.url)) {
  const path = (name) => fileURLToPath(new URL(`${name}.wasm`, dir));
  try {
    return {
      opml: await load(path("opml-to-uri-list"), { name: "opml-to-uri-list", modes: ["malformed XML"] }),
      feed: await load(path("feed-to-entries"), {
        name: "feed-to-entries",
        modes: ["malformed WARC record", "malformed XML", "neither RSS nor Atom", "unsupported charset",
          "too large", "no post has a GUID, an ID or a link", "a post contains the multipart boundary"],
      }),
      state: await load(path("feed-state"), { name: "feed-state", modes: ["unknown event"] }),
      view: await load(path("atom-to-html"), { name: "atom-to-html", modes: ["malformed XML", "not an Atom feed", "too large"] }),
    };
  } catch (err) {
    if (err.code === "ENOENT") throw new Error(`${err.path} is missing; run make first`);
    throw err;
  }
}

// feedKey names a feed's state object: its host, to make listings
// readable, and a digest of the whole URL.
export function feedKey(url) {
  let host = "feed";
  try {
    host = new URL(url).hostname || host;
  } catch {}
  return feedsPrefix + host + "-" + sha256Hex(url).slice(0, 16);
}

// decodeState reads the fields of a stored state the host acts on: the
// validators for the next fetch, and whether the feed is due. Transitions
// are the feed-state component's job.
export function decodeState(text) {
  const s = {};
  for (const line of text.split("\n")) {
    const eq = line.indexOf("=");
    if (eq > 0) s[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return s;
}

const unix = (date) => BigInt(Math.floor(date.getTime() / 1000));

export class Reader {
  constructor({ s3, components, now = () => new Date(), log = () => {}, viewSize = 25, parallel = 4 }) {
    Object.assign(this, { s3, components, now, log, viewSize, parallel });
  }

  // poll runs one pass: every subscribed feed that's due is fetched and
  // its new posts stored, feeds no longer subscribed are retired, and the
  // view is rebuilt if anything was added or it doesn't exist yet.
  async poll() {
    const res = { feeds: 0, fetched: 0, notModified: 0, failed: 0, skipped: 0, retired: 0, added: 0 };
    await this.s3.createBucket();
    const config = await this.s3.get(subscriptionsKey);
    if (config.status === 404) {
      throw new Error(`no ${subscriptionsKey} in bucket ${this.s3.bucket}; upload an OPML file there first`);
    }
    let urls;
    try {
      urls = this.components.opml.render(config.body).body.toString().split("\r\n").filter(Boolean);
    } catch (err) {
      throw new Error(`${subscriptionsKey}: ${err.message}`);
    }
    res.feeds = urls.length;

    let next = 0;
    const worker = async () => {
      while (next < urls.length) {
        const { outcome, added } = await this.pollFeed(urls[next++], config.etag);
        res.added += added;
        res[{ fetched: "fetched", "not-modified": "notModified", failed: "failed" }[outcome] ?? "skipped"]++;
      }
    };
    await Promise.all(Array.from({ length: Math.min(this.parallel, urls.length) }, worker));

    try {
      res.retired = await this.retire(urls);
    } catch (err) {
      this.log(`retiring feeds: ${err.message}`);
    }

    let rebuild = res.added > 0;
    if (!rebuild) rebuild = (await this.s3.head(indexKey)).status === 404;
    if (rebuild) {
      try {
        await this.rebuildView();
      } catch (err) {
        throw new Error(`rebuilding ${indexKey}: ${err.message}`);
      }
    }
    return res;
  }

  // pollFeed takes one feed through the statechart and returns what
  // happened and how many posts it added. The state object is the commit
  // point: it moves to the origin's new ETag only after every post from
  // that fetch is stored, so a failure partway leaves the old ETag and the
  // next poll fetches the same content again.
  async pollFeed(url, configETag) {
    const key = feedKey(url);
    let stored;
    try {
      stored = await this.s3.get(key);
    } catch (err) {
      this.log(`${url}: reading state: ${err.message}`);
      return { outcome: "failed", added: 0 };
    }
    // New: no state object yet, so the first write creates it.
    let stateText = "", condition = "If-None-Match", value = "*";
    if (stored.status === 200) {
      stateText = stored.body.toString();
      condition = "If-Match";
      value = stored.etag;
    }
    const st = decodeState(stateText);

    const now = this.now();
    if (st.state === "failed" && now < new Date(st.retry_at)) return { outcome: "skipped", added: 0 };
    if (st.state === "dead") {
      if (st.config === configETag) return { outcome: "skipped", added: 0 };
      this.log(`${url}: ${subscriptionsKey} changed, so retrying this dead feed once`);
    }

    let outcome, added, event;
    try {
      ({ outcome, added, event } = await this.fetchFeed(url, st, now));
    } catch (err) {
      this.log(`${url}: ${err.message}`);
      outcome = "failed";
      added = err.added ?? 0;
      event = { event: "failed", url, error: err.message, config: configETag };
    }

    const input = (stateText && !stateText.endsWith("\n") ? stateText + "\n" : stateText) + "\n" + eventLines(event);
    const next = this.components.state.render(input, { now_unix_seconds: unix(now) }).body;
    if (next.length === 0) return { outcome, added }; // 304 while Idle: nothing to write

    try {
      const put = await this.s3.put(key, "text/plain; charset=utf-8", next, condition, value);
      if (put.status === 412) {
        // Another poller saved this feed's state first. Its posts are
        // stored either way; the next poll starts from its state.
        this.log(`${url}: state changed during this poll; leaving the other poller's`);
      } else if (decodeState(next.toString()).state === "dead") {
        this.log(`${url}: dead after failing since ${decodeState(next.toString()).first_failed_at}; edit ${subscriptionsKey} to retry it`);
      }
    } catch (err) {
      this.log(`${url}: saving state: ${err.message}`);
    }
    return { outcome, added };
  }

  // fetchFeed makes a conditional GET of the feed, converts it with the
  // feed-to-entries component and stores its posts. It returns the event
  // for the feed-state component.
  async fetchFeed(url, st, now) {
    const headers = {
      "User-Agent": "featherd-rss-reader-qip/0.1",
      Accept: "application/atom+xml, application/rss+xml, application/xml;q=0.9, */*;q=0.1",
    };
    if (st.etag) headers["If-None-Match"] = st.etag;
    if (st.last_modified) headers["If-Modified-Since"] = st.last_modified;
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) });
    if (res.status === 304) {
      await res.body?.cancel();
      return { outcome: "not-modified", added: 0, event: { event: "not_modified", url } };
    }
    if (res.status !== 200) {
      await res.body?.cancel();
      throw new Error(`HTTP ${res.status}`);
    }

    // Leave room in the component's input for the WARC and HTTP headers.
    const body = await readAtMost(res, this.components.feed.inputCap - 64 * 1024);
    const { body: parts, contentType } = this.components.feed.render(warcRecord(url, res, body, now), { now_unix_seconds: unix(now) });
    const entries = parseMultipart(parts, contentType);

    let added = 0;
    for (const { name, body } of entries) {
      try {
        if (await this.storeEntry(name, body)) added++;
      } catch (err) {
        // The state keeps the old ETag, so these posts are fetched and
        // offered again next time.
        err.added = added;
        throw err;
      }
    }
    return {
      outcome: "fetched",
      added,
      event: { event: "fetched", url, etag: res.headers.get("etag") ?? "", last_modified: res.headers.get("last-modified") ?? "" },
    };
  }

  // storeEntry writes a post to const/ once, and reports whether this call
  // added it. name is "{invTS}/{hash}", as feed-to-entries names the part.
  //
  // The item's key holds its date, so the log lists newest first, but a
  // feed can re-date a post. So the first store also writes
  // const/seen/{hash}, holding the date part of the key, and every later
  // fetch of the post reuses it: the post keeps one key for good. The seen
  // object is written first; if the reader stops before the item is
  // written, the next fetch finds the seen object, writes the missing item
  // at that key, and gets 412 for every item that's already there.
  async storeEntry(name, body) {
    let [ts, hash] = name.split("/");
    const seenKey = seenPrefix + hash;
    let put = await this.s3.put(seenKey, "text/plain; charset=utf-8", ts, "If-None-Match", "*");
    if (put.status === 412) {
      const got = await this.s3.get(seenKey);
      if (got.status !== 200) throw new Error(`${seenKey} vanished`);
      ts = got.body.toString().trim();
    }
    put = await this.s3.put(`${itemsPrefix}${ts}/${hash}`, "application/atom+xml; type=entry", body, "If-None-Match", "*");
    return put.status === 200;
  }

  // retire deletes the state of every feed no longer in the
  // subscriptions, with If-Match, so a state saved since it was read isn't
  // lost. Its posts stay in const/ for good.
  async retire(urls) {
    const keep = new Set(urls.map(feedKey));
    const errors = [];
    let n = 0;
    for (const key of await this.s3.list(feedsPrefix)) {
      if (keep.has(key)) continue;
      try {
        const head = await this.s3.head(key);
        if (head.status !== 200) continue;
        const del = await this.s3.delete(key, { "If-Match": head.etag });
        if (del.status !== 412) {
          this.log(`retired ${key}`);
          n++;
        }
      } catch (err) {
        errors.push(err);
      }
    }
    if (errors.length > 0) throw new AggregateError(errors, errors.map((e) => e.message).join("; "));
    return n;
  }

  // rebuildView renders the newest posts in const/items/ to
  // view/index.html. The keys list newest first, so it's one LIST and a
  // GET per post, in parallel, wrapped as one Atom feed for the
  // atom-to-html component. The view is a projection: it can always be
  // rebuilt from const/, so it's written with a plain PUT by the one
  // reader.
  async rebuildView() {
    const keys = await this.s3.list(itemsPrefix, this.viewSize);
    const entries = await Promise.all(keys.map(async (key) => {
      const res = await this.s3.get(key);
      if (res.status !== 200) throw new Error(`${key} vanished`);
      // Posts stored by the Go reader start with an XML declaration.
      return res.body.toString().replace(/^\s*<\?xml[^>]*\?>\s*/, "");
    }));
    const feed = `<feed xmlns="http://www.w3.org/2005/Atom">\n${entries.join("\n")}\n</feed>\n`;
    const page = this.components.view.render(feed, { now_unix_seconds: unix(this.now()) }).body;
    await this.s3.put(indexKey, "text/html; charset=utf-8", page);
  }
}

// eventLines encodes an event for feed-state. A value can't hold a line
// break, which would start another field.
function eventLines(event) {
  return Object.entries(event)
    .map(([k, v]) => `${k}=${String(v).replace(/\s+/g, " ").trim()}\n`)
    .join("");
}

// warcRecord wraps an origin's response as one WARC response record, the
// input feed-to-entries takes: the feed's URL, the HTTP headers that
// matter, and the body. https://iipc.github.io/warc-specifications/
export function warcRecord(url, res, body, now) {
  let http = `HTTP/1.1 ${res.status} ${res.statusText || "OK"}\r\n`;
  for (const name of ["content-type", "etag", "last-modified"]) {
    const v = res.headers.get(name);
    if (v) http += `${name}: ${v.replace(/[\r\n]+/g, " ")}\r\n`;
  }
  const block = Buffer.concat([Buffer.from(http + "\r\n"), body]);
  const header =
    "WARC/1.1\r\n" +
    "WARC-Type: response\r\n" +
    `WARC-Record-ID: <urn:uuid:${randomUUID()}>\r\n` +
    `WARC-Date: ${now.toISOString().replace(/\.\d+Z$/, "Z")}\r\n` +
    `WARC-Target-URI: ${url}\r\n` +
    "Content-Type: application/http;msgtype=response\r\n" +
    `Content-Length: ${block.length}\r\n\r\n`;
  return Buffer.concat([Buffer.from(header), block, Buffer.from("\r\n\r\n")]);
}

// parseMultipart splits feed-to-entries' output into its parts. The
// component is trusted, but its part names become object keys, so they're
// checked anyway.
export function parseMultipart(body, contentType) {
  const boundary = "--" + contentType.slice(contentType.indexOf("boundary=") + "boundary=".length);
  const text = body.toString();
  const parts = [];
  let at = text.indexOf(boundary + "\r\n");
  while (at >= 0) {
    const headersStart = at + boundary.length + 2;
    const headersEnd = text.indexOf("\r\n\r\n", headersStart);
    const next = text.indexOf("\r\n" + boundary, headersEnd);
    if (headersEnd < 0 || next < 0) throw new Error("feed-to-entries: malformed multipart output");
    const name = text.slice(headersStart, headersEnd).match(/name="([^"]*)"/)?.[1] ?? "";
    if (!/^\d{10}\/[0-9a-f]{32}$/.test(name)) throw new Error(`feed-to-entries: bad part name ${JSON.stringify(name)}`);
    parts.push({ name, body: text.slice(headersEnd + 4, next) });
    at = text.startsWith(boundary + "\r\n", next + 2) ? next + 2 : -1;
  }
  return parts;
}

// readAtMost reads a response body, failing if it's larger than limit.
async function readAtMost(res, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of res.body) {
    size += chunk.length;
    if (size > limit) {
      await res.body.cancel?.().catch(() => {});
      throw new Error(`feed larger than ${limit} bytes`);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c)));
}
