// The small part of the S3 API the reader needs from featherd: path-style
// object PUT, GET, HEAD and DELETE with conditional headers, CreateBucket
// and ListObjectsV2. Requests are signed with SigV4 when a key pair is set,
// and sent unsigned otherwise, for FEATHERD_AUTH=none.

import { createHash, createHmac } from "node:crypto";

export class S3Error extends Error {
  constructor(method, key, status, code) {
    super(`${method} ${key}: HTTP ${status} ${code}`.trim());
    this.status = status;
    this.code = code;
  }
}

export class S3 {
  constructor({ endpoint, bucket, accessKeyId = "", secretAccessKey = "", region = "us-east-1", now = () => new Date() }) {
    this.endpoint = new URL(endpoint);
    this.bucket = bucket;
    this.accessKeyId = accessKeyId;
    this.secretAccessKey = secretAccessKey;
    this.region = region;
    this.now = now;
  }

  // request sends one request and reads the whole response: featherd's
  // objects are small.
  async request(method, key, { query = {}, body, headers = {} } = {}) {
    let path = "/" + awsEscape(this.bucket, false);
    if (key) path += "/" + awsEscape(key, true);
    const rawQuery = canonicalQuery(query);
    // The URL is sent as written, so its path and query are exactly the
    // ones signed.
    const target = `${this.endpoint.protocol}//${this.endpoint.host}${path}${rawQuery ? "?" + rawQuery : ""}`;
    const payload = body ?? Buffer.alloc(0);
    const h = { ...headers };
    if (this.accessKeyId) this.#sign(h, method, path, rawQuery, payload);
    const res = await fetch(target, {
      method,
      headers: h,
      body: method === "GET" || method === "HEAD" ? undefined : payload,
      signal: AbortSignal.timeout(30_000),
    });
    return { status: res.status, etag: res.headers.get("etag") ?? "", body: Buffer.from(await res.arrayBuffer()) };
  }

  async get(key) {
    const res = await this.request("GET", key);
    return expect("GET", key, res, 200, 404);
  }

  async head(key) {
    return this.request("HEAD", key);
  }

  // put stores body at key with one condition, such as If-None-Match: *
  // or If-Match: "<etag>", or none, and returns 200 or 412.
  async put(key, contentType, body, condition, value) {
    const headers = { "Content-Type": contentType };
    if (condition) headers[condition] = value;
    const res = await this.request("PUT", key, { body: Buffer.from(body), headers });
    return expect("PUT", key, res, 200, 412);
  }

  async delete(key, headers = {}) {
    const res = await this.request("DELETE", key, { headers });
    return expect("DELETE", key, res, 200, 204, 412);
  }

  async createBucket() {
    const res = await this.request("PUT", "");
    // 409 BucketAlreadyOwnedByYou: it already exists.
    expect("PUT", "/" + this.bucket, res, 200, 409);
  }

  // list returns the keys under prefix in ascending order, at most limit
  // of them, or all of them for limit 0.
  async list(prefix, limit = 0) {
    const keys = [];
    let token = "";
    for (;;) {
      const query = { "list-type": "2", prefix };
      if (limit > 0) query["max-keys"] = String(Math.min(limit - keys.length, 1000));
      if (token) query["continuation-token"] = token;
      const res = expect("LIST", prefix, await this.request("GET", "", { query }), 200);
      // featherd's ListBucketResult is a fixed shape, so a pattern reads it.
      const xml = res.body.toString();
      for (const [, key] of xml.matchAll(/<Key>([^<]*)<\/Key>/g)) keys.push(unescapeXML(key));
      const truncated = /<IsTruncated>true<\/IsTruncated>/.test(xml);
      if (!truncated || (limit > 0 && keys.length >= limit)) return keys;
      token = unescapeXML(xml.match(/<NextContinuationToken>([^<]*)</)?.[1] ?? "");
      if (!token) return keys;
    }
  }

  // #sign adds a SigV4 Authorization header covering the host, the
  // payload digest and the date, as featherd checks it.
  // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
  #sign(headers, method, path, rawQuery, body) {
    const amzDate = this.now().toISOString().replace(/[-:]/g, "").replace(/\.\d+/, "");
    const day = amzDate.slice(0, 8);
    const payload = sha256Hex(body);
    headers["X-Amz-Date"] = amzDate;
    headers["X-Amz-Content-Sha256"] = payload;
    const signed = "host;x-amz-content-sha256;x-amz-date";
    const canonical = [
      method, path, rawQuery,
      "host:" + this.endpoint.host,
      "x-amz-content-sha256:" + payload,
      "x-amz-date:" + amzDate,
      "", signed, payload,
    ].join("\n");
    const scope = `${day}/${this.region}/s3/aws4_request`;
    const toSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${sha256Hex(canonical)}`;
    let key = Buffer.from("AWS4" + this.secretAccessKey);
    for (const part of [day, this.region, "s3", "aws4_request"]) key = hmac(key, part);
    headers["Authorization"] =
      `AWS4-HMAC-SHA256 Credential=${this.accessKeyId}/${scope}, SignedHeaders=${signed}, Signature=${hmac(key, toSign).toString("hex")}`;
  }
}

// expect returns the response if its status is one of ok, and throws an
// S3Error with S3's error code otherwise.
function expect(method, key, res, ...ok) {
  if (ok.includes(res.status)) return res;
  const code = res.body.toString().match(/<Code>([^<]*)<\/Code>/)?.[1] ?? "";
  throw new S3Error(method, key, res.status, code);
}

export function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}

function hmac(key, data) {
  return createHmac("sha256", key).update(data).digest();
}

// awsEscape percent-encodes s as SigV4 does: everything but A-Z, a-z, 0-9
// and -._~, plus / when keepSlash is set, as in object keys.
export function awsEscape(s, keepSlash) {
  let out = "";
  for (const b of Buffer.from(s)) {
    const c = String.fromCharCode(b);
    if (/[A-Za-z0-9\-._~]/.test(c) || (keepSlash && c === "/")) out += c;
    else out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

// canonicalQuery is the query string sorted and encoded as SigV4 requires.
// The request sends the same string, so the two can't differ.
export function canonicalQuery(query) {
  return Object.entries(query)
    .map(([k, v]) => awsEscape(k, false) + "=" + awsEscape(v, false))
    .sort()
    .join("&");
}

function unescapeXML(s) {
  return s.replace(/&(lt|gt|amp|quot|apos|#\d+|#x[0-9a-fA-F]+);/g, (_, e) => {
    switch (e) {
      case "lt": return "<";
      case "gt": return ">";
      case "amp": return "&";
      case "quot": return '"';
      case "apos": return "'";
    }
    return String.fromCodePoint(e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
  });
}
