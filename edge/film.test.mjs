// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// The site's film function (edge/film.js) against a stand-in asset binding: what a Range asks for,
// what is refused, and If-Range (RFC 9110 section 13.1.5), which must never splice a slice of one
// file onto a cached copy of another. Run: node --test edge/film.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import film from "./film.js";

const BYTES = new Uint8Array(100).map((_, i) => i);
const ETAG = '"film-v2"';
const env = (status = 200) => ({ ASSETS: { fetch: async () => status === 200
  ? new Response(BYTES, { status: 200, headers: { ETag: ETAG, "Content-Type": "video/mp4" } })
  : new Response("missing", { status }) } });
const call = (headers = {}, method = "GET", e = env()) =>
  film.fetch(new Request("https://polaris-id.org/film/sky-1440.0000.mp4", { method, headers }), e);
const bytesOf = async (r) => new Uint8Array(await r.arrayBuffer());

test("1. no Range: the whole file, 200, and it says it takes ranges", async () => {
  const r = await call();
  assert.equal(r.status, 200); assert.equal(r.headers.get("Accept-Ranges"), "bytes");
  assert.deepEqual(await bytesOf(r), BYTES);
});
test("2. bytes=0-1: 206 with the first two bytes", async () => {
  const r = await call({ Range: "bytes=0-1" });
  assert.equal(r.status, 206); assert.equal(r.headers.get("Content-Range"), "bytes 0-1/100");
  assert.equal(r.headers.get("Content-Length"), "2"); assert.deepEqual(await bytesOf(r), BYTES.slice(0, 2));
});
test("3. a suffix, bytes=-5: the last five bytes", async () => {
  const r = await call({ Range: "bytes=-5" });
  assert.equal(r.status, 206); assert.equal(r.headers.get("Content-Range"), "bytes 95-99/100");
  assert.deepEqual(await bytesOf(r), BYTES.slice(95));
});
test("4. open-ended, bytes=90-: to the end", async () => {
  const r = await call({ Range: "bytes=90-" });
  assert.equal(r.status, 206); assert.deepEqual(await bytesOf(r), BYTES.slice(90));
});
test("5. an end past the file is clamped to the last byte", async () => {
  const r = await call({ Range: "bytes=98-500" });
  assert.equal(r.status, 206); assert.equal(r.headers.get("Content-Range"), "bytes 98-99/100");
});
test("6. a start past the file: 416 with the size", async () => {
  const r = await call({ Range: "bytes=100-" });
  assert.equal(r.status, 416); assert.equal(r.headers.get("Content-Range"), "bytes */100");
});
test("7. a range it does not parse (several ranges, other units): the whole file", async () => {
  for (const range of ["bytes=0-1,5-6", "items=0-1", "bytes=a-b"]) {
    const r = await call({ Range: range });
    assert.equal(r.status, 200, range); assert.deepEqual(await bytesOf(r), BYTES);
  }
});
test("8. If-Range equal to the strong ETag: the range is served", async () => {
  const r = await call({ Range: "bytes=0-1", "If-Range": ETAG });
  assert.equal(r.status, 206); assert.deepEqual(await bytesOf(r), BYTES.slice(0, 2));
});
test("9. If-Range with a stale ETag: 200 and the whole file, never a slice", async () => {
  const r = await call({ Range: "bytes=0-1", "If-Range": '"film-v1"' });
  assert.equal(r.status, 200); assert.equal(r.headers.get("Content-Range"), null);
  assert.deepEqual(await bytesOf(r), BYTES);
});
test("10. If-Range as a date or a weak tag: 200 and the whole file", async () => {
  for (const v of ["Tue, 13 Oct 2026 20:34:00 GMT", `W/${ETAG}`]) {
    const r = await call({ Range: "bytes=0-1", "If-Range": v });
    assert.equal(r.status, 200, v); assert.deepEqual(await bytesOf(r), BYTES);
  }
});
test("11. HEAD with a range: the 206 headers and no body", async () => {
  const r = await call({ Range: "bytes=0-1" }, "HEAD");
  assert.equal(r.status, 206); assert.equal(r.headers.get("Content-Range"), "bytes 0-1/100");
  assert.equal((await bytesOf(r)).length, 0);
});
test("12. other methods are refused, and a missing asset passes through", async () => {
  const p = await call({}, "POST"); assert.equal(p.status, 405); assert.equal(p.headers.get("Allow"), "GET, HEAD");
  const m = await call({ Range: "bytes=0-1" }, "GET", env(404)); assert.equal(m.status, 404);
});
