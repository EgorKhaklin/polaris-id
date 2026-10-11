// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// The project site is static: Cloudflare serves site/ as committed. This one function runs only for
// /film/* (wrangler.jsonc: run_worker_first), because Safari plays video only from a server that
// answers byte-range requests, and static assets answer every request with the whole file. It
// fetches the asset and returns the slice a Range header asks for, with 206 and Content-Range.
// Everything else on the site never reaches it.

function parseRange(header, size) {
  const m = /^bytes=(\d*)-(\d*)$/.exec((header || "").trim());
  if (!m || (m[1] === "" && m[2] === "")) return null;
  let start, end;
  if (m[1] === "") {                       // a suffix: the last N bytes
    const n = Number(m[2]);
    if (n === 0) return "unsatisfiable";
    start = Math.max(0, size - n); end = size - 1;
  } else {
    start = Number(m[1]);
    end = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
  }
  if (start >= size || start > end) return "unsatisfiable";
  return { start, end };
}

export default {
  async fetch(request, env) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response(null, { status: 405, headers: { Allow: "GET, HEAD" } });
    }
    const asset = await env.ASSETS.fetch(new Request(request.url, { method: "GET" }));
    if (asset.status !== 200) return asset;
    const headers = new Headers(asset.headers);
    headers.set("Accept-Ranges", "bytes");
    headers.set("X-Content-Type-Options", "nosniff");
    const range = request.headers.get("Range");
    if (!range) {
      return new Response(request.method === "HEAD" ? null : asset.body, { status: 200, headers });
    }
    const body = await asset.arrayBuffer();
    const size = body.byteLength;
    const r = parseRange(range, size);
    if (r === null) {
      headers.set("Content-Length", String(size));
      return new Response(request.method === "HEAD" ? null : body, { status: 200, headers });
    }
    if (r === "unsatisfiable") {
      return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${size}`, "Accept-Ranges": "bytes" } });
    }
    headers.set("Content-Range", `bytes ${r.start}-${r.end}/${size}`);
    headers.set("Content-Length", String(r.end - r.start + 1));
    return new Response(request.method === "HEAD" ? null : body.slice(r.start, r.end + 1), { status: 206, headers });
  },
};

export { parseRange };
