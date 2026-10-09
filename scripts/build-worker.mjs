import { readFile, mkdir, writeFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const htmlPath = new URL('public/index.html', root);
let html = await readFile(htmlPath, 'utf8');
const css = await readFile(new URL('public/styles.css', root), 'utf8');
const js = await readFile(new URL('public/app.js', root), 'utf8');
html = html
  .replace('<link rel="stylesheet" href="/styles.css" />', `<style>\n${css}\n</style>`)
  .replace('<script defer src="/app.js"></script>', `<script>\n${js}\n</script>`);
const output = `const HTML = ${JSON.stringify(html)};\n\naddEventListener("fetch", event => {\n  const request = event.request;\n  const url = new URL(request.url);\n  if (request.method !== "GET" && request.method !== "HEAD") {\n    event.respondWith(new Response("Method Not Allowed", { status: 405, headers: { "Allow": "GET, HEAD" } }));\n    return;\n  }\n  if (url.pathname !== "/" && url.pathname !== "/index.html") {\n    event.respondWith(new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } }));\n    return;\n  }\n  const headers = {\n    "Content-Type": "text/html; charset=utf-8",\n    "Cache-Control": "no-store",\n    "X-Content-Type-Options": "nosniff",\n    "Referrer-Policy": "no-referrer",\n    "X-Frame-Options": "DENY",\n    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",\n    "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"\n  };\n  event.respondWith(new Response(request.method === "HEAD" ? null : HTML, { status: 200, headers }));\n});\n`;
await mkdir(new URL('../dist/', import.meta.url), { recursive: true });
await writeFile(new URL('../dist/worker.js', import.meta.url), output);
console.log(`Built dist/worker.js (${Buffer.byteLength(output)} bytes)`);
