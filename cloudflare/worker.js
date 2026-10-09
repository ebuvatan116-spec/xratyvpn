const REPOSITORY = "https://raw.githubusercontent.com/ebuvatan116-spec/xratyvpn/main/";
const ASSETS = {
  "/": ["public/index.html", "text/html; charset=utf-8"],
  "/index.html": ["public/index.html", "text/html; charset=utf-8"],
  "/styles.css": ["public/styles.css", "text/css; charset=utf-8"],
  "/app.js": ["public/app.js", "text/javascript; charset=utf-8"]
};

addEventListener("fetch", (event) => event.respondWith(handle(event.request)));

async function handle(request) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
  }
  const url = new URL(request.url);
  if (url.pathname === "/favicon.ico") return new Response(null, { status: 204 });
  const asset = ASSETS[url.pathname];
  if (!asset) return new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } });

  let upstream;
  try {
    upstream = await fetch(REPOSITORY + asset[0], { cf: { cacheTtl: 60, cacheEverything: true } });
  } catch {
    return new Response("Asset source temporarily unavailable", { status: 502 });
  }
  if (!upstream.ok) return new Response("Asset source unavailable", { status: 502 });

  const headers = new Headers({
    "Content-Type": asset[1],
    "Cache-Control": asset[1].startsWith("text/html") ? "no-store" : "public, max-age=60",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  });
  if (asset[1].startsWith("text/html")) {
    headers.set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  }
  return new Response(request.method === "HEAD" ? null : upstream.body, { status: 200, headers });
}
