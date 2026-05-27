// =============================================================================
// SMS sink — a DEV "SMS catcher" (the SMS analog of the Mailpit mail catcher).
//
// Kratos has no built-in SMS provider: it delivers SMS by POSTing to an HTTP
// gateway (courier.channels[sms].request_config). Without a real provider
// (Twilio etc.) there is nothing to send to, so this tiny service stands in as
// the gateway: it accepts Kratos's SMS POSTs, captures them in memory, logs each
// to stdout, and serves a simple web UI + JSON API so the operator can READ the
// codes (the dev equivalent of opening Mailpit). It is NOT a real SMS provider —
// production points Kratos at a real gateway via the console SMS page.
//
// Zero dependencies: Node's built-in http only (runs on the node:alpine image
// with the file mounted — no image build needed).
// =============================================================================

const http = require("http")

const PORT = Number(process.env.PORT || 8080)
const MAX = 200
/** @type {Array<{at:string, to:string, body:string, raw:string}>} */
const messages = []

function record(raw) {
  let to = ""
  let body = ""
  try {
    const j = JSON.parse(raw)
    // Be liberal in what we accept — Kratos's template decides the shape. Try
    // the common field names so the captured row is readable regardless.
    to = j.to || j.recipient || j.To || j.phone || j.number || ""
    body = j.body || j.message || j.Body || j.text || raw
  } catch {
    body = raw
  }
  const entry = { at: new Date().toISOString(), to: String(to), body: String(body), raw }
  messages.unshift(entry)
  if (messages.length > MAX) messages.length = MAX
  // Stdout so `docker compose logs sms-sink` shows every captured SMS.
  console.log(`[sms-sink] to=${entry.to || "?"} body=${JSON.stringify(entry.body)}`)
}

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]))
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && (req.url === "/healthz" || req.url === "/readyz")) {
    res.writeHead(200, { "Content-Type": "text/plain" })
    return res.end("ok")
  }
  if (req.method === "GET" && req.url.startsWith("/api/messages")) {
    res.writeHead(200, { "Content-Type": "application/json" })
    return res.end(JSON.stringify({ count: messages.length, messages }))
  }
  if (req.method === "GET" && req.url === "/") {
    const rows = messages
      .map(
        (m) =>
          `<tr><td>${esc(m.at)}</td><td>${esc(m.to)}</td><td><pre>${esc(m.body)}</pre></td></tr>`,
      )
      .join("")
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" })
    return res.end(
      `<!doctype html><html><head><meta charset="utf-8"><title>SMS Sink</title>
<meta http-equiv="refresh" content="5">
<style>body{font-family:system-ui,sans-serif;margin:2rem}h1{font-size:1.2rem}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.5rem;text-align:left;vertical-align:top}
pre{margin:0;white-space:pre-wrap}</style></head>
<body><h1>SMS Sink — captured messages (${messages.length})</h1>
<p>Dev SMS catcher. Auto-refreshes every 5s.</p>
<table><thead><tr><th>Time</th><th>To</th><th>Message</th></tr></thead><tbody>${rows || '<tr><td colspan="3">No messages yet.</td></tr>'}</tbody></table>
</body></html>`,
    )
  }
  // Any other method/path: treat as an inbound SMS-send request and capture it.
  const chunks = []
  req.on("data", (c) => chunks.push(c))
  req.on("end", () => {
    const raw = Buffer.concat(chunks).toString("utf8")
    record(raw)
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify({ status: "ok" }))
  })
})

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[sms-sink] listening on :${PORT}`)
})
