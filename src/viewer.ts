import { createServer } from "node:http";
import { readAudit } from "./audit.js";

const escapeHtml = (value: unknown) => String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

export async function startViewer(port = 4173): Promise<void> {
  const server = createServer(async (req, res) => {
    if (req.url !== "/" && req.url !== "/api/events") {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" }); res.end("Not found"); return;
    }
    try {
      const events = await readAudit();
      if (req.url === "/api/events") {
        res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
        res.end(JSON.stringify(events)); return;
      }
      const counts = { total: events.length, blocked: events.filter(e => e.decision === "block").length, review: events.filter(e => e.decision === "approve" || e.decision === "error").length, allowed: events.filter(e => e.decision === "allow").length };
      const rows = events.slice().reverse().map(e => `<tr><td>${escapeHtml(e.timestamp)}</td><td class="${escapeHtml(e.decision)}">${escapeHtml(e.decision.toUpperCase())}</td><td>${escapeHtml(e.reason)}</td><td><code>${escapeHtml(e.commandSummary)}</code></td></tr>`).join("");
      const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AgentShield activity</title><style>
      :root{color-scheme:dark;font:14px system-ui;background:#0b1020;color:#e8edf8}body{max-width:1100px;margin:40px auto;padding:0 18px}h1{font-size:28px}p{color:#aab6cc}.panel{border:1px solid #27324a;border-radius:14px;overflow:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px;border-bottom:1px solid #27324a;vertical-align:top}th{color:#aab6cc}code{overflow-wrap:anywhere;white-space:pre-wrap}.allow{color:#7ce0b0}.approve{color:#ffd27d}.block,.error{color:#ff8e9a}.empty{padding:24px;color:#aab6cc}body{min-height:100vh}.topbar{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:0 0 22px;border-bottom:1px solid #243149}.brand{display:flex;align-items:center;gap:12px}.brand svg{width:42px;height:42px}.brand strong{display:block;font-size:17px;letter-spacing:-.3px}.brand span{display:block;font-size:10px;letter-spacing:1.6px;color:#8a9bb5;margin-top:3px}.integration{display:flex;align-items:center;gap:8px;border:1px solid #303a50;border-radius:10px;padding:8px 11px;color:#e8edf8;text-decoration:none}.integration svg{width:24px;height:24px}.integration span{font-size:13px;font-weight:600}.integration small{font-size:11px;color:#9ba9c0;margin-left:5px}.page-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin:30px 0 20px}.eyebrow{color:#df9c7e;font-size:11px;font-weight:700;letter-spacing:1.8px}h1{font-size:30px;letter-spacing:-.8px;margin:7px 0 5px}.page-heading p{margin:0;max-width:600px}.local-tag{display:flex;align-items:center;gap:8px;border:1px solid #293b42;border-radius:999px;padding:8px 12px;font-size:12px;color:#a4e1c3;white-space:nowrap}.local-tag span{width:7px;height:7px;border-radius:50%;background:#78d7a4;display:inline-block}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:20px}.stat{background:#111b2e;border:1px solid #26334b;border-radius:12px;padding:16px}.stat>span{display:block;color:#acb9cd;font-size:12px}.stat strong{display:block;font-size:28px;letter-spacing:-1px;margin:10px 0 5px}.stat small{color:#8291aa;font-size:11px}.stat-block strong{color:#ff9b9b}.stat-review strong{color:#ffd27d}.stat-allow strong{color:#7ce0b0}footer{font-size:11px;color:#7f8da4;margin:18px 0 30px}@media(max-width:700px){body{margin:22px auto}.topbar{align-items:flex-start}.integration{flex-wrap:wrap;max-width:150px}.integration small{display:none}.page-heading{align-items:flex-start;flex-direction:column}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}</style>

      <body>
      <header class="topbar">
        <div class="brand">
          <svg viewBox="0 0 48 48" aria-hidden="true"><path d="M24 3 43 11v13c0 11-7 18-19 23C12 42 5 35 5 24V11Z" fill="#17243a" stroke="#536681" stroke-width="1.5"/><path d="m15 25 6 6 12-13" fill="none" stroke="#e4a17f" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          <div><strong>AgentShield</strong><span>LOCAL ACTIVITY</span></div>
        </div>
        <a class="integration" href="https://code.claude.com/docs/en/hooks" target="_blank" rel="noreferrer">
          <svg viewBox="0 0 32 32" aria-hidden="true"><g fill="none" stroke="#d97757" stroke-width="2.3" stroke-linecap="round"><path d="M16 3v6M16 23v6M3 16h6M23 16h6M7 7l4.5 4.5M20.5 20.5 25 25M25 7l-4.5 4.5M11.5 20.5 7 25"/></g></svg>
          <span>Claude Code</span><small>Hook guide ↗</small>
        </a>
      </header>
      <main>
        <section class="page-heading"><div><span class="eyebrow">ACTIVITY LOG</span><h1>Security activity</h1><p>See which commands were allowed, blocked, or flagged for review.</p></div><span class="local-tag"><span></span>Local only</span></section>
        <section class="stats">
          <article class="stat"><span>Total events</span><strong>${counts.total}</strong><small>Decisions recorded</small></article>
          <article class="stat stat-block"><span>Blocked</span><strong>${counts.blocked}</strong><small>Tool calls denied</small></article>
          <article class="stat stat-review"><span>Needs review</span><strong>${counts.review}</strong><small>Approval or evaluation issue</small></article>
          <article class="stat stat-allow"><span>Allowed</span><strong>${counts.allowed}</strong><small>Matched the low-risk allowlist</small></article>
        </section>
        <div class="panel"><table><thead><tr><th>Time</th><th>Decision</th><th>Reason</th><th>Command summary</th></tr></thead><tbody>${rows || '<tr><td colspan="4" class="empty">No events recorded yet.</td></tr>'}</tbody></table></div></main><footer>AgentShield keeps these events in a local JSONL file. Redaction is best-effort; do not put real secrets in commands.</footer></body></html>`;
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "cache-control": "no-store" });
      res.end(html);
    } catch {
      res.writeHead(500, { "content-type": "text/plain; charset=utf-8" }); res.end("Unable to read local audit log.");
    }
  });
  server.listen(port, "127.0.0.1", () => console.log(`AgentShield viewer: http://127.0.0.1:${port}`));
}
