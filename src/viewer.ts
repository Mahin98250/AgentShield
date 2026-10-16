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
      const rows = events.slice().reverse().map(e => `<tr><td>${escapeHtml(e.timestamp)}</td><td class="${escapeHtml(e.decision)}">${escapeHtml(e.decision.toUpperCase())}</td><td>${escapeHtml(e.reason)}</td><td><code>${escapeHtml(e.commandSummary)}</code></td></tr>`).join("");
      const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AgentShield activity</title><style>
      :root{color-scheme:dark;font:14px system-ui;background:#0b1020;color:#e8edf8}body{max-width:1100px;margin:40px auto;padding:0 18px}h1{font-size:28px}p{color:#aab6cc}.panel{border:1px solid #27324a;border-radius:14px;overflow:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px;border-bottom:1px solid #27324a;vertical-align:top}th{color:#aab6cc}code{overflow-wrap:anywhere;white-space:pre-wrap}.allow{color:#7ce0b0}.approve{color:#ffd27d}.block,.error{color:#ff8e9a}.empty{padding:24px;color:#aab6cc}</style>
      <h1>AgentShield activity</h1><p>Local read-only audit view. Commands are redacted; audit files may still contain sensitive metadata.</p><div class="panel"><table><thead><tr><th>Time</th><th>Decision</th><th>Reason</th><th>Command summary</th></tr></thead><tbody>${rows || '<tr><td colspan="4" class="empty">No events recorded yet.</td></tr>'}</tbody></table></div></html>`;
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "cache-control": "no-store" });
      res.end(html);
    } catch {
      res.writeHead(500, { "content-type": "text/plain; charset=utf-8" }); res.end("Unable to read local audit log.");
    }
  });
  server.listen(port, "127.0.0.1", () => console.log(`AgentShield viewer: http://127.0.0.1:${port}`));
}
