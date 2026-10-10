// Small self-contained HTML pages (no scripts, no external resources) and JSON replies.

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const SECURITY_HEADERS: Record<string, string> = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  // Keeps tokens in our URLs out of Referer headers to anything the page links to.
  "referrer-policy": "no-referrer",
};

const PAGE_CSP = "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

export function json(status: number, body: Record<string, unknown>, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...SECURITY_HEADERS, "content-type": "application/json; charset=utf-8", ...extra },
  });
}

export type PageTone = "neutral" | "success" | "error" | "cta";

const SPARK = `<svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 0 L14.2 9.8 L24 12 L14.2 14.2 L12 24 L9.8 14.2 L0 12 L9.8 9.8 Z" fill="#FF4A1C"/></svg>`;

/**
 * The waitlist's pages in the site's brand: bone, ink, ember only for the action. Fonts come from
 * the site's own origin (self-hosted, no third party); until the site serves them, the system
 * font stands in. One short spark burst on success, off with reduced motion.
 */
export function page(status: number, title: string, bodyHtml: string, siteUrl: string, tone: PageTone = status < 300 ? "neutral" : "error"): Response {
  const site = escapeHtml(siteUrl);
  // The strike (confirm and success pages): a bolt from the top right hits the card's spark, which
  // ignites and throws sparks; the headline glows, the button gets an ember ring. CSS and inline SVG
  // only (the CSP allows no script); geometry is anchored to the spark, so it holds at any width.
  const strike = tone === "success" || tone === "cta";
  const bolt = `<svg class="bolt" viewBox="0 0 440 300" aria-hidden="true">
<path class="b glow" d="M440 -10 L428 -0 L413 7 L396 9 L389 27 L375 35 L361 43 L354 60 L336 63 L322 69 L306 75 L304 100 L288 104 L279 118 L253 110 L242 122 L241 148 L211 132 L199 142 L191 159 L179 169 L174 190 L163 202 L142 199 L136 219 L121 225 L107 233 L98 246 L78 246 L66 256 L47 257 L39 272 L24 279 L13 291 L0 300" pathLength="1"/>
<path class="b mid" d="M440 -10 L428 -0 L413 7 L396 9 L389 27 L375 35 L361 43 L354 60 L336 63 L322 69 L306 75 L304 100 L288 104 L279 118 L253 110 L242 122 L241 148 L211 132 L199 142 L191 159 L179 169 L174 190 L163 202 L142 199 L136 219 L121 225 L107 233 L98 246 L78 246 L66 256 L47 257 L39 272 L24 279 L13 291 L0 300" pathLength="1"/>
<path class="b core" d="M440 -10 L428 -0 L413 7 L396 9 L389 27 L375 35 L361 43 L354 60 L336 63 L322 69 L306 75 L304 100 L288 104 L279 118 L253 110 L242 122 L241 148 L211 132 L199 142 L191 159 L179 169 L174 190 L163 202 L142 199 L136 219 L121 225 L107 233 L98 246 L78 246 L66 256 L47 257 L39 272 L24 279 L13 291 L0 300" pathLength="1"/>
<path class="br" d="M322 69 L323 81 L325 93 L326 105 L322 118 L325 130 L325 142 L327 154 L329 166 L328 178 L330 190" pathLength="1"/>
<path class="br" d="M241 148 L234 157 L233 170 L225 179 L219 190 L209 197 L203 208 L195 216 L197 232 L187 240 L185 252 L177 261 L168 270 L166 282 L158 291 L150 300" pathLength="1"/>
</svg>`;
  const burst = strike
    ? `<div class="burst" aria-hidden="true">${bolt}${[0, 1, 2, 3, 4, 5, 6].map((i) => `<i style="--a:${i * 51}deg"></i>`).join("")}<span class="core">${SPARK.replace('width="18" height="18"', 'width="34" height="34"')}</span></div>`
    : "";
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><meta name="color-scheme" content="light"><title>${escapeHtml(title)} · Zunder</title>
<style>
@font-face{font-family:"Schibsted Grotesk";src:url("/fonts/schibsted-grotesk-latin.woff2") format("woff2");font-weight:400 700;font-display:swap}
@font-face{font-family:"JetBrains Mono";src:url("/fonts/jetbrains-mono-latin.woff2") format("woff2");font-weight:400 500;font-display:swap}
:root{--bone:#F2F0EB;--paper:#FBFAF7;--ink:#111113;--muted:#55555C;--line:#DCD9D1;--ember:#FF4A1C;--ember-ink:#B32E0A}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bone);color:var(--ink)}
body{font:17px/1.55 "Schibsted Grotesk",-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;min-height:100vh;display:flex;flex-direction:column}
header{max-width:1120px;width:100%;margin:0 auto;padding:28px 24px;display:flex;align-items:center;justify-content:space-between}
.mark{display:inline-flex;align-items:center;gap:8px;color:var(--ink);text-decoration:none;font-weight:700;font-size:22px;letter-spacing:-.04em}
main{flex:1;width:100%;max-width:640px;margin:0 auto;padding:8vh 24px 48px}
.card{background:var(--paper);border:1px solid var(--line);border-radius:28px;padding:44px 40px}
.eyebrow{font:500 12px/1 "JetBrains Mono",ui-monospace,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase;color:${tone === "error" ? "var(--ember-ink)" : "var(--muted)"};display:flex;align-items:center;gap:8px}
.eyebrow::before{content:"";width:8px;height:8px;border-radius:50%;background:${tone === "error" ? "var(--ember-ink)" : "var(--ember)"}}
h1{margin:18px 0 14px;font-size:44px;line-height:1;font-weight:600;letter-spacing:-.04em}
p{margin:0 0 16px;color:#3F3F45}
.muted{color:var(--muted);font-size:14px}
.offer{padding:12px 16px;border:1px solid #FFC9B6;background:#FFF1EB;border-radius:14px;color:var(--ink);font-size:15px}
.offer strong{font:500 11px/1 "JetBrains Mono",ui-monospace,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase;color:var(--ember-ink)}
a{color:var(--ink)}
button{font:700 16px/1 "Schibsted Grotesk",-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;min-height:52px;padding:0 28px;border:0;border-radius:999px;background:var(--ember);color:var(--ink);cursor:pointer;margin-top:8px;transition:transform .18s cubic-bezier(.2,.8,.2,1),box-shadow .18s}
button:hover{transform:translateY(-1px);box-shadow:0 10px 26px -12px rgba(255,74,28,.7)}
button:focus-visible{outline:3px solid var(--ink);outline-offset:3px}
footer{max-width:1120px;width:100%;margin:0 auto;padding:24px;display:flex;flex-wrap:wrap;gap:18px;font:12px/1.4 "JetBrains Mono",ui-monospace,Menlo,monospace;color:var(--muted)}
footer a{color:var(--muted)}
html,body{overflow-x:hidden}
.card{position:relative}
.burst{position:relative;width:64px;height:64px;margin:0 0 6px}
.burst .core{position:absolute;left:15px;top:15px;animation:pop .5s cubic-bezier(.34,1.56,.64,1) .07s both}
.burst i{position:absolute;left:30px;top:30px;width:4px;height:4px;border-radius:50%;background:var(--ember);opacity:0;transform:rotate(var(--a)) translateX(0);animation:fly .7s cubic-bezier(.15,.7,.3,1) .12s both}
.bolt{position:absolute;left:32px;bottom:32px;width:440px;height:300px;overflow:visible;pointer-events:none;z-index:2}
.bolt path{fill:none;stroke-linejoin:round;stroke-linecap:round;stroke-dasharray:1;stroke-dashoffset:1}
.bolt .glow{stroke:var(--ember);stroke-width:12;opacity:.45;filter:blur(6px)}
.bolt .mid{stroke:var(--ember);stroke-width:3.4}
.bolt .core{stroke:#FFF7EE;stroke-width:1.3}
.bolt .b{animation:lead .45s cubic-bezier(.5,0,.1,1) both}
.bolt .br{stroke:#FF6A3D;stroke-width:1.6;animation:branch .32s cubic-bezier(.5,0,.1,1) .05s both}
@keyframes lead{0%{stroke-dashoffset:1;opacity:1}14%{stroke-dashoffset:0}19%{opacity:.25}24%{opacity:1}31%{opacity:.15}37%{opacity:.85}60%,100%{stroke-dashoffset:0;opacity:0}}
@keyframes branch{0%{stroke-dashoffset:1;opacity:1}30%{stroke-dashoffset:0;opacity:.95}45%{opacity:.4}55%{opacity:.85}100%{stroke-dashoffset:0;opacity:0}}
body.strike::after{content:"";position:fixed;inset:0;background:#fff;pointer-events:none;opacity:0;animation:flash .45s ease-out both}
@keyframes flash{0%,12%{opacity:0}15%{opacity:.16}20%{opacity:.04}25%{opacity:.1}34%,100%{opacity:0}}
body.strike h1{animation:hglow .6s ease-out both}
@keyframes hglow{0%,12%{text-shadow:0 0 0 rgba(255,74,28,0)}16%{text-shadow:0 0 26px rgba(255,74,28,.55),0 0 3px rgba(255,180,140,.9)}100%{text-shadow:0 0 0 rgba(255,74,28,0)}}
body.strike button{animation:ring .8s ease-out .22s both}
@keyframes ring{0%{box-shadow:0 0 0 0 rgba(255,74,28,0)}35%{box-shadow:0 0 0 6px rgba(255,74,28,.35),0 10px 30px -8px rgba(255,74,28,.8)}100%{box-shadow:0 0 0 14px rgba(255,74,28,0),0 8px 24px -12px rgba(255,74,28,0)}}
@keyframes pop{0%{transform:scale(0)}100%{transform:scale(1)}}
@keyframes fly{0%{opacity:1;transform:rotate(var(--a)) translateX(4px)}100%{opacity:0;transform:rotate(var(--a)) translateX(34px)}}
@media (prefers-reduced-motion:reduce){.burst .core,.burst i,button,.bolt path,body.strike h1,body.strike button,body.strike::after{animation:none;transition:none}.burst i,.bolt,body.strike::after{display:none}}
@media (max-width:520px){.card{padding:32px 24px;border-radius:22px}h1{font-size:34px}.bolt{width:300px;height:205px}}
</style></head>
<body${strike ? ' class="strike"' : ""}>
<header><a class="mark" href="${site}/" aria-label="Zunder home">${SPARK}<span>zunder</span></a></header>
<main><div class="card">${burst}<div class="eyebrow">${tone === "error" ? "Something is off" : "Zunder waitlist"}</div><h1>${escapeHtml(title)}</h1>${bodyHtml}</div></main>
<footer><span>orcastrate UG (haftungsbeschränkt)</span><a href="${site}/impressum">Legal notice</a><a href="${site}/privacy">Privacy</a><a href="${site}/">zunderlabs.com</a></footer>
</body></html>`;
  return new Response(html, {
    status,
    headers: { ...SECURITY_HEADERS, "content-type": "text/html; charset=utf-8", "content-security-policy": PAGE_CSP },
  });
}

/** A one-button form that POSTs back to the same URL, so mail scanners that open links change nothing. */
export function postButton(action: string, fields: Record<string, string>, label: string): string {
  const inputs = Object.entries(fields)
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join("");
  return `<form method="post" action="${escapeHtml(action)}">${inputs}<button type="submit">${escapeHtml(label)}</button></form>`;
}
