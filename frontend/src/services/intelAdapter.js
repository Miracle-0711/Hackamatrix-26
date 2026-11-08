// The ONLY place that knows the shape of the security-intelligence data.
// ASSUMPTION: field names are placeholders until the backend team confirms the JSON.
// Expected (placeholder) shape, read from result.intelligence:
// { certificate: { status: valid|warning|invalid|expired, issuer, issued_at, expires_at, summary, issues[], details{},
//                  chain: [{ role: root|intermediate|leaf, name, status: pass|warning|fail|missing, issue }] },
//   redirects:   { status, summary, details{},
//                  chain: [{ url, status_code, suspicious, status, reason }] },
//   security:    { status, summary, details{},
//                  headers: [{ name, status, note }],       // e.g. Content-Security-Policy
//                  cookies: [{ name, status, note }] } }    // cookie checks: Secure, HttpOnly, SameSite
// A missing section stays null and the UI shows "no data". Nothing is filled in.

export function level(s) {
  const v = String(s ?? '').toLowerCase();
  if (['pass', 'passed', 'ok', 'valid', 'safe', 'secure', 'good', 'present', 'clean'].includes(v)) return 'pass';
  if (['warn', 'warning', 'suspicious', 'review', 'medium'].includes(v)) return 'warn';
  if (['fail', 'failed', 'invalid', 'insecure', 'missing', 'expired', 'danger', 'high', 'critical'].includes(v)) return 'fail';
  return 'unknown';
}
export const worst = (list) =>
  ['fail', 'warn', 'pass'].find((s) => list.some((x) => x.status === s)) ?? 'unknown';

const text = (v) => (v == null ? null : String(v));
const strings = (a) => (Array.isArray(a) ? a.map((x) => (typeof x === 'string' ? x : x?.message ?? '')).filter(Boolean) : []);
const pairs = (o) => Object.entries(o && typeof o === 'object' ? o : {}).map(([k, v]) => [k.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase()), String(v)]);
const items = (a) => (Array.isArray(a) ? a : []).map((x) => ({ name: text(x?.name) ?? 'Unnamed', status: level(x?.status), note: text(x?.note) }));

export const fmtDate = (iso) => {
  const d = iso ? new Date(iso) : null;
  return d && !isNaN(d) ? d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : 'Not provided';
};

const certLabel = (raw, lvl) =>
  String(raw ?? '').toLowerCase() === 'expired' ? 'Expired' : ({ pass: 'Valid', warn: 'Warning', fail: 'Invalid' }[lvl] ?? 'No data');

// Rough registrable-domain check (handles common two-part endings like co.uk) for spotting domain changes.
const SECOND = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac']);
const hostname = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } };
export function registrable(host = '') {
  const p = host.split('.').filter(Boolean);
  if (p.length <= 2) return p.join('.');
  const n = p[p.length - 1].length === 2 && SECOND.has(p[p.length - 2]) ? 3 : 2;
  return p.slice(-n).join('.');
}

export function normalizeIntel(raw = {}) {
  const { certificate: c, redirects: r, security: s } = raw.intelligence ?? {};
  return {
    certificate: c && {
      status: level(c.status), statusLabel: certLabel(c.status, level(c.status)),
      issuer: text(c.issuer), issuedAt: c.issued_at ?? null, expiresAt: c.expires_at ?? null, summary: text(c.summary),
      chain: (Array.isArray(c.chain) ? c.chain : []).map((n) => ({
        role: text(n?.role), name: text(n?.name) ?? 'Unknown', status: level(n?.status), issue: text(n?.issue),
        missing: String(n?.status ?? '').toLowerCase() === 'missing',
      })),
      issues: strings(c.issues), details: pairs(c.details),
    },
    redirects: r && {
      status: level(r.status), summary: text(r.summary), details: pairs(r.details),
      hops: (Array.isArray(r.chain) ? r.chain : []).map((h, i, all) => {
        const prev = i > 0 ? registrable(hostname(all[i - 1]?.url)) : '';
        const now = registrable(hostname(h?.url));
        return {
          url: text(h?.url) ?? '', code: h?.status_code ?? null, reason: text(h?.reason),
          status: h?.status ? level(h.status) : h?.suspicious ? 'warn' : 'pass',
          domainChange: i > 0 && !!prev && !!now && prev !== now,
        };
      }),
    },
    security: s && {
      status: level(s.status), summary: text(s.summary), details: pairs(s.details),
      headers: items(s.headers), cookies: items(s.cookies),
    },
  };
}
