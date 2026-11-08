// The ONLY place that knows the shape of a threat-feed entry.
// ASSUMPTION: field names are placeholders until the backend team confirms the JSON:
// { id, url, category, risk_score (0-100), verified | status:'verified', reported_at, description }
// Severity is never stored: it is always derived from risk_score with the shared risk bands
// (Low 0-29, Medium 30-59, High Risk 60-79, Critical 80-100) in reportAdapter.js.
import { classify } from './reportAdapter.js';

export const CATEGORIES = { phishing: 'Phishing', malware: 'Malware', malicious_website: 'Malicious Website', brand_impersonation: 'Brand Impersonation' };
export const SEVERITY_LABEL = { low: 'Low', medium: 'Medium', high: 'High Risk', critical: 'Critical' };
export const SEV_STATUS = { low: 'pass', medium: 'warn', high: 'high', critical: 'fail' };
const SEV_KEY = { Low: 'low', Medium: 'medium', 'High Risk': 'high', Critical: 'critical' };
const human = (s) => String(s).replace(/[_-]+/g, ' ').replace(/^./, (c) => c.toUpperCase());

export const hostOf = (u) => { try { return new URL(u).host; } catch { return u; } };

export function normalizeThreat(r = {}) {
  let cat = String(r.category ?? '').toLowerCase().replace(/[\s-]+/g, '_');
  if (cat === 'malicious_websites') cat = 'malicious_website';
  const s = r.risk_score ?? r.score;
  const score = typeof s === 'number' ? Math.max(0, Math.min(100, s)) : null;
  const level = classify(score, r.severity ?? r.risk_level);
  return {
    id: String(r.id ?? r.url),
    url: r.url ?? '',
    category: CATEGORIES[cat] ? cat : null,
    categoryLabel: CATEGORIES[cat] ?? (r.category ? human(r.category) : 'Uncategorised'),
    score,
    severity: SEV_KEY[level] ?? null,                // null = not rated (never guessed)
    verified: r.verified === true || String(r.status ?? '').toLowerCase() === 'verified',
    reportedAt: r.reported_at ?? null,
    description: r.description ?? '',
    source: r._demo ? 'demo' : r._local ? 'local' : 'api',
  };
}
