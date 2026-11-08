// The ONLY place that knows the shape of a scan result.
// ASSUMPTION: field names below are placeholders until the backend team confirms
// the JSON. When they do, edit this file and nothing else.
//
// Expected (placeholder) shape:
// { url, risk_score, risk_level, completed_at, summary,
//   checks: { threat_detection|domain_intelligence|ssl_tls|brand_impersonation|
//             redirect_analysis|security_assessment: { status, findings[], explanation } },
//   recommendations: [ { risk, action } | "text" ] }

export const CHECKS = [
  { key: 'threat_detection', title: 'Threat Detection' },
  { key: 'domain_intelligence', title: 'Domain Intelligence' },
  { key: 'ssl_tls', title: 'SSL/TLS Certificate Validation' },
  { key: 'brand_impersonation', title: 'Brand Impersonation' },
  { key: 'redirect_analysis', title: 'Redirect Analysis' },
  { key: 'security_assessment', title: 'Website Security Assessment' },
];

export const LEVELS = ['Low', 'Medium', 'High Risk', 'Critical'];
// Single source of truth for risk bands (upper bound exclusive):
// Low 0-29, Medium 30-59, High Risk 60-79, Critical 80-100.
const BANDS = [[30, 'Low'], [60, 'Medium'], [80, 'High Risk'], [101, 'Critical']];
export const levelFromScore = (s) => BANDS.find(([max]) => s < max)[1];
// Labels from a backend are only used when there is no score. 'safe' folds into Low.
const ALIASES = { safe: 'Low', low: 'Low', medium: 'Medium', high: 'High Risk', 'high risk': 'High Risk', critical: 'Critical' };
export const riskLabel = (level) => (level === 'High Risk' ? level : `${level} risk`);

// The score wins: whenever one exists the level comes from the bands above, so every screen agrees.
export function classify(score, given) {
  if (typeof score === 'number') return levelFromScore(Math.max(0, Math.min(100, score)));
  return given ? (ALIASES[String(given).toLowerCase()] ?? String(given)) : null;
}

export function extractRisk(raw = {}) {
  const s = raw.risk_score ?? raw.score;
  const score = typeof s === 'number' ? Math.max(0, Math.min(100, s)) : null;
  return { score, level: classify(score, raw.risk_level ?? raw.classification ?? raw.risk) };
}

function normalizeStatus(s) {
  const v = String(s ?? '').toLowerCase();
  if (['pass', 'passed', 'ok', 'safe', 'clean', 'valid'].includes(v)) return 'pass';
  if (['warn', 'warning', 'suspicious', 'medium', 'review'].includes(v)) return 'warn';
  if (['fail', 'failed', 'danger', 'malicious', 'high', 'critical', 'invalid'].includes(v)) return 'fail';
  return 'unknown';
}

export function normalizeReport(raw = {}, fallbackUrl = '') {
  const { score, level } = extractRisk(raw);
  return {
    url: raw.url ?? fallbackUrl,
    score, level,
    scannedAt: raw.completed_at ?? raw.scanned_at ?? raw.created_at ?? null,
    summary: raw.summary ?? null,
    checks: CHECKS.map(({ key, title }) => {
      const c = raw.checks?.[key];
      return {
        id: key, title, available: !!c,
        status: c ? normalizeStatus(c.status) : 'unknown',
        findings: (Array.isArray(c?.findings) ? c.findings : []).map((f) => (typeof f === 'string' ? f : f?.message ?? f?.title ?? '')).filter(Boolean),
        explanation: c?.explanation ?? null,
      };
    }),
    recommendations: (Array.isArray(raw.recommendations) ? raw.recommendations : [])
      .map((r) => (typeof r === 'string' ? { action: r } : { risk: r?.risk, action: r?.action ?? r?.detail ?? r?.title }))
      .filter((r) => r.risk || r.action),
  };
}
