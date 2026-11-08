import { DEMO_THREATS } from '../data/demoThreats.js';
import { normalizeThreat } from './threatAdapter.js';

// NO threat-feed endpoints have been agreed with the backend team, so none are invented.
// Everything below is local/demo. When the API exists, replace the bodies of
// listThreats, submitReport and submitDispute; the screens won't need to change.
const REPORTS = 'weblyze.threats.local';
const DISPUTES = 'weblyze.threats.disputes';

const read = (k, fallback) => { try { return JSON.parse(localStorage.getItem(k)) ?? fallback; } catch { return fallback; } };
const write = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch { return false; } };

export async function listThreats() {
  const disputes = read(DISPUTES, {});
  return [...read(REPORTS, []), ...DEMO_THREATS]
    .map(normalizeThreat)
    .map((t) => ({ ...t, disputed: !!disputes[t.id] }))
    .sort((a, b) => (Date.parse(b.reportedAt) || 0) - (Date.parse(a.reportedAt) || 0));
}

export async function submitReport({ url, category, description }) {
  const entry = { id: 'local-' + Date.now(), url, category, description, verified: false, reported_at: new Date().toISOString(), _local: true };
  if (!write(REPORTS, [entry, ...read(REPORTS, [])].slice(0, 50))) throw new Error('storage');
  return entry;
}

export async function submitDispute(id, reason) {
  const next = { ...read(DISPUTES, {}), [id]: { reason, at: new Date().toISOString() } };
  if (!write(DISPUTES, next)) throw new Error('storage');
}
