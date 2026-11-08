import { api, USE_MOCK } from './api.js';

// Status values are matched loosely until the backend team confirms the contract.
export const isDone = (s) => ['completed', 'complete', 'done', 'finished'].includes(String(s).toLowerCase());
export const isFailed = (s) => ['failed', 'error'].includes(String(s).toLowerCase());

// ---- MOCK (temporary, labelled; enable with VITE_USE_MOCK=true) ----
const mockStarts = new Map();
const mock = {
  start: async () => {
    await new Promise((r) => setTimeout(r, 400));
    const scan_id = 'MOCK-' + Date.now();
    mockStarts.set(scan_id, Date.now());
    return { scan_id, status: 'processing', _mock: true };
  },
  get: async (id) => {
    await new Promise((r) => setTimeout(r, 300));
    const done = Date.now() - (mockStarts.get(id) || 0) > 5000;
    return { scan_id: id, status: done ? 'completed' : 'processing', _mock: true,
             ...(done && { note: 'Mock response. No real analysis was performed.' }) };
  },
};

// ---- REAL API ----
export async function startScan(url) {
  if (USE_MOCK) return mock.start(url);
  const { data } = await api.post('/api/scan', { url });   // -> { scan_id, status }
  return data;
}

export async function getScan(scanId) {
  if (USE_MOCK) return mock.get(scanId);
  const { data } = await api.get(`/api/scan/${encodeURIComponent(scanId)}`);
  return data;
}

// Recent investigations: the agreed contract has no list endpoint, so this
// only remembers scans started from this browser. Swap for the API when one exists.
const KEY = 'weblyze.recent';
export const getRecent = () => { try { return JSON.parse(localStorage.getItem(KEY)) || []; } catch { return []; } };
export function rememberScan(entry) {
  try { localStorage.setItem(KEY, JSON.stringify([entry, ...getRecent()].slice(0, 5))); } catch { /* storage unavailable */ }
}

export function validateUrl(raw) {
  const value = raw.trim();
  if (!value) return { error: 'Enter a website address to investigate.' };
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : 'https://' + value;
  try {
    const u = new URL(withScheme);
    if (!['http:', 'https:'].includes(u.protocol)) return { error: 'Only http:// and https:// addresses can be scanned.' };
    if (!u.hostname.includes('.')) return { error: 'That doesn’t look like a full domain, for example example.com.' };
    return { url: u.href };
  } catch {
    return { error: 'That address isn’t valid. Try something like https://example.com.' };
  }
}
