
import { api, USE_MOCK } from './api.js';

export const isDone = (status) =>
  ['completed', 'complete', 'done', 'finished'].includes(
    String(status).toLowerCase()
  );

export const isFailed = (status) =>
  ['failed', 'error'].includes(String(status).toLowerCase());

// ---- MOCK MODE ----

const mockScans = new Map();

const mock = {
  start: async () => {
    await new Promise((resolve) => setTimeout(resolve, 400));

    const scan_id = `MOCK-${Date.now()}`;

    const result = {
      scan_id,
      status: 'completed',
      _mock: true,
      report: {
        status: 'ANALYZED',
        risk_assessment: {
          risk_score: 15,
          classification: 'LOW',
        },
        message: 'Mock response. No real analysis was performed.',
      },
    };

    mockScans.set(scan_id, result);
    return result;
  },

  get: async (id) => {
    await new Promise((resolve) => setTimeout(resolve, 300));

    return mockScans.get(id) || {
      scan_id: id,
      status: 'error',
      message: 'Mock scan not found.',
      _mock: true,
    };
  },
};

// ---- REAL API ----

const realScans = new Map();

export async function startScan(url) {
  if (USE_MOCK) {
    return mock.start(url);
  }

  const { data } = await api.post('/api/v1/investigate', {
    url,
  });

  const scan_id =
    data.scan_id ||
    `SCAN-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  // Keep frontend status separate from backend report status.
  const result = {
    scan_id,
    status: 'completed',
    report: data,
    _mock: false,
  };

  realScans.set(scan_id, result);

  return result;
}

export async function getScan(scanId) {
  if (USE_MOCK) {
    return mock.get(scanId);
  }

  const result = realScans.get(scanId);

  if (!result) {
    throw new Error(
      'Scan result is not available. Please start a new scan.'
    );
  }

  return result;
}

// ---- WATCH SCAN ----

export function watchScan(
  id,
  { onUpdate, onDone, onFailed, onError }
) {
  let stopped = false;

  const run = async () => {
    try {
      const result = await getScan(id);

      if (stopped) return;

      onUpdate?.(result);

      if (isFailed(result.status)) {
        onFailed?.(result);
      } else if (isDone(result.status)) {
        onDone?.(result);
      }
    } catch (error) {
      if (!stopped) {
        onError?.(error);
      }
    }
  };

  run();

  return () => {
    stopped = true;
  };
}

// ---- REPORT ADAPTER ----

export { extractRisk } from './reportAdapter.js';

// ---- SCAN HISTORY ----

const KEY = 'weblyze.history';

export const getHistory = () => {
  try {
    return JSON.parse(localStorage.getItem(KEY)) || [];
  } catch {
    return [];
  }
};

const save = (list) => {
  try {
    localStorage.setItem(
      KEY,
      JSON.stringify(list.slice(0, 50))
    );
  } catch {
    // Browser storage unavailable.
  }
};

export const addScan = (entry) =>
  save([entry, ...getHistory()]);

export const updateScan = (id, patch) =>
  save(
    getHistory().map((scan) =>
      scan.scan_id === id
        ? { ...scan, ...patch }
        : scan
    )
  );

export const clearHistory = () => save([]);

// ---- URL VALIDATION ----

export function validateUrl(raw) {
  const value = raw.trim();

  if (!value) {
    return {
      error: 'Enter a website address to investigate.',
    };
  }

  const withScheme =
    /^[a-z][a-z0-9+.-]*:\/\//i.test(value)
      ? value
      : `https://${value}`;

  try {
    const url = new URL(withScheme);

    if (!['http:', 'https:'].includes(url.protocol)) {
      return {
        error: 'Only HTTP and HTTPS addresses can be scanned.',
      };
    }

    if (
      !url.hostname.includes('.') ||
      url.username ||
      url.password
    ) {
      return {
        error: 'Enter a valid public website address.',
      };
    }

    return {
      url: url.href,
    };
  } catch {
    return {
      error: 'That address is not valid. Try https://example.com.',
    };
  }
}
