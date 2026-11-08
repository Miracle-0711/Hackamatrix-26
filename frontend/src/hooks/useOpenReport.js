import { useState } from 'react';
import { errorMessage } from '../services/api.js';
import { getScan, isDone, isFailed } from '../services/scanService.js';

// Opens a past scan's report by asking the backend for it again.
export function useOpenReport(onReport) {
  const [busyId, setBusyId] = useState(null);
  const [error, setError] = useState('');
  async function open(entry) {
    setBusyId(entry.scan_id); setError('');
    try {
      const result = await getScan(entry.scan_id);
      if (isDone(result.status)) onReport({ url: entry.url, result });
      else if (isFailed(result.status)) setError('This scan didn’t complete, so there is no report.');
      else setError('This scan is still running. Try again in a moment.');
    } catch (e) { setError(errorMessage(e)); }
    finally { setBusyId(null); }
  }
  return { open, busyId, error };
}
