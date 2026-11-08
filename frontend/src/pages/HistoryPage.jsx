import { useState } from 'react';
import RecentInvestigations from '../components/RecentInvestigations.jsx';
import { useOpenReport } from '../hooks/useOpenReport.js';
import { getHistory, clearHistory } from '../services/scanService.js';

export default function HistoryPage({ onReport }) {
  const [entries, setEntries] = useState(getHistory);
  const opener = useOpenReport(onReport);
  return (
    <main>
      <div className="titlebar">
        <h1 className="small">Scan History</h1>
        {entries.length > 0 && <button className="ghost" onClick={() => { clearHistory(); setEntries([]); }}>Clear history</button>}
      </div>
      <p className="dim">Websites scanned from this browser.</p>
      <RecentInvestigations entries={entries} onView={opener.open} busyId={opener.busyId} error={opener.error} />
    </main>
  );
}
