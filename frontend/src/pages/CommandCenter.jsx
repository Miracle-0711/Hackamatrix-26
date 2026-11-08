import { useEffect, useRef, useState } from 'react';
import URLScanner from '../components/URLScanner.jsx';
import ScanStatus from '../components/ScanStatus.jsx';
import RecentInvestigations from '../components/RecentInvestigations.jsx';
import { useOpenReport } from '../hooks/useOpenReport.js';
import { DEMO_RAW } from '../data/demoReport.js';
import { USE_MOCK, errorMessage } from '../services/api.js';
import { startScan, watchScan, extractRisk, getHistory, addScan, updateScan } from '../services/scanService.js';

const CAPABILITIES = ['Threat Analysis', 'Certificate Validation', 'Redirect Analysis', 'Security Assessment'];

export default function CommandCenter({ onReport, onNavigate }) {
  const [phase, setPhase] = useState('idle');          // idle | starting | processing | error
  const [target, setTarget] = useState('');
  const [message, setMessage] = useState('');
  const [history, setHistory] = useState(getHistory);
  const stop = useRef();
  const opener = useOpenReport(onReport);
  useEffect(() => () => stop.current?.(), []);

  const refresh = () => setHistory(getHistory());
  const fail = (e) => { setMessage(errorMessage(e)); setPhase('error'); };

  async function run(url) {
    setTarget(url); setPhase('starting');
    try {
      const { scan_id } = await startScan(url);
      setPhase('processing');
      addScan({ scan_id, url, at: Date.now(), status: 'processing' }); refresh();
      stop.current = watchScan(scan_id, {
        onDone: (res) => {
          // Demo scans carry the sample score, flagged as demo so history never passes it off as real.
          const risk = res._mock ? { ...extractRisk(DEMO_RAW), demo: true } : extractRisk(res);
          updateScan(scan_id, { status: 'completed', ...risk }); refresh(); onReport({ url, result: res });
        },
        onFailed: () => { updateScan(scan_id, { status: 'failed' }); refresh(); setMessage('The scan didn’t complete. Please try again.'); setPhase('error'); },
        onError: fail,
      });
    } catch (e) { fail(e); }
  }

  const busy = phase === 'starting' || phase === 'processing';
  return (
    <main>
      {USE_MOCK && <div className="mock">Demo mode: scans return sample data, not real security results.</div>}
      {phase === 'idle' ? (
        <section className="hero">
          <h1>Know Before You Trust.</h1>
          <p>Investigate websites, identify suspicious activity and understand digital risks before you trust a link.</p>
          <URLScanner onSubmit={run} disabled={busy} />
          <button className="link" onClick={() => onReport({ url: DEMO_RAW.url, result: DEMO_RAW })}>
            Explore a sample report (demo data)
          </button>
        </section>
      ) : (
        <ScanStatus url={target} state={phase} message={message} onRetry={() => setPhase('idle')} />
      )}

      <ul className="caps" aria-label="Security capabilities">
        {CAPABILITIES.map((c) => <li key={c}>{c}</li>)}
      </ul>

      <section>
        <h2>Recent investigations</h2>
        <RecentInvestigations entries={history.slice(0, 5)} onView={opener.open} busyId={opener.busyId} error={opener.error} />
        {history.length > 5 && <button className="link" onClick={() => onNavigate('history')}>View all {history.length} investigations</button>}
      </section>
    </main>
  );
}
