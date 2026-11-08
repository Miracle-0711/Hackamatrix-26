import { useEffect, useRef, useState } from 'react';
import Header from '../components/Header.jsx';
import URLScanner from '../components/URLScanner.jsx';
import ScanStatus from '../components/ScanStatus.jsx';
import { USE_MOCK, BASE_URL, errorMessage } from '../services/api.js';
import { startScan, getScan, isDone, isFailed, getRecent, rememberScan } from '../services/scanService.js';

const CAPABILITIES = ['Threat Analysis', 'Certificate Validation', 'Redirect Analysis', 'Security Assessment'];
const POLL_MS = 2000;

export default function CommandCenter({ onComplete }) {
  const [phase, setPhase] = useState('idle');          // idle | starting | processing | error
  const [target, setTarget] = useState('');
  const [scanId, setScanId] = useState('');
  const [message, setMessage] = useState('');
  const [connection, setConnection] = useState('unknown');
  const [recent, setRecent] = useState(getRecent);
  const timer = useRef();
  useEffect(() => () => clearTimeout(timer.current), []);

  const fail = (e) => { setConnection(e.response || !e.request ? 'ok' : 'down'); setMessage(errorMessage(e)); setPhase('error'); };

  async function poll(id, url) {
    try {
      const res = await getScan(id);
      setConnection('ok');
      if (isFailed(res.status)) { setMessage(res.message || 'The backend reported that this scan failed.'); return setPhase('error'); }
      if (isDone(res.status)) return onComplete({ url, result: res });
      timer.current = setTimeout(() => poll(id, url), POLL_MS);
    } catch (e) { fail(e); }
  }

  async function run(url) {
    setTarget(url); setScanId(''); setPhase('starting');
    try {
      const { scan_id } = await startScan(url);
      setConnection('ok'); setScanId(scan_id); setPhase('processing');
      rememberScan({ scan_id, url, at: Date.now() }); setRecent(getRecent());
      poll(scan_id, url);
    } catch (e) { fail(e); }
  }

  const busy = phase === 'starting' || phase === 'processing';
  return (
    <div className="center">
      <Header connection={connection} />
      <main>
        {USE_MOCK && <div className="mock">Mock mode: responses are placeholders, not real security results.</div>}
        {phase === 'idle' ? (
          <section className="hero">
            <h1>Know Before You Trust.</h1>
            <p>Investigate any website before you visit it, sign in, or share data. Paste an address and Weblyze will analyse it.</p>
            <URLScanner onSubmit={run} disabled={busy} />
          </section>
        ) : (
          <ScanStatus url={target} scanId={scanId} state={phase} message={message} onRetry={() => setPhase('idle')} />
        )}

        <ul className="caps" aria-label="Security capabilities">
          {CAPABILITIES.map((c) => <li key={c}>{c}</li>)}
        </ul>

        <div className="panels">
          <section>
            <h2>Recent investigations</h2>
            {recent.length === 0 ? <p className="dim">No investigations yet. Scans you run will appear here.</p> : (
              <ul className="recent">{recent.map((r) => (
                <li key={r.scan_id}><span className="mono">{r.url}</span><span className="dim">{r.scan_id}</span></li>
              ))}</ul>
            )}
          </section>
          <section>
            <h2>System</h2>
            <dl>
              <dt>Backend</dt><dd>{USE_MOCK ? 'Mock mode (no backend used)' : BASE_URL || 'VITE_API_BASE_URL not set'}</dd>
              <dt>Connection</dt><dd>{connection === 'unknown' ? 'Not checked yet' : connection === 'ok' ? 'Last request succeeded' : 'Last request failed'}</dd>
              <dt>Scan service</dt><dd>Availability appears here once the backend exposes it</dd>
            </dl>
          </section>
        </div>
      </main>
    </div>
  );
}
