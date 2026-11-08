import { useCallback, useEffect, useState } from 'react';
import FilterBar from '../components/threat/FilterBar.jsx';
import ThreatCard from '../components/threat/ThreatCard.jsx';
import ThreatDetailsModal from '../components/threat/ThreatDetailsModal.jsx';
import ReportThreatModal from '../components/threat/ReportThreatModal.jsx';
import DisputeModal from '../components/threat/DisputeModal.jsx';
import { listThreats } from '../services/threatService.js';

// Edit the rules here to change what each filter means.
const FILTERS = [
  { id: 'all', label: 'All', test: () => true },
  { id: 'phishing', label: 'Phishing', test: (t) => t.category === 'phishing' },
  { id: 'malware', label: 'Malware', test: (t) => t.category === 'malware' },
  { id: 'malicious', label: 'Malicious Websites', test: (t) => t.category === 'malicious_website' },
  { id: 'verified', label: 'Verified Reports', test: (t) => t.verified },
];

export default function ThreatFeedPage() {
  const [threats, setThreats] = useState([]);
  const [status, setStatus] = useState('loading');     // loading | ready | error
  const [filter, setFilter] = useState('all');
  const [modal, setModal] = useState(null);            // { type: 'report' | 'details' | 'dispute', threat? }

  const load = useCallback(async () => {
    try { setThreats(await listThreats()); setStatus('ready'); } catch { setStatus('error'); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const close = () => setModal(null);
  const shown = threats.filter(FILTERS.find((f) => f.id === filter).test);
  const hasDemo = threats.some((t) => t.source === 'demo');

  return (
    <main>
      <div className="titlebar">
        <h1 className="small">Threat Intelligence</h1>
        <button className="primary" onClick={() => setModal({ type: 'report' })}>Report a Website</button>
      </div>
      <p className="dim">Websites reported as unsafe. Verified reports have been confirmed.</p>
      {hasDemo && <div className="demo" role="note"><strong>DEMO DATA</strong> Sample entries are examples, not real reports.</div>}

      <FilterBar filters={FILTERS} value={filter} onChange={setFilter} />

      {status === 'loading' && <p className="empty" role="status">Loading reports…</p>}
      {status === 'error' && (
        <div className="empty" role="alert">We couldn’t load the threat feed. <button className="link" onClick={() => { setStatus('loading'); load(); }}>Try again</button></div>
      )}
      {status === 'ready' && (shown.length === 0
        ? <div className="empty">No threats match this filter. <button className="link" onClick={() => setFilter('all')}>Show all threats</button></div>
        : <div className="tf-grid" aria-live="polite">
            {shown.map((t) => (
              <ThreatCard key={t.id} threat={t} onDetails={(x) => setModal({ type: 'details', threat: x })} onDispute={(x) => setModal({ type: 'dispute', threat: x })} />
            ))}
          </div>)}

      {modal?.type === 'report' && <ReportThreatModal onClose={close} onSubmitted={load} />}
      {modal?.type === 'details' && <ThreatDetailsModal threat={modal.threat} onClose={close} onDispute={(x) => setModal({ type: 'dispute', threat: x })} />}
      {modal?.type === 'dispute' && <DisputeModal threat={modal.threat} onClose={close} onSubmitted={load} />}
    </main>
  );
}
