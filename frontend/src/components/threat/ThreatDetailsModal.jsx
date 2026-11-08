import Modal from './Modal.jsx';
import { SEVERITY_LABEL } from '../../services/threatAdapter.js';
import { fmtDate } from '../../services/intelAdapter.js';

const SOURCE = { demo: 'DEMO DATA: a sample entry, not a real report', local: 'Saved in this browser only. Not shared with anyone.' };

export default function ThreatDetailsModal({ threat: t, onClose, onDispute }) {
  return (
    <Modal title="Threat details" onClose={onClose}>
      <dl className="tech">
        <dt>Website</dt><dd className="mono">{t.url}</dd>
        <dt>Category</dt><dd>{t.categoryLabel}</dd>
        <dt>Risk</dt><dd>{t.severity ? `${SEVERITY_LABEL[t.severity]}${t.score !== null ? ` (${t.score} out of 100)` : ''}` : 'Not rated'}</dd>
        <dt>Status</dt><dd>{t.verified ? 'Verified' : 'Reported, not yet verified'}{t.disputed ? ' (dispute submitted)' : ''}</dd>
        <dt>Reported</dt><dd>{fmtDate(t.reportedAt)}</dd>
        <dt>Description</dt><dd>{t.description || 'No description provided.'}</dd>
        {SOURCE[t.source] && <><dt>Source</dt><dd>{SOURCE[t.source]}</dd></>}
      </dl>
      <div className="mactions">
        {t.verified && !t.disputed && <button className="ghost" onClick={() => onDispute(t)}>Dispute Report</button>}
        <button className="primary" onClick={onClose}>Close</button>
      </div>
    </Modal>
  );
}
