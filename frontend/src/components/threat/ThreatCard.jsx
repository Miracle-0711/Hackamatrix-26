import StatusDot from '../intel/StatusDot.jsx';
import { SEVERITY_LABEL, SEV_STATUS, hostOf } from '../../services/threatAdapter.js';
import { fmtDate } from '../../services/intelAdapter.js';

export default function ThreatCard({ threat: t, onDetails, onDispute }) {
  return (
    <article className="tf-card" data-sev={t.severity || 'none'}>
      <div className="tf-top">
        <span className="tf-host">{hostOf(t.url)}</span>
        <span className={'chip ' + (t.verified ? 'ver' : 'rep')}>{t.verified ? '✓ Verified' : 'Reported'}</span>
      </div>
      <div className="tf-meta">
        <StatusDot status={t.severity ? SEV_STATUS[t.severity] : 'unknown'} label={t.severity ? `${SEVERITY_LABEL[t.severity]}${t.score !== null ? ` · ${t.score}` : ''}` : 'Not rated'} />
        <span className="chip">{t.categoryLabel}</span>
        {t.source === 'demo' && <span className="demotag">DEMO DATA</span>}
        {t.source === 'local' && <span className="demotag">LOCAL, NOT SHARED</span>}
      </div>
      <p className="tf-desc">{t.description}</p>
      <p className="dim tf-date">Reported {fmtDate(t.reportedAt)}</p>
      <div className="tf-actions">
        <button className="ghost" onClick={() => onDetails(t)}>View Details</button>
        {t.verified && (t.disputed
          ? <button className="ghost" disabled>Dispute submitted</button>
          : <button className="ghost" onClick={() => onDispute(t)}>Dispute Report</button>)}
      </div>
    </article>
  );
}
