import { classify } from '../services/reportAdapter.js';

function host(url) { try { return new URL(url).hostname; } catch { return url; } }

export default function RecentInvestigations({ entries, onView, busyId, error }) {
  if (entries.length === 0) {
    return <p className="empty">No investigations yet. Websites you scan will appear here.</p>;
  }
  return (
    <>
      {error && <p className="error" role="alert">{error}</p>}
      <ul className="rows">
        {entries.map((s) => { const level = classify(s.score, s.level); return (
          <li key={s.scan_id}>
            <div className="site">
              <strong>{host(s.url)}</strong>
              <span className="dim">{new Date(s.at).toLocaleString()}</span>
              {s.demo && <span className="demotag">DEMO DATA</span>}
            </div>
            <span className="badge" data-level={(level || '').toLowerCase()}>
              {level || (s.status === 'completed' ? 'Not provided' : s.status || 'Pending')}
            </span>
            <span className="score" title="Risk score">{s.score ?? '–'}</span>
            <button className="ghost" onClick={() => onView(s)} disabled={busyId === s.scan_id}>
              {busyId === s.scan_id ? 'Opening…' : 'View Report'}
            </button>
          </li>
        ); })}
      </ul>
    </>
  );
}
