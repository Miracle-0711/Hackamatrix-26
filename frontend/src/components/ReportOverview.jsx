import { riskLabel } from '../services/reportAdapter.js';

const R = 52, C = 2 * Math.PI * R;

export default function ReportOverview({ report, demo }) {
  const { score, level, url, scannedAt, summary } = report;
  return (
    <section className="overview" aria-label="Report overview">
      <div className="gaugebox">
        <svg viewBox="0 0 120 120" className="gauge" role="img" aria-label={score === null ? 'Risk score not provided' : `Risk score ${score} out of 100`}>
          <circle cx="60" cy="60" r={R} className="track" />
          {score !== null && (
            <circle cx="60" cy="60" r={R} className="arc" data-level={(level || '').toLowerCase()}
              strokeDasharray={`${(C * score) / 100} ${C}`} transform="rotate(-90 60 60)" />
          )}
          <text x="60" y="64" textAnchor="middle" className="num">{score ?? '–'}</text>
          <text x="60" y="82" textAnchor="middle" className="of">out of 100</text>
        </svg>
        <span className="badge big" data-level={(level || '').toLowerCase()}>{level ? riskLabel(level) : 'Risk not classified'}</span>
      </div>
      <div className="facts">
        {demo && <span className="demotag">DEMO DATA</span>}
        <p className="label">Scanned website</p>
        <p className="mono url">{url || 'Not provided'}</p>
        <p className="label">Scanned on</p>
        <p>{scannedAt ? new Date(scannedAt).toLocaleString() : 'Not provided'}</p>
        <p className="label">Threat summary</p>
        <p className="summary">{summary || 'No summary was provided for this scan.'}</p>
      </div>
    </section>
  );
}
