import ReportOverview from '../components/ReportOverview.jsx';
import DiagnosticCard from '../components/DiagnosticCard.jsx';
import Recommendations from '../components/Recommendations.jsx';
import { normalizeReport } from '../services/reportAdapter.js';
import { DEMO_RAW } from '../data/demoReport.js';

// data = { url, result }. Mock-mode scans and "sample report" both show the DEMO DATA investigation.
export default function ReportPage({ data, onBack, onIntelligence }) {
  const raw = data.result || {};
  const demo = !!(raw._demo || raw._mock);
  const report = normalizeReport(demo ? DEMO_RAW : raw, data.url);
  return (
    <main className="report">
      <div className="actions">
        <button className="back" onClick={onBack}>Back to Command Center</button>
        <button className="ghost" onClick={onIntelligence}>View security intelligence</button>
      </div>
      {demo && (
        <div className="demo" role="note">
          <strong>DEMO DATA</strong> This is a predefined sample investigation. It is not a real scan of any website.
        </div>
      )}
      <h1 className="small">Threat Analysis Report</h1>
      <ReportOverview report={report} demo={demo} />
      <h2 className="section">Diagnostics</h2>
      <div className="cards">{report.checks.map((c) => <DiagnosticCard key={c.id} check={c} />)}</div>
      <Recommendations items={report.recommendations} />
      <button className="back" onClick={onBack}>Back to Command Center</button>
    </main>
  );
}
