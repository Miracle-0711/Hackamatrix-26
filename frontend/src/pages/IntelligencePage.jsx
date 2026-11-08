import CertificateCard from '../components/intel/CertificateCard.jsx';
import RedirectCard from '../components/intel/RedirectCard.jsx';
import WebsiteSecurityCard from '../components/intel/WebsiteSecurityCard.jsx';
import { normalizeIntel } from '../services/intelAdapter.js';
import { extractRisk, riskLabel } from '../services/reportAdapter.js';
import { DEMO_INTEL } from '../data/demoIntelligence.js';
import { DEMO_RAW } from '../data/demoReport.js';

// data = the same { url, result } object the report uses.
export default function IntelligencePage({ data, onBack }) {
  const raw = data.result || {};
  const demo = !!(raw._demo || raw._mock);
  const intel = normalizeIntel(demo ? DEMO_INTEL : raw);
  const risk = extractRisk(demo ? DEMO_RAW : raw);
  const url = demo ? DEMO_RAW.url : raw.url ?? data.url;
  return (
    <main className="report">
      <button className="back" onClick={onBack}>Back to Threat Analysis Report</button>
      {demo && (
        <div className="demo" role="note">
          <strong>DEMO DATA</strong> This is a predefined sample investigation. It is not a real scan of any website.
        </div>
      )}
      <h1 className="small">Security Intelligence</h1>
      <p className="mono">{url}</p>
      {risk.level && (
        <p className="riskline">
          <span className="badge" data-level={risk.level.toLowerCase()}>{riskLabel(risk.level)}</span>
          {risk.score !== null && <span className="dim">Overall score {risk.score} out of 100</span>}
        </p>
      )}
      <p className="dim">Select a card to see its technical details.</p>
      <div className="icards">
        <CertificateCard data={intel.certificate} />
        <RedirectCard data={intel.redirects} />
        <WebsiteSecurityCard data={intel.security} />
      </div>
      <button className="back" onClick={onBack}>Back to Threat Analysis Report</button>
    </main>
  );
}
