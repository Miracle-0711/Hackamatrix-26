import { BASE_URL, USE_MOCK } from '../services/api.js';

export const connectionLabel = { unknown: 'Backend not checked yet', ok: 'Backend connected', down: 'Backend unreachable' };

export default function Header({ connection }) {
  return (
    <header className="header">
      <div className="brand">WEBLYZE</div>
      <nav aria-label="Main">
        <a href="#command" aria-current="page">Command Center</a>
        {/* Later modules: wire routes here */}
        <button disabled title="Coming soon">Threat Intelligence</button>
        <button disabled title="Coming soon">Scan History</button>
      </nav>
      <div className="sys" title={USE_MOCK ? 'Mock mode' : BASE_URL}>
        <span className={'led ' + connection} /> {USE_MOCK ? 'Mock mode' : connectionLabel[connection]}
      </div>
    </header>
  );
}
