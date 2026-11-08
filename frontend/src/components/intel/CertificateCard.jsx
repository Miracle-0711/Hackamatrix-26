import IntelCard, { TechList } from './IntelCard.jsx';
import { fmtDate } from '../../services/intelAdapter.js';
import { worst } from '../../services/intelAdapter.js';

const ROLE = { root: 'Root', intermediate: 'Intermediate', leaf: 'Leaf' };

export function ChainViz({ chain }) {
  return (
    <span className="chain" aria-label="Certificate chain">
      {chain.map((n, i) => (
        <span key={i} className="cwrap" style={{ '--i': i }}>
          {i > 0 && <span className="clink" aria-hidden="true" />}
          <span className="cnode" data-s={n.status}>
            <b>{ROLE[n.role] ?? n.role ?? 'Certificate'}</b>
            <em>{n.missing ? 'Not found' : n.name}</em>
            {n.missing && !n.issue && <small>This certificate is missing from the chain.</small>}
            {n.issue && <small>{n.issue}</small>}
          </span>
        </span>
      ))}
    </span>
  );
}

export default function CertificateCard({ data }) {
  if (!data) return <IntelCard title="Certificate Security" status="unknown" label="No data" emptyText="No certificate data was returned for this scan." />;
  const problems = data.chain.filter((n) => n.status !== 'pass').length + data.issues.length;
  const sev = worst([...data.chain, ...data.issues.map(() => ({ status: 'fail' }))]);
  return (
    <IntelCard title="Certificate Security" status={data.status} label={data.statusLabel} summary={data.summary}
      preview={<>
        <span className="meta">
          <span><span className="k">Issuer</span>{data.issuer ?? 'Not provided'}</span>
          <span><span className="k">Issued</span>{fmtDate(data.issuedAt)}</span>
          <span><span className="k">Expires</span>{fmtDate(data.expiresAt)}</span>
        </span>
        {data.chain.length > 0 && <ChainViz chain={data.chain} />}
        {problems > 0 && <span className="alertline" data-s={sev === 'pass' ? 'warn' : sev}>{problems} certificate {problems === 1 ? 'problem' : 'problems'} found. Open for details.</span>}
      </>}>
      {data.issues.length > 0 && <ul className="flags">{data.issues.map((m, i) => <li key={i} data-s="fail">{m}</li>)}</ul>}
      <TechList rows={data.details} />
      {data.issues.length === 0 && data.details.length === 0 && <p className="dim">No further details were provided.</p>}
    </IntelCard>
  );
}
