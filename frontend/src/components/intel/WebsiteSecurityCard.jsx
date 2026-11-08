import IntelCard, { TechList } from './IntelCard.jsx';
import StatusDot, { CHECK_LABEL } from './StatusDot.jsx';
import CheckRow from './CheckRow.jsx';
import { worst } from '../../services/intelAdapter.js';

const LABEL = { pass: 'Well configured', warn: 'Gaps found', fail: 'At risk', unknown: 'No data' };

function Group({ title, rows }) {
  if (rows.length === 0) return null;
  return (
    <>
      <h4>{title}</h4>
      <ul className="checks">{rows.map((r, i) => <CheckRow key={i} check={r} />)}</ul>
    </>
  );
}

export default function WebsiteSecurityCard({ data }) {
  if (!data) return <IntelCard title="Website Security" status="unknown" label="No data" emptyText="No website security data was returned for this scan." />;
  const hOk = data.headers.filter((h) => h.status === 'pass').length;
  const cOk = data.cookies.filter((c) => c.status === 'pass').length;
  return (
    <IntelCard title="Website Security" status={data.status} label={LABEL[data.status]} summary={data.summary}
      preview={<span className="mrows">
        <span className="mrow"><span>Security headers</span>{data.headers.length ? <StatusDot status={worst(data.headers)} label={`${hOk} of ${data.headers.length} passed`} /> : <span>Not provided</span>}</span>
        <span className="mrow"><span>Cookie security</span>{data.cookies.length ? <StatusDot status={worst(data.cookies)} label={`${cOk} of ${data.cookies.length} passed`} /> : <span>Not provided</span>}</span>
        <span className="mrow"><span>Overall configuration</span><StatusDot status={data.status} label={CHECK_LABEL[data.status]} /></span>
      </span>}>
      <p className="dim hint">Select a check to see what it means.</p>
      <Group title="HTTP security headers" rows={data.headers} />
      <Group title="Cookie security" rows={data.cookies} />
      <TechList rows={data.details} />
    </IntelCard>
  );
}
