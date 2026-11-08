import IntelCard, { TechList } from './IntelCard.jsx';

const LABEL = { pass: 'No concerns', warn: 'Suspicious', fail: 'Suspicious', unknown: 'No data' };
const host = (u) => { try { return new URL(u).host; } catch { return u; } };

export function RedirectPath({ hops }) {
  return (
    <span className="path" aria-label="Redirect journey">
      {hops.map((h, i) => (
        <span key={i} className="hop" data-s={h.status} style={{ '--i': i }}>
          <span className="hdot" aria-hidden="true" />
          <span className="hbody">
            <span className="hhost">{host(h.url)}
              {i === 0 && <small>Entered URL</small>}
              {i === hops.length - 1 && i > 0 && <small className="fin">Final destination</small>}
              {h.domainChange && <small className="chg">Domain change</small>}
            </span>
            {h.reason && <span className="hwhy">{h.reason}</span>}
          </span>
          {h.code != null && <span className="scode" data-c={String(h.code)[0]} title="HTTP status code">{h.code}</span>}
        </span>
      ))}
    </span>
  );
}

export default function RedirectCard({ data }) {
  if (!data) return <IntelCard title="Redirect Analysis" status="unknown" label="No data" emptyText="No redirect data was returned for this scan." />;
  const n = Math.max(0, data.hops.length - 1);
  const last = data.hops[data.hops.length - 1];
  return (
    <IntelCard title="Redirect Analysis" status={data.status} label={LABEL[data.status]}
      summary={data.summary ?? (data.hops.length ? (n === 0 ? 'No redirects.' : `${n} ${n === 1 ? 'redirect' : 'redirects'} before the final page.`) : null)}
      preview={last ? <>
        <RedirectPath hops={data.hops} />
        <span className="final" data-s={last.status}>
          <span className="k">Final destination</span>
          <span className="mono">{last.url}</span>
        </span>
      </> : null}>
      <ol className="urls">
        {data.hops.map((h, i) => (
          <li key={i}><span className="code">{h.code ?? '–'}</span><span className="mono">{h.url}</span></li>
        ))}
      </ol>
      <TechList rows={data.details} />
    </IntelCard>
  );
}
